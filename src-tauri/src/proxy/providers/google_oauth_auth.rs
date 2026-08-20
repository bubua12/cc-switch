//! Google OAuth authentication manager.
//!
//! Google uses OAuth 2.0 Device Authorization Grant for headless/device flows
//! and OAuth 2.0 Token Refresh.
//!
//! Endpoints:
//! - Device Authorization: `https://oauth2.googleapis.com/device/code`
//! - Token Exchange / Refresh: `https://oauth2.googleapis.com/token`
//! - UserInfo: `https://www.googleapis.com/oauth2/v3/userinfo`
//!
//! Client credentials:
//! Reuses the official Gemini CLI public OAuth client identity.

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::io::Write;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::{Mutex, RwLock};

use super::copilot_auth::GitHubDeviceCodeResponse;

pub const GOOGLE_OAUTH_CLIENT_ID: &str =
    "681255809395-oo8ft2oprdrnp9e3aqf6av3hmdib135j.apps.googleusercontent.com";
pub const GOOGLE_OAUTH_CLIENT_SECRET: &str = "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";
pub const GOOGLE_DEVICE_CODE_URL: &str = "https://oauth2.googleapis.com/device/code";
pub const GOOGLE_TOKEN_URL: &str = "https://oauth2.googleapis.com/token";
#[allow(dead_code)]
pub const GOOGLE_USERINFO_URL: &str = "https://www.googleapis.com/oauth2/v3/userinfo";
pub const GOOGLE_SCOPE: &str =
    "openid email profile https://www.googleapis.com/auth/cloud-platform";
pub const GOOGLE_USER_AGENT: &str = "cc-switch-google-oauth";

const TOKEN_REFRESH_BUFFER_MS: i64 = 60_000;
const DEFAULT_TOKEN_LIFETIME_SECS: i64 = 3_600;
const POLLING_SAFETY_MARGIN_SECS: u64 = 3;
const MAX_DEVICE_CODE_LIFETIME_SECS: u64 = 24 * 60 * 60;
const MAX_POLL_INTERVAL_SECS: u64 = 60;
const MAX_OAUTH_RESPONSE_BYTES: usize = 64 * 1024;

#[derive(Debug, thiserror::Error)]
pub enum GoogleOAuthError {
    #[error("等待用户授权中")]
    AuthorizationPending,
    #[error("用户拒绝授权")]
    AccessDenied,
    #[error("Device Code 已过期")]
    ExpiredToken,
    #[error("OAuth Token 获取失败: {0}")]
    TokenFetchFailed(String),
    #[error("Refresh Token 失效或已过期，请重新登录 Google 账号")]
    RefreshTokenInvalid,
    #[error("账号需要重新登录: {0}")]
    ReauthRequired(String),
    #[error("网络错误: {0}")]
    NetworkError(String),
    #[error("解析错误: {0}")]
    ParseError(String),
    #[error("IO 错误: {0}")]
    IoError(String),
    #[error("账号不存在: {0}")]
    AccountNotFound(String),
}

impl From<reqwest::Error> for GoogleOAuthError {
    fn from(err: reqwest::Error) -> Self {
        Self::NetworkError(err.to_string())
    }
}

impl From<std::io::Error> for GoogleOAuthError {
    fn from(err: std::io::Error) -> Self {
        Self::IoError(err.to_string())
    }
}

#[derive(Debug, Clone, Deserialize)]
struct DeviceCodeResponse {
    device_code: String,
    user_code: String,
    #[serde(alias = "verification_url")]
    verification_uri: String,
    #[allow(dead_code)]
    #[serde(default, alias = "verification_url_complete")]
    verification_uri_complete: Option<String>,
    expires_in: u64,
    #[serde(default = "default_poll_interval")]
    interval: u64,
}

#[derive(Debug, Clone, Deserialize)]
struct OAuthTokenResponse {
    access_token: String,
    #[serde(default)]
    refresh_token: Option<String>,
    #[serde(default)]
    id_token: Option<String>,
    #[serde(default)]
    expires_in: Option<i64>,
}

#[derive(Debug, Clone, Default, Deserialize)]
struct GoogleTokenClaims {
    #[serde(default)]
    sub: Option<String>,
    #[serde(default)]
    email: Option<String>,
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    picture: Option<String>,
}

#[derive(Debug, Clone)]
struct CachedAccessToken {
    token: String,
    expires_at_ms: i64,
}

impl CachedAccessToken {
    fn is_expiring_soon(&self) -> bool {
        self.expires_at_ms - chrono::Utc::now().timestamp_millis() < TOKEN_REFRESH_BUFFER_MS
    }
}

#[derive(Debug, Clone)]
struct PendingDeviceCode {
    expires_at_ms: i64,
    interval_secs: u64,
    next_poll_at_ms: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct GoogleAccountData {
    account_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    login: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    avatar_url: Option<String>,
    refresh_token: String,
    authenticated_at: i64,
    #[serde(default)]
    requires_reauth: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GoogleOAuthAccount {
    pub id: String,
    pub login: String,
    pub avatar_url: Option<String>,
    pub authenticated_at: i64,
    pub github_domain: String,
    pub requires_reauth: bool,
}

impl From<&GoogleAccountData> for GoogleOAuthAccount {
    fn from(data: &GoogleAccountData) -> Self {
        let short_id: String = data.account_id.chars().take(12).collect();
        Self {
            id: data.account_id.clone(),
            login: data
                .login
                .clone()
                .unwrap_or_else(|| format!("Google ({short_id})")),
            avatar_url: data.avatar_url.clone(),
            authenticated_at: data.authenticated_at,
            github_domain: "google.com".to_string(),
            requires_reauth: data.requires_reauth,
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct GoogleOAuthStore {
    #[serde(default)]
    version: u32,
    #[serde(default)]
    accounts: HashMap<String, GoogleAccountData>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    default_account_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GoogleOAuthStatus {
    pub accounts: Vec<GoogleOAuthAccount>,
    pub default_account_id: Option<String>,
    pub authenticated: bool,
    pub username: Option<String>,
}

pub struct GoogleOAuthManager {
    accounts: Arc<RwLock<HashMap<String, GoogleAccountData>>>,
    default_account_id: Arc<RwLock<Option<String>>>,
    access_tokens: Arc<RwLock<HashMap<String, CachedAccessToken>>>,
    refresh_locks: Arc<RwLock<HashMap<String, Arc<Mutex<()>>>>>,
    pending_device_codes: Arc<RwLock<HashMap<String, PendingDeviceCode>>>,
    mutation_lock: Arc<Mutex<()>>,
    storage_path: PathBuf,
}

impl GoogleOAuthManager {
    pub fn new(data_dir: PathBuf) -> Self {
        let manager = Self {
            accounts: Arc::new(RwLock::new(HashMap::new())),
            default_account_id: Arc::new(RwLock::new(None)),
            access_tokens: Arc::new(RwLock::new(HashMap::new())),
            refresh_locks: Arc::new(RwLock::new(HashMap::new())),
            pending_device_codes: Arc::new(RwLock::new(HashMap::new())),
            mutation_lock: Arc::new(Mutex::new(())),
            storage_path: data_dir.join("google_oauth_auth.json"),
        };

        if let Err(error) = manager.load_from_disk_sync() {
            log::warn!("[GoogleOAuth] 加载存储失败: {error}");
        }
        manager
    }

    pub async fn start_device_flow(&self) -> Result<GitHubDeviceCodeResponse, GoogleOAuthError> {
        let response = crate::proxy::http_client::get()
            .post(GOOGLE_DEVICE_CODE_URL)
            .header("User-Agent", GOOGLE_USER_AGENT)
            .form(&[
                ("client_id", GOOGLE_OAUTH_CLIENT_ID),
                ("scope", GOOGLE_SCOPE),
            ])
            .send()
            .await?;

        let status = response.status();
        let value = read_json_response(response).await?;
        if !status.is_success() {
            return Err(GoogleOAuthError::TokenFetchFailed(format_oauth_error(
                status, &value,
            )));
        }
        let device = parse_device_code_response(value)?;
        let interval = device
            .interval
            .clamp(1, MAX_POLL_INTERVAL_SECS)
            .saturating_add(POLLING_SAFETY_MARGIN_SECS);
        let expires_in = device.expires_in.clamp(1, MAX_DEVICE_CODE_LIFETIME_SECS);
        let now_ms = chrono::Utc::now().timestamp_millis();

        {
            let mut pending = self.pending_device_codes.write().await;
            pending.retain(|_, entry| entry.expires_at_ms > now_ms);
            pending.insert(
                device.device_code.clone(),
                PendingDeviceCode {
                    expires_at_ms: now_ms.saturating_add(
                        i64::try_from(expires_in)
                            .unwrap_or(i64::MAX)
                            .saturating_mul(1_000),
                    ),
                    interval_secs: interval,
                    next_poll_at_ms: now_ms,
                },
            );
        }

        Ok(GitHubDeviceCodeResponse {
            device_code: device.device_code,
            user_code: device.user_code,
            verification_uri: device.verification_uri,
            expires_in,
            interval,
        })
    }

    pub async fn poll_for_token(
        &self,
        device_code: &str,
    ) -> Result<Option<GoogleOAuthAccount>, GoogleOAuthError> {
        let now_ms = chrono::Utc::now().timestamp_millis();
        let entry = {
            let pending = self.pending_device_codes.read().await;
            pending.get(device_code).cloned()
        }
        .ok_or_else(|| {
            GoogleOAuthError::TokenFetchFailed("Device Code 不存在，请重新启动登录".to_string())
        })?;

        if entry.expires_at_ms <= now_ms {
            self.pending_device_codes.write().await.remove(device_code);
            return Err(GoogleOAuthError::ExpiredToken);
        }
        if entry.next_poll_at_ms > now_ms {
            return Err(GoogleOAuthError::AuthorizationPending);
        }
        self.schedule_next_poll(device_code, entry.interval_secs)
            .await;

        let response = crate::proxy::http_client::get()
            .post(GOOGLE_TOKEN_URL)
            .header("User-Agent", GOOGLE_USER_AGENT)
            .form(&[
                ("grant_type", "urn:ietf:params:oauth:grant-type:device_code"),
                ("client_id", GOOGLE_OAUTH_CLIENT_ID),
                ("client_secret", GOOGLE_OAUTH_CLIENT_SECRET),
                ("device_code", device_code),
            ])
            .send()
            .await?;
        let status = response.status();
        let value = read_json_response(response).await?;

        if let Some(error_code) = oauth_error_code(&value) {
            return match error_code.as_str() {
                "authorization_pending" => Err(GoogleOAuthError::AuthorizationPending),
                "slow_down" => {
                    self.increase_poll_interval(device_code).await;
                    Err(GoogleOAuthError::AuthorizationPending)
                }
                "access_denied" => {
                    self.pending_device_codes.write().await.remove(device_code);
                    Err(GoogleOAuthError::AccessDenied)
                }
                "expired_token" => {
                    self.pending_device_codes.write().await.remove(device_code);
                    Err(GoogleOAuthError::ExpiredToken)
                }
                _ => Err(GoogleOAuthError::TokenFetchFailed(format_oauth_error(
                    status, &value,
                ))),
            };
        }
        if !status.is_success() {
            return Err(GoogleOAuthError::TokenFetchFailed(format_oauth_error(
                status, &value,
            )));
        }

        let tokens = parse_token_response(value)?;
        validate_access_token(&tokens.access_token)?;
        let refresh_token = tokens
            .refresh_token
            .as_deref()
            .filter(|token| !token.trim().is_empty())
            .map(ToString::to_string)
            .ok_or_else(|| {
                GoogleOAuthError::TokenFetchFailed("成功响应缺少 refresh_token".to_string())
            })?;
        let (account_id, login, avatar_url) =
            extract_identity_from_tokens(&tokens).ok_or_else(|| {
                GoogleOAuthError::ParseError(
                    "Google token 缺少稳定的 sub claim，未保存账号".to_string(),
                )
            })?;

        let cached_access_token = CachedAccessToken {
            token: tokens.access_token,
            expires_at_ms: compute_expires_at_ms(tokens.expires_in),
        };
        let account = self
            .add_account_internal(
                account_id,
                login,
                avatar_url,
                refresh_token,
                Some(device_code),
                Some(cached_access_token),
            )
            .await?;
        Ok(Some(account))
    }

    /// 导入本地已有 Gemini CLI / Google 凭据
    pub async fn import_local_credentials(
        &self,
        refresh_token: &str,
    ) -> Result<GoogleOAuthAccount, GoogleOAuthError> {
        let tokens = self.refresh_with_token(refresh_token).await?;
        let effective_refresh = tokens
            .refresh_token
            .as_deref()
            .unwrap_or(refresh_token)
            .to_string();
        let (account_id, login, avatar_url) =
            extract_identity_from_tokens(&tokens).ok_or_else(|| {
                GoogleOAuthError::ParseError("Google token 无法解析身份信息".to_string())
            })?;

        let cached_access_token = CachedAccessToken {
            token: tokens.access_token,
            expires_at_ms: compute_expires_at_ms(tokens.expires_in),
        };
        self.add_account_internal(
            account_id,
            login,
            avatar_url,
            effective_refresh,
            None,
            Some(cached_access_token),
        )
        .await
    }

    pub async fn get_valid_token_for_account(
        &self,
        account_id: &str,
    ) -> Result<String, GoogleOAuthError> {
        if let Some(token) = self.cached_token_for_usable_account(account_id).await {
            return Ok(token);
        }

        let refresh_lock = self.get_refresh_lock(account_id).await;
        let _refresh_guard = refresh_lock.lock().await;
        if let Some(token) = self.cached_token_for_usable_account(account_id).await {
            return Ok(token);
        }

        let account = self
            .accounts
            .read()
            .await
            .get(account_id)
            .cloned()
            .ok_or_else(|| GoogleOAuthError::AccountNotFound(account_id.to_string()))?;
        if account.requires_reauth {
            return Err(GoogleOAuthError::ReauthRequired(account_id.to_string()));
        }

        let tokens = match self.refresh_with_token(&account.refresh_token).await {
            Ok(tokens) => tokens,
            Err(GoogleOAuthError::RefreshTokenInvalid) => {
                self.mark_reauth_required(account_id).await?;
                return Err(GoogleOAuthError::ReauthRequired(account_id.to_string()));
            }
            Err(error) => return Err(error),
        };

        self.commit_refreshed_tokens(account_id, &account.refresh_token, tokens)
            .await
    }

    pub async fn get_valid_token(&self) -> Result<String, GoogleOAuthError> {
        match self.resolve_default_account_id().await {
            Some(account_id) => self.get_valid_token_for_account(&account_id).await,
            None => Err(GoogleOAuthError::AccountNotFound(
                "无可用的 Google 账号，请登录或重新登录".to_string(),
            )),
        }
    }

    pub async fn default_account_id(&self) -> Option<String> {
        self.resolve_default_account_id().await
    }

    pub async fn get_status(&self) -> GoogleOAuthStatus {
        let accounts = self.accounts.read().await.clone();
        let default_account_id = self.resolve_default_account_id().await;
        let account_list = Self::sorted_accounts(&accounts, default_account_id.as_deref());
        let username = default_account_id
            .as_ref()
            .and_then(|id| accounts.get(id))
            .and_then(|account| account.login.clone());
        GoogleOAuthStatus {
            authenticated: default_account_id.is_some(),
            default_account_id,
            accounts: account_list,
            username,
        }
    }

    pub async fn list_accounts(&self) -> Vec<GoogleOAuthAccount> {
        let accounts = self.accounts.read().await.clone();
        let default_account_id = self.resolve_default_account_id().await;
        Self::sorted_accounts(&accounts, default_account_id.as_deref())
    }

    pub async fn remove_account(&self, account_id: &str) -> Result<(), GoogleOAuthError> {
        let _mutation_guard = self.mutation_lock.lock().await;
        let mut accounts = self.accounts.read().await.clone();
        if accounts.remove(account_id).is_none() {
            return Err(GoogleOAuthError::AccountNotFound(account_id.to_string()));
        }
        let stored_default = self.default_account_id.read().await.clone();
        let default_account_id = if stored_default.as_deref() == Some(account_id) {
            Self::fallback_default_account_id(&accounts)
        } else {
            stored_default.filter(|id| Self::is_usable_account(&accounts, id))
        };
        self.persist_and_commit(accounts, default_account_id)
            .await?;
        self.access_tokens.write().await.remove(account_id);
        self.refresh_locks.write().await.remove(account_id);
        Ok(())
    }

    pub async fn set_default_account(&self, account_id: &str) -> Result<(), GoogleOAuthError> {
        let _mutation_guard = self.mutation_lock.lock().await;
        let accounts = self.accounts.read().await.clone();
        let account = accounts
            .get(account_id)
            .ok_or_else(|| GoogleOAuthError::AccountNotFound(account_id.to_string()))?;
        if account.requires_reauth {
            return Err(GoogleOAuthError::ReauthRequired(account_id.to_string()));
        }
        self.persist_and_commit(accounts, Some(account_id.to_string()))
            .await
    }

    pub async fn clear_auth(&self) -> Result<(), GoogleOAuthError> {
        let _mutation_guard = self.mutation_lock.lock().await;
        if self.storage_path.exists() {
            fs::remove_file(&self.storage_path)?;
        }
        *self.accounts.write().await = HashMap::new();
        *self.default_account_id.write().await = None;
        self.access_tokens.write().await.clear();
        self.refresh_locks.write().await.clear();
        self.pending_device_codes.write().await.clear();
        Ok(())
    }

    async fn refresh_with_token(
        &self,
        refresh_token: &str,
    ) -> Result<OAuthTokenResponse, GoogleOAuthError> {
        let response = crate::proxy::http_client::get()
            .post(GOOGLE_TOKEN_URL)
            .header("User-Agent", GOOGLE_USER_AGENT)
            .form(&[
                ("grant_type", "refresh_token"),
                ("client_id", GOOGLE_OAUTH_CLIENT_ID),
                ("client_secret", GOOGLE_OAUTH_CLIENT_SECRET),
                ("refresh_token", refresh_token),
                ("scope", GOOGLE_SCOPE),
            ])
            .send()
            .await?;
        let status = response.status();
        let value_result = read_json_response(response).await;
        if refresh_response_requires_reauth(status, value_result.is_err()) {
            return Err(GoogleOAuthError::RefreshTokenInvalid);
        }
        let value = value_result?;
        let error_code = oauth_error_code(&value);
        if matches!(
            error_code.as_deref(),
            Some("invalid_grant" | "invalid_token")
        ) {
            return Err(GoogleOAuthError::RefreshTokenInvalid);
        }
        if !status.is_success() || error_code.is_some() {
            return Err(GoogleOAuthError::TokenFetchFailed(format_oauth_error(
                status, &value,
            )));
        }
        let tokens = parse_token_response(value)?;
        validate_access_token(&tokens.access_token)?;
        Ok(tokens)
    }

    async fn add_account_internal(
        &self,
        account_id: String,
        login: Option<String>,
        avatar_url: Option<String>,
        refresh_token: String,
        pending_device_code: Option<&str>,
        cached_access_token: Option<CachedAccessToken>,
    ) -> Result<GoogleOAuthAccount, GoogleOAuthError> {
        let _mutation_guard = self.mutation_lock.lock().await;
        if let Some(device_code) = pending_device_code {
            let login_is_pending = self
                .pending_device_codes
                .read()
                .await
                .contains_key(device_code);
            if !login_is_pending {
                return Err(GoogleOAuthError::TokenFetchFailed(
                    "登录已取消，请重新启动登录".to_string(),
                ));
            }
        }
        let mut accounts = self.accounts.read().await.clone();
        let data = GoogleAccountData {
            account_id: account_id.clone(),
            login,
            avatar_url,
            refresh_token,
            authenticated_at: chrono::Utc::now().timestamp(),
            requires_reauth: false,
        };
        let account = GoogleOAuthAccount::from(&data);
        accounts.insert(account_id.clone(), data);
        let current_default = self.default_account_id.read().await.clone();
        let default_account_id = match current_default {
            Some(id) if Self::is_usable_account(&accounts, &id) => Some(id),
            _ => Some(account_id.clone()),
        };
        self.persist_and_commit(accounts, default_account_id)
            .await?;
        if let Some(access_token) = cached_access_token {
            self.access_tokens
                .write()
                .await
                .insert(account_id, access_token);
        }
        if let Some(device_code) = pending_device_code {
            self.pending_device_codes.write().await.remove(device_code);
        }
        Ok(account)
    }

    async fn commit_refreshed_tokens(
        &self,
        account_id: &str,
        expected_refresh_token: &str,
        tokens: OAuthTokenResponse,
    ) -> Result<String, GoogleOAuthError> {
        let _mutation_guard = self.mutation_lock.lock().await;
        let mut accounts = self.accounts.read().await.clone();
        let account = accounts
            .get_mut(account_id)
            .ok_or_else(|| GoogleOAuthError::AccountNotFound(account_id.to_string()))?;
        if account.requires_reauth {
            return Err(GoogleOAuthError::ReauthRequired(account_id.to_string()));
        }
        if account.refresh_token != expected_refresh_token {
            return Err(GoogleOAuthError::TokenFetchFailed(
                "账号认证状态已变化，请重试请求".to_string(),
            ));
        }

        let refresh_token_changed = tokens
            .refresh_token
            .as_deref()
            .filter(|token| !token.trim().is_empty())
            .is_some_and(|refresh_token| {
                if refresh_token == account.refresh_token {
                    false
                } else {
                    account.refresh_token = refresh_token.to_string();
                    true
                }
            });
        if refresh_token_changed {
            let default_account_id = self.default_account_id.read().await.clone();
            self.persist_and_commit(accounts, default_account_id)
                .await?;
        }

        let access_token = tokens.access_token;
        self.access_tokens.write().await.insert(
            account_id.to_string(),
            CachedAccessToken {
                token: access_token.clone(),
                expires_at_ms: compute_expires_at_ms(tokens.expires_in),
            },
        );
        Ok(access_token)
    }

    async fn mark_reauth_required(&self, account_id: &str) -> Result<(), GoogleOAuthError> {
        let _mutation_guard = self.mutation_lock.lock().await;
        let mut accounts = self.accounts.read().await.clone();
        let account = accounts
            .get_mut(account_id)
            .ok_or_else(|| GoogleOAuthError::AccountNotFound(account_id.to_string()))?;
        account.requires_reauth = true;
        let default_account_id = Self::fallback_default_account_id(&accounts);
        self.persist_and_commit(accounts, default_account_id)
            .await?;
        self.access_tokens.write().await.remove(account_id);
        Ok(())
    }

    async fn persist_and_commit(
        &self,
        accounts: HashMap<String, GoogleAccountData>,
        default_account_id: Option<String>,
    ) -> Result<(), GoogleOAuthError> {
        let store = GoogleOAuthStore {
            version: 1,
            accounts: accounts.clone(),
            default_account_id: default_account_id.clone(),
        };
        let content = serde_json::to_string_pretty(&store)
            .map_err(|error| GoogleOAuthError::ParseError(error.to_string()))?;
        self.write_store_atomic(&content)?;
        *self.accounts.write().await = accounts;
        *self.default_account_id.write().await = default_account_id;
        Ok(())
    }

    async fn schedule_next_poll(&self, device_code: &str, interval_secs: u64) {
        if let Some(entry) = self.pending_device_codes.write().await.get_mut(device_code) {
            entry.next_poll_at_ms = chrono::Utc::now().timestamp_millis().saturating_add(
                i64::try_from(interval_secs)
                    .unwrap_or(5)
                    .saturating_mul(1_000),
            );
        }
    }

    async fn increase_poll_interval(&self, device_code: &str) {
        if let Some(entry) = self.pending_device_codes.write().await.get_mut(device_code) {
            entry.interval_secs = entry
                .interval_secs
                .saturating_add(5)
                .min(MAX_POLL_INTERVAL_SECS);
            entry.next_poll_at_ms = chrono::Utc::now().timestamp_millis().saturating_add(
                i64::try_from(entry.interval_secs)
                    .unwrap_or(5)
                    .saturating_mul(1_000),
            );
        }
    }

    async fn cached_token_for_usable_account(&self, account_id: &str) -> Option<String> {
        let is_usable = {
            let accounts = self.accounts.read().await;
            accounts
                .get(account_id)
                .is_some_and(|account| !account.requires_reauth)
        };
        if !is_usable {
            return None;
        }
        let tokens = self.access_tokens.read().await;
        tokens
            .get(account_id)
            .filter(|cached| !cached.is_expiring_soon())
            .map(|cached| cached.token.clone())
    }

    async fn get_refresh_lock(&self, account_id: &str) -> Arc<Mutex<()>> {
        let mut locks = self.refresh_locks.write().await;
        locks
            .entry(account_id.to_string())
            .or_insert_with(|| Arc::new(Mutex::new(())))
            .clone()
    }

    async fn resolve_default_account_id(&self) -> Option<String> {
        let accounts = self.accounts.read().await;
        let stored_default = self.default_account_id.read().await.clone();
        match stored_default {
            Some(id) if Self::is_usable_account(&accounts, &id) => Some(id),
            _ => Self::fallback_default_account_id(&accounts),
        }
    }

    fn is_usable_account(accounts: &HashMap<String, GoogleAccountData>, account_id: &str) -> bool {
        accounts
            .get(account_id)
            .is_some_and(|account| !account.requires_reauth)
    }

    fn fallback_default_account_id(
        accounts: &HashMap<String, GoogleAccountData>,
    ) -> Option<String> {
        accounts
            .values()
            .filter(|account| !account.requires_reauth)
            .max_by_key(|account| account.authenticated_at)
            .map(|account| account.account_id.clone())
    }

    fn sorted_accounts(
        accounts: &HashMap<String, GoogleAccountData>,
        default_account_id: Option<&str>,
    ) -> Vec<GoogleOAuthAccount> {
        let mut list: Vec<GoogleOAuthAccount> =
            accounts.values().map(GoogleOAuthAccount::from).collect();
        list.sort_by(|left, right| {
            let left_is_default = default_account_id == Some(&left.id);
            let right_is_default = default_account_id == Some(&right.id);
            match (left_is_default, right_is_default) {
                (true, false) => std::cmp::Ordering::Less,
                (false, true) => std::cmp::Ordering::Greater,
                _ => match (left.requires_reauth, right.requires_reauth) {
                    (false, true) => std::cmp::Ordering::Less,
                    (true, false) => std::cmp::Ordering::Greater,
                    _ => right.authenticated_at.cmp(&left.authenticated_at),
                },
            }
        });
        list
    }

    fn load_from_disk_sync(&self) -> Result<(), GoogleOAuthError> {
        if !self.storage_path.exists() {
            return Ok(());
        }
        let content = fs::read_to_string(&self.storage_path)?;
        if content.trim().is_empty() {
            return Ok(());
        }
        let store: GoogleOAuthStore = serde_json::from_str(&content)
            .map_err(|error| GoogleOAuthError::ParseError(error.to_string()))?;
        if let Ok(mut accounts) = self.accounts.try_write() {
            *accounts = store.accounts;
        }
        if let Ok(mut default_account_id) = self.default_account_id.try_write() {
            *default_account_id = store.default_account_id;
        }
        Ok(())
    }

    fn write_store_atomic(&self, content: &str) -> Result<(), GoogleOAuthError> {
        let parent = self
            .storage_path
            .parent()
            .ok_or_else(|| GoogleOAuthError::IoError("无效的存储路径".to_string()))?;
        fs::create_dir_all(parent)?;
        let file_name = self
            .storage_path
            .file_name()
            .ok_or_else(|| GoogleOAuthError::IoError("无效的存储文件名".to_string()))?
            .to_string_lossy();
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        let temporary_path = parent.join(format!("{file_name}.tmp.{nonce}"));

        #[cfg(unix)]
        {
            use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
            let result = (|| -> Result<(), std::io::Error> {
                let mut file = fs::OpenOptions::new()
                    .create_new(true)
                    .write(true)
                    .mode(0o600)
                    .open(&temporary_path)?;
                file.write_all(content.as_bytes())?;
                file.flush()?;
                fs::rename(&temporary_path, &self.storage_path)?;
                fs::set_permissions(&self.storage_path, fs::Permissions::from_mode(0o600))?;
                Ok(())
            })();
            if result.is_err() {
                let _ = fs::remove_file(&temporary_path);
            }
            result?;
        }

        #[cfg(windows)]
        {
            let result = (|| -> Result<(), std::io::Error> {
                let mut file = fs::OpenOptions::new()
                    .create_new(true)
                    .write(true)
                    .open(&temporary_path)?;
                file.write_all(content.as_bytes())?;
                file.flush()?;
                if self.storage_path.exists() {
                    fs::remove_file(&self.storage_path)?;
                }
                fs::rename(&temporary_path, &self.storage_path)?;
                Ok(())
            })();
            if result.is_err() {
                let _ = fs::remove_file(&temporary_path);
            }
            result?;
        }
        Ok(())
    }
}

fn default_poll_interval() -> u64 {
    5
}

fn compute_expires_at_ms(expires_in: Option<i64>) -> i64 {
    chrono::Utc::now().timestamp_millis().saturating_add(
        expires_in
            .unwrap_or(DEFAULT_TOKEN_LIFETIME_SECS)
            .max(1)
            .saturating_mul(1_000),
    )
}

fn validate_access_token(access_token: &str) -> Result<(), GoogleOAuthError> {
    if access_token.trim().is_empty() {
        return Err(GoogleOAuthError::TokenFetchFailed(
            "成功响应缺少 access_token".to_string(),
        ));
    }
    Ok(())
}

fn parse_device_code_response(
    value: serde_json::Value,
) -> Result<DeviceCodeResponse, GoogleOAuthError> {
    serde_json::from_value(value)
        .map_err(|_| GoogleOAuthError::ParseError("设备授权响应字段无效".to_string()))
}

fn parse_token_response(value: serde_json::Value) -> Result<OAuthTokenResponse, GoogleOAuthError> {
    serde_json::from_value(value)
        .map_err(|_| GoogleOAuthError::ParseError("OAuth Token 响应字段无效".to_string()))
}

fn refresh_response_requires_reauth(
    status: reqwest::StatusCode,
    response_body_is_invalid: bool,
) -> bool {
    matches!(
        status,
        reqwest::StatusCode::UNAUTHORIZED | reqwest::StatusCode::FORBIDDEN
    ) || (status == reqwest::StatusCode::BAD_REQUEST && response_body_is_invalid)
}

fn parse_jwt_claims(token: &str) -> Option<GoogleTokenClaims> {
    let payload = token.split('.').nth(1)?;
    let decoded = URL_SAFE_NO_PAD.decode(payload).ok()?;
    serde_json::from_slice(&decoded).ok()
}

fn extract_identity_from_tokens(
    tokens: &OAuthTokenResponse,
) -> Option<(String, Option<String>, Option<String>)> {
    let claims = tokens
        .id_token
        .as_deref()
        .and_then(parse_jwt_claims)
        .or_else(|| parse_jwt_claims(&tokens.access_token));

    if let Some(claims) = claims {
        if let Some(account_id) = claims
            .sub
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
        {
            let login = claims
                .email
                .or(claims.name)
                .filter(|v| !v.trim().is_empty());
            return Some((account_id, login, claims.picture));
        }
    }

    // If no JWT claims, generate a synthetic id based on access_token
    if !tokens.access_token.is_empty() {
        use sha2::Digest;
        let mut hasher = sha2::Sha256::new();
        hasher.update(tokens.access_token.as_bytes());
        let hash = format!("{:x}", hasher.finalize());
        let account_id = format!("google-{}", &hash[..12]);
        return Some((account_id, Some("Google Account".to_string()), None));
    }
    None
}

async fn read_json_response(
    response: reqwest::Response,
) -> Result<serde_json::Value, GoogleOAuthError> {
    if response
        .content_length()
        .is_some_and(|length| length > MAX_OAUTH_RESPONSE_BYTES as u64)
    {
        return Err(GoogleOAuthError::ParseError(
            "OAuth 响应超过大小限制".to_string(),
        ));
    }
    let bytes = response.bytes().await?;
    if bytes.len() > MAX_OAUTH_RESPONSE_BYTES {
        return Err(GoogleOAuthError::ParseError(
            "OAuth 响应超过大小限制".to_string(),
        ));
    }
    serde_json::from_slice(&bytes)
        .map_err(|_| GoogleOAuthError::ParseError("OAuth 响应不是有效 JSON".to_string()))
}

fn oauth_error_code(value: &serde_json::Value) -> Option<String> {
    value
        .get("error")
        .and_then(serde_json::Value::as_str)
        .map(sanitize_oauth_error_code)
        .filter(|value| !value.is_empty())
}

fn sanitize_oauth_error_code(value: &str) -> String {
    value
        .chars()
        .filter(|character| character.is_ascii_alphanumeric() || "_.-".contains(*character))
        .take(64)
        .collect()
}

fn format_oauth_error(status: reqwest::StatusCode, value: &serde_json::Value) -> String {
    match oauth_error_code(value) {
        Some(code) => format!("HTTP {status} ({code})"),
        None => format!("HTTP {status}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn unsigned_jwt(payload: &serde_json::Value) -> String {
        let header = URL_SAFE_NO_PAD.encode(br#"{"alg":"none"}"#);
        let payload = URL_SAFE_NO_PAD.encode(serde_json::to_vec(payload).unwrap());
        format!("{header}.{payload}.")
    }

    #[test]
    fn identity_extracts_sub_and_email() {
        let tokens = OAuthTokenResponse {
            access_token: "ya29.test".to_string(),
            refresh_token: Some("refresh".to_string()),
            id_token: Some(unsigned_jwt(
                &serde_json::json!({"sub":"google-user-123","email":"test@gmail.com","name":"Test User"}),
            )),
            expires_in: Some(3_600),
        };
        let (id, login, _) = extract_identity_from_tokens(&tokens).unwrap();
        assert_eq!(id, "google-user-123");
        assert_eq!(login, Some("test@gmail.com".to_string()));
    }

    #[test]
    fn oauth_error_never_embeds_upstream_body() {
        let value = serde_json::json!({
            "error": "invalid_grant<script>",
            "error_description": "refresh_token=super-secret"
        });
        let message = format_oauth_error(reqwest::StatusCode::BAD_REQUEST, &value);
        assert_eq!(message, "HTTP 400 Bad Request (invalid_grantscript)");
        assert!(!message.contains("super-secret"));
        assert!(!message.contains("refresh_token"));
    }

    #[test]
    fn refresh_auth_status_is_classified_before_body_parsing() {
        assert!(refresh_response_requires_reauth(
            reqwest::StatusCode::UNAUTHORIZED,
            true,
        ));
        assert!(refresh_response_requires_reauth(
            reqwest::StatusCode::FORBIDDEN,
            true,
        ));
    }

    #[test]
    fn fallback_default_skips_accounts_requiring_reauth() {
        let mut accounts = HashMap::new();
        accounts.insert(
            "acc1".to_string(),
            GoogleAccountData {
                account_id: "acc1".to_string(),
                login: Some("user1@gmail.com".to_string()),
                avatar_url: None,
                refresh_token: "r1".to_string(),
                authenticated_at: 10,
                requires_reauth: true,
            },
        );
        accounts.insert(
            "acc2".to_string(),
            GoogleAccountData {
                account_id: "acc2".to_string(),
                login: Some("user2@gmail.com".to_string()),
                avatar_url: None,
                refresh_token: "r2".to_string(),
                authenticated_at: 20,
                requires_reauth: false,
            },
        );

        let default_id = GoogleOAuthManager::fallback_default_account_id(&accounts);
        assert_eq!(default_id, Some("acc2".to_string()));
    }

    #[test]
    fn test_validate_access_token() {
        assert!(validate_access_token("").is_err());
        assert!(validate_access_token("  ").is_err());
        assert!(validate_access_token("ya29.valid_token").is_ok());
    }
}
