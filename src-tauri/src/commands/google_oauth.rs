//! Google OAuth state and Google-specific commands.

use crate::proxy::providers::google_oauth_auth::GoogleOAuthManager;
use crate::services::model_fetch::FetchedModel;
use crate::services::subscription::{CredentialStatus, SubscriptionQuota};
use serde::Deserialize;
use std::sync::Arc;
use std::time::Duration;
use tauri::State;
use tokio::sync::RwLock;

pub struct GoogleOAuthState(pub Arc<RwLock<GoogleOAuthManager>>);

/// 查询 Google OAuth (Gemini / Google AI 反代) 订阅额度的共享核心
pub(crate) async fn query_google_oauth_quota_for(
    state: &GoogleOAuthState,
    account_id: Option<String>,
) -> Result<SubscriptionQuota, String> {
    let manager = state.0.read().await;

    // 解析最终使用的账号 ID：显式 > 默认账号 > 无账号 (not_found)
    let resolved = match account_id
        .as_deref()
        .map(str::trim)
        .filter(|id| !id.is_empty())
    {
        Some(id) => Some(id.to_string()),
        None => manager.default_account_id().await,
    };
    let Some(id) = resolved else {
        return Ok(SubscriptionQuota::not_found("google_oauth"));
    };

    // 获取（必要时自动刷新）access_token
    let token = match manager.get_valid_token_for_account(&id).await {
        Ok(t) => t,
        Err(e) => {
            return Ok(SubscriptionQuota::error(
                "google_oauth",
                CredentialStatus::Expired,
                format!("Google OAuth token unavailable: {e}"),
            ));
        }
    };

    crate::services::subscription::query_gemini_quota_with_tool_label(&token, "google_oauth").await
}

/// 查询 Google OAuth 订阅额度
#[tauri::command(rename_all = "camelCase")]
pub async fn get_google_oauth_quota(
    account_id: Option<String>,
    state: State<'_, GoogleOAuthState>,
) -> Result<SubscriptionQuota, String> {
    query_google_oauth_quota_for(&state, account_id).await
}

#[derive(Debug, Deserialize)]
struct GeminiModelItem {
    name: String,
}

#[derive(Debug, Deserialize)]
struct GeminiModelsResponse {
    #[serde(default)]
    models: Vec<GeminiModelItem>,
}

/// 获取 Google OAuth 可用模型列表
#[tauri::command(rename_all = "camelCase")]
pub async fn get_google_oauth_models(
    account_id: Option<String>,
    state: State<'_, GoogleOAuthState>,
) -> Result<Vec<FetchedModel>, String> {
    let manager = state.0.read().await;
    let resolved = match account_id
        .as_deref()
        .map(str::trim)
        .filter(|id| !id.is_empty())
    {
        Some(id) => Some(id.to_string()),
        None => manager.default_account_id().await,
    };
    let account_id = resolved.ok_or_else(|| "No usable Google account available".to_string())?;
    let token = manager
        .get_valid_token_for_account(&account_id)
        .await
        .map_err(|error| format!("Google OAuth token unavailable: {error}"))?;

    let response = crate::proxy::http_client::get()
        .get("https://generativelanguage.googleapis.com/v1beta/models")
        .bearer_auth(token)
        .timeout(Duration::from_secs(15))
        .send()
        .await;

    match response {
        Ok(resp) if resp.status().is_success() => {
            if let Ok(payload) = resp.json::<GeminiModelsResponse>().await {
                let models: Vec<FetchedModel> = payload
                    .models
                    .into_iter()
                    .map(|m| {
                        let id = m
                            .name
                            .strip_prefix("models/")
                            .unwrap_or(&m.name)
                            .to_string();
                        FetchedModel {
                            id,
                            owned_by: Some("google".to_string()),
                        }
                    })
                    .collect();
                if !models.is_empty() {
                    return Ok(models);
                }
            }
        }
        _ => {}
    }

    // 默认内置模型列表兜底
    Ok(vec![
        FetchedModel {
            id: "gemini-2.5-pro".to_string(),
            owned_by: Some("google".to_string()),
        },
        FetchedModel {
            id: "gemini-2.5-flash".to_string(),
            owned_by: Some("google".to_string()),
        },
        FetchedModel {
            id: "gemini-2.5-flash-lite".to_string(),
            owned_by: Some("google".to_string()),
        },
        FetchedModel {
            id: "gemini-3.7-flash".to_string(),
            owned_by: Some("google".to_string()),
        },
    ])
}

/// 尝试从本地 Gemini CLI 或 Keychain 导入已有凭据
#[tauri::command(rename_all = "camelCase")]
pub async fn import_google_oauth_local_credentials(
    state: State<'_, GoogleOAuthState>,
) -> Result<crate::proxy::providers::google_oauth_auth::GoogleOAuthAccount, String> {
    // 1. 尝试从 Keychain 或 ~/.gemini/oauth_creds.json 读取
    let (_access_token, refresh_token, status, _msg) =
        crate::services::subscription::read_gemini_credentials_raw();

    let refresh_token = match refresh_token {
        Some(rt) if !rt.trim().is_empty() => rt,
        _ => {
            return Err(format!(
                "未在本地检测到有效的 Gemini CLI 登录凭据 (status: {status:?})"
            ));
        }
    };

    let manager = state.0.write().await;
    manager
        .import_local_credentials(&refresh_token)
        .await
        .map_err(|e| format!("导入本地 Google 凭据失败: {e}"))
}
