import React from "react";
import type { ProviderMeta } from "@/types";
import { useGoogleOauthQuota } from "@/lib/query/subscription";
import { SubscriptionQuotaView } from "@/components/SubscriptionQuotaFooter";

interface GoogleOauthQuotaFooterProps {
  meta?: ProviderMeta;
  inline?: boolean;
  /** 是否为当前激活的供应商 */
  isCurrent?: boolean;
}

/**
 * Google OAuth (Gemini / Google AI 反代) 订阅额度 footer
 *
 * 复用 SubscriptionQuotaView 的全部渲染逻辑（5 状态 × inline/expanded）。
 * 数据源为 cc-switch 自管的 Google OAuth token，展示 Gemini Pro / Flash 订阅额度。
 */
const GoogleOauthQuotaFooter: React.FC<GoogleOauthQuotaFooterProps> = ({
  meta,
  inline = false,
  isCurrent = false,
}) => {
  const {
    data: quota,
    isFetching: loading,
    refetch,
  } = useGoogleOauthQuota(meta, { enabled: true, autoQuery: isCurrent });

  return (
    <SubscriptionQuotaView
      quota={quota}
      loading={loading}
      refetch={refetch}
      appIdForExpiredHint="google_oauth"
      inline={inline}
    />
  );
};

export default GoogleOauthQuotaFooter;
