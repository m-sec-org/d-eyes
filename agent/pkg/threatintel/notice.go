package threatintel

// Notice code conventions:
// - `threatintel.notice` MUST be a stable, machine-assertable code (lowercase snake_case).
// - Human-readable context MUST be written to `threatintel.notice_detail`.
// - Multiple codes MAY be comma-separated (deterministic order).
const (
	NoticeCodeUnknown               = "unknown"
	NoticeCodeFallbackLocalNoAPIKey = "fallback_local_no_api_key"
	NoticeCodeInitFailed            = "init_failed"
	NoticeCodeServerMode            = "server_mode"

	// Reserved for 4.2+ remote providers.
	NoticeCodeRemoteQuotaExceeded = "remote_quota_exceeded"
	NoticeCodeRemotePaused        = "remote_paused"
	NoticeCodeProviderError       = "provider_error"
)
