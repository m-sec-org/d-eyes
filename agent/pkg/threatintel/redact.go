package threatintel

import "strings"

const redactedValue = "<redacted>"

// RedactSensitive replaces configured API keys that may appear in logs or metadata.
// Callers MUST still avoid embedding secrets into error strings or notices.
func RedactSensitive(value string, cfg Config) string {
	return RedactSecrets(value, cfg.OpenTIPAPIKey, cfg.MetaDefenderAPIKey)
}

// RedactSecrets replaces each non-empty secret occurrence with a placeholder.
func RedactSecrets(value string, secrets ...string) string {
	if value == "" || len(secrets) == 0 {
		return value
	}
	redacted := value
	for _, secret := range secrets {
		secret = strings.TrimSpace(secret)
		if secret == "" {
			continue
		}
		redacted = strings.ReplaceAll(redacted, secret, redactedValue)
	}
	return redacted
}
