package threatintel

import (
	"fmt"
	"strings"
)

const (
	maxNoticeDetailRunes      = 256
	maxNoticeDetailFieldRunes = 64
)

type NoticeField struct {
	Key   string
	Value string
}

// FormatNoticeDetail builds a short, human-readable detail string in a stable format.
// Callers should include only minimal diagnostic fields and MUST NOT embed request/headers/config dumps.
func FormatNoticeDetail(cfg Config, summary string, fields ...NoticeField) string {
	summary = strings.TrimSpace(summary)

	parts := make([]string, 0, 2)
	if summary != "" {
		parts = append(parts, summary)
	}

	fieldParts := make([]string, 0, len(fields))
	for _, field := range fields {
		key := strings.TrimSpace(field.Key)
		value := strings.TrimSpace(field.Value)
		if key == "" || value == "" {
			continue
		}
		value = strings.Join(strings.Fields(value), " ")
		value = truncateRunes(value, maxNoticeDetailFieldRunes)
		fieldParts = append(fieldParts, fmt.Sprintf("%s=%s", key, value))
	}
	if len(fieldParts) > 0 {
		parts = append(parts, strings.Join(fieldParts, " "))
	}

	return SanitizeNoticeDetail(strings.Join(parts, " | "), cfg)
}

// SanitizeNoticeDetail collapses whitespace, redacts configured secrets and truncates to a small budget.
func SanitizeNoticeDetail(detail string, cfg Config) string {
	detail = strings.TrimSpace(detail)
	if detail == "" {
		return ""
	}
	detail = strings.Join(strings.Fields(detail), " ")
	detail = RedactSensitive(detail, cfg)
	return truncateRunes(detail, maxNoticeDetailRunes)
}

func truncateRunes(value string, limit int) string {
	if limit <= 0 || value == "" {
		return ""
	}
	runes := []rune(value)
	if len(runes) <= limit {
		return value
	}
	if limit == 1 {
		return "…"
	}
	return string(runes[:limit-1]) + "…"
}
