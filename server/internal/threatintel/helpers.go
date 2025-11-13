package threatintel

import (
	"strconv"
	"strings"
	"time"
)

func parseRetryAfter(header string) time.Duration {
	if header == "" {
		return 30 * time.Second
	}
	if seconds, err := strconv.Atoi(header); err == nil && seconds > 0 {
		return time.Duration(seconds) * time.Second
	}
	if d, err := time.ParseDuration(header); err == nil && d > 0 {
		return d
	}
	return 30 * time.Second
}

func pickString(m map[string]any, keys ...string) string {
	for _, key := range keys {
		if v, ok := m[key]; ok {
			if s, ok := v.(string); ok && strings.TrimSpace(s) != "" {
				return s
			}
		}
		if v, ok := m[strings.ToLower(key)]; ok {
			if s, ok := v.(string); ok && strings.TrimSpace(s) != "" {
				return s
			}
		}
	}
	return ""
}
