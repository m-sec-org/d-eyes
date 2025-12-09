package store

import "strings"

func ClampEventQueryLimit(limit int) int {
	if limit <= 0 {
		return 100
	}
	if limit > 1000 {
		return 1000
	}
	return limit
}

func NormalizeStringList(values []string) []string {
	if len(values) == 0 {
		return nil
	}
	out := make([]string, 0, len(values))
	for _, v := range values {
		name := strings.ToLower(strings.TrimSpace(v))
		if name == "" {
			continue
		}
		out = append(out, name)
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func DefaultPriorityLabel(v string) string {
	name := strings.ToLower(strings.TrimSpace(v))
	if name == "" {
		return "normal"
	}
	return name
}

func DefaultTierLabel(v string) string {
	name := strings.ToLower(strings.TrimSpace(v))
	if name == "" {
		return "hot"
	}
	return name
}
