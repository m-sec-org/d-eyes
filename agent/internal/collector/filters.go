package collector

import "strings"

func filterMatchesAll(filters map[string][]string, event *SystemEvent) bool {
	if len(filters) == 0 || event == nil {
		return true
	}
	for key, values := range filters {
		value := getEventField(key, event)
		if value == "" || !containsIgnoreCase(values, value) {
			return false
		}
	}
	return true
}

func filterMatchesAny(filters map[string][]string, event *SystemEvent) bool {
	if len(filters) == 0 || event == nil {
		return false
	}
	for key, values := range filters {
		value := getEventField(key, event)
		if value != "" && containsIgnoreCase(values, value) {
			return true
		}
	}
	return false
}

func getEventField(field string, event *SystemEvent) string {
	if event == nil {
		return ""
	}
	key := strings.ToLower(strings.TrimSpace(field))
	switch key {
	case "event_type":
		return event.EventType
	case "source":
		return event.Source
	default:
		if value := lookupStringField(event.Metadata, key); value != "" {
			return value
		}
		if value := lookupStringField(event.Tags, key); value != "" {
			return value
		}
	}
	return ""
}

func containsIgnoreCase(values []string, target string) bool {
	for _, v := range values {
		if strings.EqualFold(strings.TrimSpace(v), target) {
			return true
		}
	}
	return false
}

func lookupStringField(fields map[string]string, key string) string {
	if len(fields) == 0 {
		return ""
	}
	normalized := strings.ToLower(strings.TrimSpace(key))
	if value, ok := fields[normalized]; ok {
		return value
	}
	for k, v := range fields {
		if strings.EqualFold(strings.TrimSpace(k), normalized) {
			return v
		}
	}
	return ""
}
