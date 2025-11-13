package playbook

import (
	"strings"
)

// TriggerEvent represents an incoming signal (threat intel verdict, anomaly, task event...)
type TriggerEvent struct {
	Type       string
	Attributes map[string]string
	Payload    interface{}
}

func (e TriggerEvent) Get(key string) string {
	if len(e.Attributes) == 0 {
		return ""
	}
	return e.Attributes[strings.ToLower(key)]
}
