package checkpoint

import "time"

// EventLogState represents the state of an individual event log.
type EventLogState struct {
	Name         string    `yaml:"name"`
	RecordNumber uint64    `yaml:"record_number"`
	Timestamp    time.Time `yaml:"timestamp"`
	Bookmark     string    `yaml:"bookmark,omitempty"`
}
