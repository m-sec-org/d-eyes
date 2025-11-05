package queue

import (
	"context"

	"github.com/m-sec-org/d-eyes/server/internal/model"
)

// Queue represents the task dispatch queue backing the scheduler.
type Queue interface {
	Push(ctx context.Context, task *model.Task) error
	Requeue(ctx context.Context, task *model.Task) error
	Pop(ctx context.Context, capabilities []string) (*model.Task, error)
	Len(ctx context.Context) (int64, error)
	Close() error
}

// MatchCapabilities checks whether a task can be executed by the provided capability set.
func MatchCapabilities(task *model.Task, caps []string) bool {
	if len(caps) == 0 {
		return true
	}
	// metadata key "required_capabilities" may contain comma-separated capabilities.
	list := task.Metadata["required_capabilities"]
	if list == "" {
		return true
	}
	required := splitAndTrim(list)
	available := make(map[string]struct{}, len(caps))
	for _, c := range caps {
		available[c] = struct{}{}
	}
	for _, req := range required {
		if _, ok := available[req]; !ok {
			return false
		}
	}
	return true
}

func splitAndTrim(s string) []string {
	res := make([]string, 0)
	current := ""
	for _, r := range s {
		switch r {
		case ',', ';':
			if current != "" {
				res = append(res, trimSpaces(current))
				current = ""
			}
		default:
			current += string(r)
		}
	}
	if current != "" {
		res = append(res, trimSpaces(current))
	}
	return res
}

func trimSpaces(s string) string {
	start := 0
	for start < len(s) && (s[start] == ' ' || s[start] == '\t') {
		start++
	}
	end := len(s)
	for end > start && (s[end-1] == ' ' || s[end-1] == '\t') {
		end--
	}
	return s[start:end]
}
