package remotelog

import (
	"sort"
	"strings"
)

// Redactor removes configured secrets from log strings.
type Redactor struct {
	secrets []string
}

// NewRedactor constructs a Redactor. Empty secrets are ignored.
func NewRedactor(secrets ...string) *Redactor {
	clean := make([]string, 0, len(secrets))
	seen := make(map[string]struct{}, len(secrets))
	for _, s := range secrets {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		if _, ok := seen[s]; ok {
			continue
		}
		seen[s] = struct{}{}
		clean = append(clean, s)
	}
	// Longest first to avoid partial overlaps leaking remaining suffix/prefix.
	sort.Slice(clean, func(i, j int) bool { return len(clean[i]) > len(clean[j]) })
	return &Redactor{secrets: clean}
}

// Redact returns a redacted version of s.
func (r *Redactor) Redact(s string) string {
	if r == nil || len(r.secrets) == 0 || s == "" {
		return s
	}
	out := s
	for _, secret := range r.secrets {
		if secret == "" {
			continue
		}
		out = strings.ReplaceAll(out, secret, "<redacted>")
	}
	return out
}
