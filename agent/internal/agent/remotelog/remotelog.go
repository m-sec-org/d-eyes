package remotelog

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"os"
	"sort"
	"strings"
	"time"
)

const (
	// Prefix is a stable grep-friendly marker for remote debug logs.
	Prefix = "[remote][debug]"
)

// Field represents a single key=value attribute in a remote debug log line.
type Field struct {
	Key   string
	Value any
}

// Logger emits redacted, structured remote debug logs.
type Logger struct {
	enabled  bool
	logger   *log.Logger
	redactor *Redactor
}

// Config controls remote debug logger behavior.
type Config struct {
	Enabled bool

	// Output is the destination for logs.
	// If nil, it defaults to writing to stderr and (if configured) the global log writer.
	Output io.Writer

	// Secrets are redacted from all string/error values.
	Secrets []string
}

// New constructs a remote debug Logger.
func New(cfg Config) *Logger {
	out := cfg.Output
	if out == nil {
		out = defaultOutput()
	}
	l := log.New(out, log.Prefix(), log.Flags())
	return &Logger{
		enabled:  cfg.Enabled,
		logger:   l,
		redactor: NewRedactor(cfg.Secrets...),
	}
}

func defaultOutput() io.Writer {
	global := log.Writer()
	if f, ok := global.(*os.File); ok && f == os.Stderr {
		return os.Stderr
	}
	return io.MultiWriter(os.Stderr, global)
}

// Enabled reports whether debug logging is active.
func (l *Logger) Enabled() bool {
	return l != nil && l.enabled
}

// Debug emits a structured debug line.
func (l *Logger) Debug(event string, fields ...Field) {
	if l == nil || !l.enabled {
		return
	}
	l.logger.Print(Format(event, l.redactor, fields...))
}

// Format renders a single structured line.
func Format(event string, redactor *Redactor, fields ...Field) string {
	event = strings.TrimSpace(event)
	if event == "" {
		event = "unknown"
	}
	var parts []string
	parts = append(parts, Prefix)
	parts = append(parts, "event="+formatValue(event, redactor, false))
	for _, f := range fields {
		key := normalizeKey(f.Key)
		if key == "" || key == "event" {
			continue
		}
		if isSensitiveKey(key) {
			parts = append(parts, key+"=<redacted>")
			continue
		}
		parts = append(parts, key+"="+formatValue(f.Value, redactor, true))
	}
	return strings.Join(parts, " ")
}

func normalizeKey(key string) string {
	key = strings.TrimSpace(key)
	if key == "" {
		return ""
	}
	key = strings.ToLower(key)
	var b strings.Builder
	b.Grow(len(key))
	for _, r := range key {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '_' || r == '-' || r == '.' {
			b.WriteRune(r)
			continue
		}
		if r == ' ' || r == '/' {
			b.WriteByte('_')
			continue
		}
		// Drop any other characters to keep logs parse-friendly.
	}
	return strings.Trim(b.String(), "._-")
}

func isSensitiveKey(key string) bool {
	k := strings.ToLower(strings.TrimSpace(key))
	if k == "" {
		return false
	}
	if strings.Contains(k, "token") {
		return true
	}
	if strings.Contains(k, "secret") || strings.Contains(k, "password") {
		return true
	}
	if k == "api_key" || k == "api-key" || strings.Contains(k, "apikey") {
		return true
	}
	if k == "authorization" || strings.Contains(k, "cookie") {
		return true
	}
	if k == "x-api-key" || strings.Contains(k, "x_api_key") {
		return true
	}
	return false
}

func formatValue(v any, redactor *Redactor, allowComplex bool) string {
	switch t := v.(type) {
	case nil:
		return "null"
	case string:
		return quoteString(redactor.Redact(t))
	case []string:
		return quoteString(strings.Join(limitStrings(sortedUnique(t), 64), ","))
	case time.Duration:
		return quoteString(t.String())
	case time.Time:
		return quoteString(t.UTC().Format(time.RFC3339Nano))
	case error:
		return quoteString(redactor.Redact(truncate(t.Error(), 512)))
	}
	if s, ok := v.(fmt.Stringer); ok && s != nil {
		return quoteString(redactor.Redact(truncate(s.String(), 512)))
	}
	if !allowComplex {
		return quoteString(redactor.Redact(truncate(fmt.Sprint(v), 512)))
	}
	switch t := v.(type) {
	case bool, int, int8, int16, int32, int64, uint, uint8, uint16, uint32, uint64, float32, float64:
		return fmt.Sprint(t)
	default:
		// Avoid dumping large payloads: fall back to a short JSON snippet.
		b, err := json.Marshal(t)
		if err != nil {
			return quoteString(redactor.Redact(truncate(fmt.Sprint(t), 512)))
		}
		if len(b) > 512 {
			b = append(b[:512], []byte("…")...)
		}
		return quoteString(redactor.Redact(string(b)))
	}
}

func quoteString(s string) string {
	if s == "" {
		return `""`
	}
	if isBareValue(s) {
		return s
	}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(s); err != nil {
		return fmt.Sprintf("%q", s)
	}
	return strings.TrimSuffix(buf.String(), "\n")
}

func isBareValue(s string) bool {
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z':
		case r >= 'A' && r <= 'Z':
		case r >= '0' && r <= '9':
		case r == '.' || r == '_' || r == '-' || r == '/' || r == ':' || r == '@':
		default:
			return false
		}
	}
	return true
}

func truncate(s string, max int) string {
	if max <= 0 || len(s) <= max {
		return s
	}
	if max <= 1 {
		return s[:max]
	}
	return s[:max-1] + "…"
}

func sortedUnique(items []string) []string {
	if len(items) == 0 {
		return nil
	}
	uniq := make(map[string]struct{}, len(items))
	for _, item := range items {
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}
		uniq[item] = struct{}{}
	}
	out := make([]string, 0, len(uniq))
	for k := range uniq {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func limitStrings(items []string, max int) []string {
	if max <= 0 || len(items) <= max {
		return items
	}
	truncated := make([]string, 0, max+1)
	truncated = append(truncated, items[:max]...)
	truncated = append(truncated, fmt.Sprintf("+%dmore", len(items)-max))
	return truncated
}

// JSONTopLevelKeys returns the sorted top-level keys for an object payload.
// It never returns nested keys and never returns values.
func JSONTopLevelKeys(payload []byte) []string {
	payload = bytes.TrimSpace(payload)
	if len(payload) == 0 || payload[0] != '{' {
		return nil
	}
	var m map[string]any
	if err := json.Unmarshal(payload, &m); err != nil {
		return nil
	}
	keys := make([]string, 0, len(m))
	for k := range m {
		k = strings.TrimSpace(k)
		if k != "" {
			keys = append(keys, k)
		}
	}
	sort.Strings(keys)
	return keys
}

// StringMapKeys returns the sorted keys of a map without values.
func StringMapKeys(m map[string]string) []string {
	if len(m) == 0 {
		return nil
	}
	keys := make([]string, 0, len(m))
	for k := range m {
		k = strings.TrimSpace(k)
		if k != "" {
			keys = append(keys, k)
		}
	}
	sort.Strings(keys)
	return keys
}
