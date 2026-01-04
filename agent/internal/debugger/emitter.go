package debugger

import (
	"bytes"
	"compress/gzip"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"time"

	"golang.org/x/term"
)

// Event captures a single debug entry for CLI/metadata use.
type Event struct {
	Timestamp time.Time      `json:"ts"`
	Type      string         `json:"type"`
	Phase     string         `json:"phase,omitempty"`
	Message   string         `json:"message,omitempty"`
	Detail    string         `json:"detail,omitempty"`
	Current   int            `json:"current,omitempty"`
	Total     int            `json:"total,omitempty"`
	Fields    map[string]any `json:"fields,omitempty"`
}

// Emitter collects debug events and optionally streams them.
type Emitter struct {
	writer          io.Writer
	enabled         bool
	limit           int
	isTTY           bool
	lastProgressLen int

	mu     sync.Mutex
	events []Event
}

// NewEmitter constructs an emitter. If writer is nil or enabled is false, it behaves as a no-op collector.
func NewEmitter(writer io.Writer, enabled bool) *Emitter {
	isTTY := false
	if f, ok := writer.(*os.File); ok {
		isTTY = term.IsTerminal(int(f.Fd()))
	}
	return &Emitter{writer: writer, enabled: enabled, limit: 200, isTTY: isTTY}
}

// Enable sets the emitter state.
func (e *Emitter) Enable() {
	e.mu.Lock()
	e.enabled = true
	e.mu.Unlock()
}

// Enabled reports whether the emitter is active.
func (e *Emitter) Enabled() bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.enabled
}

func (e *Emitter) append(ev Event) {
	e.mu.Lock()
	defer e.mu.Unlock()
	ev.Timestamp = time.Now()
	if e.limit <= 0 {
		e.limit = 200
	}
	if len(e.events) >= e.limit {
		copy(e.events, e.events[1:])
		e.events[len(e.events)-1] = ev
	} else {
		e.events = append(e.events, ev)
	}
	if !e.enabled || e.writer == nil {
		return
	}
	if ev.Type == "progress.update" {
		e.renderProgress(ev)
		return
	}
	e.clearProgressLine()
	fmt.Fprintf(e.writer, "%s\n", formatEvent(ev))
}

// Events returns a snapshot of buffered events.
func (e *Emitter) Events() []Event {
	e.mu.Lock()
	defer e.mu.Unlock()
	out := make([]Event, len(e.events))
	copy(out, e.events)
	return out
}

// Metadata encodes buffered events and summary for persistence.
func (e *Emitter) Metadata() map[string]string {
	if e == nil {
		return nil
	}
	events := e.Events()
	if len(events) == 0 {
		return nil
	}
	encoded, err := encode(events)
	if err != nil || encoded == "" {
		return nil
	}
	summary := buildSummary(events)
	meta := map[string]string{
		"telemetry.debug_timeline": encoded,
		"telemetry.debug.summary":  summary,
	}
	if errPhase := firstErrorPhase(events); errPhase != "" {
		meta["telemetry.debug.error_phase"] = errPhase
	}
	return meta
}

// SetLimit adjusts the buffer size.
func (e *Emitter) SetLimit(limit int) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if limit <= 0 {
		limit = 200
	}
	e.limit = limit
}

// PhaseStart records a phase start event.
func (e *Emitter) PhaseStart(phase, label, target string) {
	if e == nil {
		return
	}
	e.append(Event{Type: "phase.start", Phase: phase, Message: label, Detail: target})
}

// PhaseEnd records a phase end event.
func (e *Emitter) PhaseEnd(phase, message string) {
	if e == nil {
		return
	}
	e.append(Event{Type: "phase.end", Phase: phase, Message: message})
}

// Progress records a progress update.
func (e *Emitter) Progress(phase string, current, total int, detail string) {
	if e == nil {
		return
	}
	e.append(Event{Type: "progress.update", Phase: phase, Current: current, Total: total, Detail: detail})
}

// Notice records an informational event.
func (e *Emitter) Notice(scope, message string) {
	if e == nil {
		return
	}
	e.append(Event{Type: "notice", Phase: scope, Message: message})
}

// Error records an error event.
func (e *Emitter) Error(scope, message string) {
	if e == nil {
		return
	}
	e.append(Event{Type: "error", Phase: scope, Message: message})
}

// Artifact records artifact creation.
func (e *Emitter) Artifact(label, path string) {
	if e == nil {
		return
	}
	e.append(Event{Type: "artifact.ready", Message: label, Detail: path})
}

// formatEvent renders a single line for CLI output.
func formatEvent(ev Event) string {
	ts := ev.Timestamp.Format("15:04:05")
	phase := ev.Phase
	if phase == "" {
		phase = "general"
	}
	switch ev.Type {
	case "phase.start":
		return fmt.Sprintf("[%s][%s] start %s %s", ts, phase, ev.Message, ev.Detail)
	case "phase.end":
		return fmt.Sprintf("[%s][%s] end %s", ts, phase, ev.Message)
	case "progress.update":
		total := "?"
		if ev.Total > 0 {
			total = fmt.Sprintf("%d", ev.Total)
		}
		return fmt.Sprintf("[%s][%s] progress %d/%s %s", ts, phase, ev.Current, total, ev.Detail)
	case "artifact.ready":
		return fmt.Sprintf("[%s][%s] artifact %s => %s", ts, phase, ev.Message, ev.Detail)
	case "notice":
		return fmt.Sprintf("[%s][%s] notice %s", ts, phase, ev.Message)
	case "error":
		return fmt.Sprintf("[%s][%s] error %s", ts, phase, ev.Message)
	default:
		return fmt.Sprintf("[%s][%s] %s %s", ts, phase, ev.Type, ev.Message)
	}
}

func encode(events []Event) (string, error) {
	data, err := json.Marshal(events)
	if err != nil {
		return "", err
	}
	var buf bytes.Buffer
	w := gzip.NewWriter(&buf)
	if _, err := w.Write(data); err != nil {
		return "", err
	}
	if err := w.Close(); err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(buf.Bytes()), nil
}

func buildSummary(events []Event) string {
	if len(events) == 0 {
		return ""
	}
	cnts := make(map[string]int)
	var first, last time.Time
	var lastPhase string
	for _, ev := range events {
		cnts[ev.Type]++
		if first.IsZero() || ev.Timestamp.Before(first) {
			first = ev.Timestamp
		}
		if ev.Timestamp.After(last) {
			last = ev.Timestamp
			lastPhase = ev.Phase
		}
	}
	summary := map[string]any{
		"counts":      cnts,
		"first_ts":    first.UTC().Format(time.RFC3339Nano),
		"last_ts":     last.UTC().Format(time.RFC3339Nano),
		"last_phase":  lastPhase,
		"event_total": len(events),
	}
	b, err := json.Marshal(summary)
	if err != nil {
		return ""
	}
	return string(b)
}

func firstErrorPhase(events []Event) string {
	for _, ev := range events {
		if ev.Type == "error" {
			return ev.Phase
		}
	}
	return ""
}

func (e *Emitter) renderProgress(ev Event) {
	if !e.isTTY {
		e.clearProgressLine()
		fmt.Fprintf(e.writer, "%s\n", formatEvent(ev))
		return
	}
	percent := 0
	if ev.Total > 0 {
		percent = int(float64(ev.Current) / float64(ev.Total) * 100)
		if percent > 100 {
			percent = 100
		}
	}
	line := fmt.Sprintf("[%s][%s] %3d%% %s", ev.Timestamp.Format("15:04:05"), ev.Phase, percent, ev.Detail)
	fmt.Fprintf(e.writer, "\r%s", line)
	if len(line) > e.lastProgressLen {
		e.lastProgressLen = len(line)
	}
	if ev.Total > 0 && ev.Current >= ev.Total {
		fmt.Fprint(e.writer, "\r")
		e.clearProgressLine()
	}
}

func (e *Emitter) clearProgressLine() {
	if !e.isTTY || e.lastProgressLen == 0 {
		return
	}
	spaces := strings.Repeat(" ", e.lastProgressLen)
	fmt.Fprintf(e.writer, "\r%s\r", spaces)
	e.lastProgressLen = 0
}
