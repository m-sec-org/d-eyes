//go:build linux

package collector

import (
	"fmt"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/sys/unix"
)

type ebpfDetector interface {
	ID() string
	Name() string
	Evaluate(event *SystemEvent, tracker *ebpfTracker) *DetectionResult
}

type ebpfDetectionEngine struct {
	mu        sync.Mutex
	detectors []ebpfDetector
	tracker   *ebpfTracker
	stats     detectionStats
}

func newEBPFDetectionEngine() *ebpfDetectionEngine {
	return &ebpfDetectionEngine{
		detectors: []ebpfDetector{
			trojanUploadDetector{},
			memoryImplantDetector{},
			remoteCommandDetector{},
		},
		tracker: newEBPFTracker(),
	}
}

func (e *ebpfDetectionEngine) Evaluate(event *SystemEvent) *DetectionResult {
	if e == nil || event == nil {
		return nil
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	e.tracker.prune(event.Timestamp.Add(-2 * time.Minute))
	for _, det := range e.detectors {
		res := det.Evaluate(event, e.tracker)
		if res == nil {
			continue
		}
		if res.RuleID == "" {
			res.RuleID = det.ID()
		}
		if res.Name == "" {
			res.Name = det.Name()
		}
		if res.ID == "" {
			res.ID = fmt.Sprintf("%s-%d", res.RuleID, time.Now().UnixNano())
		}
		e.stats.Record(res.RuleID, res.ID)
		return res
	}
	return nil
}

func (e *ebpfDetectionEngine) Stats() (uint64, map[string]uint64, map[string]string) {
	if e == nil {
		return 0, nil, nil
	}
	return e.stats.Snapshot()
}

type ebpfTracker struct {
	writes   map[uint32]trackedWrite
	connects map[uint32]trackedConn
}

type trackedWrite struct {
	Path string
	Seen time.Time
}

type trackedConn struct {
	Addr string
	Port int
	Seen time.Time
}

func newEBPFTracker() *ebpfTracker {
	return &ebpfTracker{
		writes:   make(map[uint32]trackedWrite),
		connects: make(map[uint32]trackedConn),
	}
}

func (t *ebpfTracker) rememberWrite(pid uint32, path string, ts time.Time) {
	if pid == 0 || path == "" {
		return
	}
	t.writes[pid] = trackedWrite{Path: path, Seen: ts}
}

func (t *ebpfTracker) lastWrite(pid uint32, within time.Duration, now time.Time) (trackedWrite, bool) {
	entry, ok := t.writes[pid]
	if !ok {
		return trackedWrite{}, false
	}
	if now.Sub(entry.Seen) > within {
		delete(t.writes, pid)
		return trackedWrite{}, false
	}
	return entry, true
}

func (t *ebpfTracker) rememberConnect(pid uint32, addr string, port int, ts time.Time) {
	if pid == 0 || port <= 0 {
		return
	}
	t.connects[pid] = trackedConn{Addr: addr, Port: port, Seen: ts}
}

func (t *ebpfTracker) lastConnect(pid uint32, within time.Duration, now time.Time) (trackedConn, bool) {
	entry, ok := t.connects[pid]
	if !ok {
		return trackedConn{}, false
	}
	if now.Sub(entry.Seen) > within {
		delete(t.connects, pid)
		return trackedConn{}, false
	}
	return entry, true
}

func (t *ebpfTracker) prune(expireBefore time.Time) {
	for pid, entry := range t.writes {
		if entry.Seen.Before(expireBefore) {
			delete(t.writes, pid)
		}
	}
	for pid, entry := range t.connects {
		if entry.Seen.Before(expireBefore) {
			delete(t.connects, pid)
		}
	}
}

type trojanUploadDetector struct{}

func (trojanUploadDetector) ID() string   { return "ebpf.detector.trojan_upload" }
func (trojanUploadDetector) Name() string { return "Suspicious Trojan Upload" }

func (trojanUploadDetector) Evaluate(event *SystemEvent, tracker *ebpfTracker) *DetectionResult {
	if event == nil || tracker == nil {
		return nil
	}
	pid := pidFromEvent(event)
	if pid == 0 {
		return nil
	}
	now := event.Timestamp
	switch event.EventType {
	case "net.connect", "net.sendmsg":
		port := parsePort(event.Metadata)
		if !isSuspiciousPort(port) {
			return nil
		}
		addr := firstNonEmpty(event.Metadata["connect.ipv4"], event.Metadata["sendmsg.ipv4"])
		tracker.rememberConnect(pid, addr, port, now)
	case "fs.write", "fs.open":
		path := pathFromEvent(event)
		if !isSuspiciousPath(path) {
			return nil
		}
		tracker.rememberWrite(pid, path, now)
		if conn, ok := tracker.lastConnect(pid, 90*time.Second, now); ok {
			return &DetectionResult{
				Category:    "trojan_upload",
				Severity:    "high",
				Action:      DetectionActionRespond,
				Description: "Process wrote an executable-like payload after reaching out to a remote endpoint.",
				Confidence:  0.78,
				Metadata: map[string]string{
					"path":        path,
					"pid":         fmt.Sprintf("%d", pid),
					"remote_ip":   conn.Addr,
					"remote_port": fmt.Sprintf("%d", conn.Port),
				},
				Tags: map[string]string{
					"source": "ebpf",
				},
			}
		}
	case "process.exec":
		path := pathFromEvent(event)
		if path == "" {
			return nil
		}
		if write, ok := tracker.lastWrite(pid, 2*time.Minute, now); ok && samePathPrefix(write.Path, path) {
			return &DetectionResult{
				Category:    "trojan_upload",
				Severity:    "high",
				Action:      DetectionActionRespond,
				Description: "Executable launched shortly after being staged in a temporary directory.",
				Confidence:  0.7,
				Metadata: map[string]string{
					"path":      path,
					"pid":       fmt.Sprintf("%d", pid),
					"staged_at": write.Path,
				},
				Tags: map[string]string{
					"source": "ebpf",
				},
			}
		}
	}
	return nil
}

type memoryImplantDetector struct{}

func (memoryImplantDetector) ID() string   { return "ebpf.detector.memory_implant" }
func (memoryImplantDetector) Name() string { return "Writable + Executable Mapping" }

func (memoryImplantDetector) Evaluate(event *SystemEvent, tracker *ebpfTracker) *DetectionResult {
	if event == nil {
		return nil
	}
	if event.EventType != "mem.mmap" && event.EventType != "mem.mprotect" {
		return nil
	}
	prot := protFromEvent(event)
	if prot == 0 || !hasWriteExec(prot) {
		return nil
	}
	pid := pidFromEvent(event)
	meta := map[string]string{
		"pid":    fmt.Sprintf("%d", pid),
		"prot":   fmt.Sprintf("0x%x", prot),
		"length": fmt.Sprintf("%v", event.Payload["length"]),
	}
	if addr := numericToUint64(event.Payload["address"]); addr != 0 {
		meta["address"] = fmt.Sprintf("0x%x", addr)
	}
	return &DetectionResult{
		Category:    "memory_implant",
		Severity:    "critical",
		Action:      DetectionActionRespond,
		Description: "Process requested writable + executable memory, a common memory implant primitive.",
		Confidence:  0.82,
		Metadata:    meta,
		Tags: map[string]string{
			"source": "ebpf",
		},
	}
}

type remoteCommandDetector struct{}

func (remoteCommandDetector) ID() string   { return "ebpf.detector.remote_command" }
func (remoteCommandDetector) Name() string { return "Remote Command Execution" }

func (remoteCommandDetector) Evaluate(event *SystemEvent, tracker *ebpfTracker) *DetectionResult {
	if event == nil || tracker == nil {
		return nil
	}
	pid := pidFromEvent(event)
	if pid == 0 {
		return nil
	}
	now := event.Timestamp
	switch event.EventType {
	case "net.connect", "net.sendmsg":
		port := parsePort(event.Metadata)
		if !isRemoteCommandPort(port) {
			return nil
		}
		addr := firstNonEmpty(event.Metadata["connect.ipv4"], event.Metadata["sendmsg.ipv4"])
		tracker.rememberConnect(pid, addr, port, now)
	case "process.exec":
		cmd := commandFromEvent(event)
		if !isSuspiciousShell(cmd) {
			return nil
		}
		if conn, ok := tracker.lastConnect(pid, 45*time.Second, now); ok {
			return &DetectionResult{
				Category:    "remote_command",
				Severity:    "high",
				Action:      DetectionActionRespond,
				Description: "Shell interpreter executed immediately after a high-risk remote connection.",
				Confidence:  0.74,
				Metadata: map[string]string{
					"command":     cmd,
					"pid":         fmt.Sprintf("%d", pid),
					"remote_ip":   conn.Addr,
					"remote_port": fmt.Sprintf("%d", conn.Port),
				},
				Tags: map[string]string{
					"source": "ebpf",
				},
			}
		}
	}
	return nil
}

func pidFromEvent(event *SystemEvent) uint32 {
	if event == nil || event.Payload == nil {
		return 0
	}
	val, ok := event.Payload["pid"]
	if !ok {
		return 0
	}
	switch v := val.(type) {
	case uint32:
		return v
	case int:
		return uint32(v)
	case int32:
		return uint32(v)
	case uint64:
		return uint32(v)
	case float64:
		return uint32(v)
	default:
		return 0
	}
}

func pathFromEvent(event *SystemEvent) string {
	if event == nil {
		return ""
	}
	if event.Payload != nil {
		if v, ok := event.Payload["path"]; ok {
			if s, ok := v.(string); ok {
				return s
			}
		}
		if v, ok := event.Payload["unix_path"]; ok {
			if s, ok := v.(string); ok {
				return s
			}
		}
	}
	if event.Metadata != nil {
		if path := event.Metadata["process.exec.path"]; path != "" {
			return path
		}
	}
	return ""
}

func commandFromEvent(event *SystemEvent) string {
	if event == nil || event.Payload == nil {
		return ""
	}
	if v, ok := event.Payload["path"]; ok {
		if s, ok := v.(string); ok && s != "" {
			return s
		}
	}
	if v, ok := event.Payload["comm"]; ok {
		if s, ok := v.(string); ok {
			return s
		}
	}
	return ""
}

func parsePort(meta map[string]string) int {
	if len(meta) == 0 {
		return 0
	}
	for _, key := range []string{"connect.port", "sendmsg.port"} {
		if val := strings.TrimSpace(meta[key]); val != "" {
			if port, err := strconv.Atoi(val); err == nil {
				return port
			}
		}
	}
	return 0
}

func isSuspiciousPort(port int) bool {
	if port == 0 {
		return false
	}
	switch port {
	case 20, 21, 22, 23, 25, 80, 443, 445, 8080, 8443, 9001:
		return true
	default:
		return port >= 1024 && (port == 4444 || port == 1337 || port == 5985 || port == 3389)
	}
}

func isRemoteCommandPort(port int) bool {
	if port == 0 {
		return false
	}
	switch port {
	case 22, 23, 3389, 5985, 5986, 2222, 4444:
		return true
	default:
		return port >= 5900 && port <= 5999
	}
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}

func isSuspiciousPath(path string) bool {
	if path == "" {
		return false
	}
	lower := strings.ToLower(path)
	suspiciousPrefixes := []string{"/tmp/", "/var/tmp/", "/dev/shm/", "/run/lock/", "/run/tmpfs/"}
	for _, prefix := range suspiciousPrefixes {
		if strings.HasPrefix(lower, prefix) {
			return true
		}
	}
	if strings.Contains(lower, "/.cache/") || strings.Contains(lower, "/.ssh/") {
		return true
	}
	suspiciousSuffixes := []string{".sh", ".py", ".pl", ".php", ".bin", ".run", ".xz", ".tar.gz"}
	for _, suf := range suspiciousSuffixes {
		if strings.HasSuffix(lower, suf) {
			return true
		}
	}
	return false
}

func samePathPrefix(a, b string) bool {
	if a == "" || b == "" {
		return false
	}
	dir := func(path string) string {
		if idx := strings.LastIndex(path, "/"); idx > 0 {
			return path[:idx]
		}
		return path
	}
	return dir(a) == dir(b)
}

func protFromEvent(event *SystemEvent) uint64 {
	if event == nil || event.Payload == nil {
		return 0
	}
	return numericToUint64(event.Payload["prot"])
}

func hasWriteExec(prot uint64) bool {
	if prot == 0 {
		return false
	}
	return prot&uint64(unix.PROT_WRITE) != 0 && prot&uint64(unix.PROT_EXEC) != 0
}

func numericToUint64(val any) uint64 {
	switch v := val.(type) {
	case uint64:
		return v
	case uint32:
		return uint64(v)
	case int:
		if v < 0 {
			return 0
		}
		return uint64(v)
	case int64:
		if v < 0 {
			return 0
		}
		return uint64(v)
	case float64:
		if v < 0 {
			return 0
		}
		return uint64(v)
	default:
		return 0
	}
}

func isSuspiciousShell(command string) bool {
	if command == "" {
		return false
	}
	lower := strings.ToLower(command)
	shells := []string{"bash", "/bin/bash", "sh", "/bin/sh", "dash", "zsh", "ksh", "fish", "python", "python3", "perl", "php", "ruby", "pwsh", "powershell", "busybox", "ash", "tcsh"}
	for _, shell := range shells {
		if strings.HasSuffix(lower, shell) || lower == shell {
			return true
		}
	}
	return false
}
