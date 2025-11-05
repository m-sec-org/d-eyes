package progress

import (
	"fmt"
	"sync"
	"time"
)

// Manager 控制进度上报节奏，避免输出过于频繁
type Manager struct {
	reporter     Reporter
	interval     time.Duration
	debugEnabled bool

	mu           sync.Mutex
	totals       map[Stage]int
	current      map[Stage]int
	descriptions map[Stage]string
	lastReport   map[Stage]time.Time
	order        []Stage
	closed       bool
}

// NewManager 创建进度管理器
func NewManager(reporter Reporter, interval time.Duration, debug bool) *Manager {
	if interval <= 0 {
		interval = 500 * time.Millisecond
	}
	return &Manager{
		reporter:     reporter,
		interval:     interval,
		debugEnabled: debug,
		totals:       make(map[Stage]int),
		current:      make(map[Stage]int),
		descriptions: make(map[Stage]string),
		lastReport:   make(map[Stage]time.Time),
		order:        make([]Stage, 0),
	}
}

// StartStage 设置阶段的总数和描述
func (m *Manager) StartStage(stage Stage, total int, description string) {
	if m == nil || m.reporter == nil {
		return
	}
	m.mu.Lock()
	current := m.current[stage]
	_, exists := m.totals[stage]
	if !exists {
		m.order = append(m.order, stage)
	}
	m.totals[stage] = total
	m.descriptions[stage] = description
	m.mu.Unlock()
	if !exists {
		m.reporter.Stage(stage, total, description)
	} else if total > 0 {
		m.reporter.Update(stage, current, total, "")
	}
}

// Add 增加阶段进度
func (m *Manager) Add(stage Stage, delta int, detail string) {
	if m == nil || m.reporter == nil {
		return
	}
	if delta <= 0 {
		delta = 1
	}

	var shouldReport bool
	var current, total int

	m.mu.Lock()
	current = m.current[stage] + delta
	m.current[stage] = current
	total = m.totals[stage]
	if total > 0 && current > total {
		total = current
		m.totals[stage] = total
	}
	now := time.Now()
	if last, ok := m.lastReport[stage]; !ok || now.Sub(last) >= m.interval || (total > 0 && current >= total) {
		shouldReport = true
		m.lastReport[stage] = now
	}
	m.mu.Unlock()

	if shouldReport {
		var d string
		if m.debugEnabled {
			d = detail
		}
		m.reporter.Update(stage, current, total, d)
	}
}

// Debugf 输出调试信息
func (m *Manager) Debugf(format string, args ...interface{}) {
	if m == nil || m.reporter == nil || !m.debugEnabled {
		return
	}
	m.reporter.Debug(fmt.Sprintf(format, args...))
}

// Finish 完成所有阶段，输出最终进度
func (m *Manager) Finish() {
	if m == nil || m.reporter == nil {
		return
	}

	m.mu.Lock()
	if m.closed {
		m.mu.Unlock()
		return
	}
	m.closed = true
	order := append([]Stage(nil), m.order...)
	currentCopy := make(map[Stage]int, len(m.current))
	totalCopy := make(map[Stage]int, len(m.totals))
	for _, stage := range order {
		currentCopy[stage] = m.current[stage]
		totalCopy[stage] = m.totals[stage]
	}
	m.mu.Unlock()

	for _, stage := range order {
		m.reporter.Update(stage, currentCopy[stage], totalCopy[stage], "")
	}
	m.reporter.Finish()
}
