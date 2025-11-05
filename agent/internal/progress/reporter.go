package progress

import (
	"fmt"
	"io"
	"os"
	"strings"
	"sync"

	"golang.org/x/term"

	"github.com/m-sec-org/d-eyes/agent/pkg/color"
)

// Reporter 负责输出进度信息
type Reporter interface {
	Stage(stage Stage, total int, description string)
	Update(stage Stage, current int, total int, detail string)
	Debug(message string)
	Finish()
}

// NewConsoleReporter 创建控制台 Reporter，progress 输出写入 writer
func NewConsoleReporter(writer io.Writer, enableColor bool, debug bool) Reporter {
	isTTY := false
	if f, ok := writer.(*os.File); ok {
		isTTY = term.IsTerminal(int(f.Fd()))
	}
	return &consoleReporter{
		writer:      writer,
		isTTY:       isTTY,
		enableColor: enableColor,
		debug:       debug,
	}
}

type consoleReporter struct {
	writer      io.Writer
	isTTY       bool
	enableColor bool
	debug       bool

	mu          sync.Mutex
	lastLineLen int
}

func (r *consoleReporter) Stage(stage Stage, total int, description string) {
	r.mu.Lock()
	defer r.mu.Unlock()

	r.clearLine()

	totalText := "未知"
	if total > 0 {
		totalText = fmt.Sprintf("%d", total)
	}
	label := r.coloredLabel(stage)
	line := fmt.Sprintf("[%s] %s (预计总数: %s)", label, description, totalText)
	fmt.Fprintln(r.writer, line)
	r.lastLineLen = 0
}

func (r *consoleReporter) Update(stage Stage, current int, total int, detail string) {
	r.mu.Lock()
	defer r.mu.Unlock()

	label := r.coloredLabel(stage)
	var percent string
	if total > 0 {
		ratio := float64(current) / float64(total)
		if ratio > 1 {
			ratio = 1
		}
		percent = fmt.Sprintf("%3d%%", int(ratio*100))
	} else {
		percent = "---"
	}

	totalText := "?"
	if total > 0 {
		totalText = fmt.Sprintf("%d", total)
	}

	line := fmt.Sprintf("[%s] 当前进度: %d/%s (%s)", label, current, totalText, percent)
	if r.isTTY {
		r.writeInline(line)
		if total > 0 && current >= total {
			fmt.Fprintln(r.writer)
			r.lastLineLen = 0
		}
	} else {
		fmt.Fprintln(r.writer, line)
	}

	if r.debug && detail != "" {
		if r.isTTY && r.lastLineLen > 0 {
			fmt.Fprintln(r.writer)
			r.lastLineLen = 0
		}
		fmt.Fprintf(r.writer, "    ↳ %s\n", detail)
	}
}

func (r *consoleReporter) Debug(message string) {
	if !r.debug {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()

	r.clearLine()
	fmt.Fprintf(r.writer, "[debug] %s\n", message)
}

func (r *consoleReporter) Finish() {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.isTTY && r.lastLineLen > 0 {
		fmt.Fprintln(r.writer)
		r.lastLineLen = 0
	}
}

func (r *consoleReporter) coloredLabel(stage Stage) string {
	label := stageLabel(stage)
	if !r.enableColor {
		return label
	}
	return color.Cyan.Sprint(label)
}

func (r *consoleReporter) clearLine() {
	if r.isTTY && r.lastLineLen > 0 {
		fmt.Fprintf(r.writer, "\r%s\r", strings.Repeat(" ", r.lastLineLen))
		r.lastLineLen = 0
	}
}

func (r *consoleReporter) writeInline(line string) {
	fmt.Fprintf(r.writer, "\r%s", line)
	r.lastLineLen = lenWithoutANSI(line)
}

func lenWithoutANSI(s string) int {
	count := 0
	skip := false
	for _, r := range s {
		if r == '\x1b' {
			skip = true
			continue
		}
		if skip {
			if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') {
				skip = false
			}
			continue
		}
		count++
	}
	return count
}

// NullReporter 不输出任何进度
type NullReporter struct{}

func (NullReporter) Stage(Stage, int, string)       {}
func (NullReporter) Update(Stage, int, int, string) {}
func (NullReporter) Debug(string)                   {}
func (NullReporter) Finish()                        {}
