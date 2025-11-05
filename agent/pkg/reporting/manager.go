package reporting

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/m-sec-org/d-eyes/agent/pkg/color"
	"github.com/m-sec-org/d-eyes/agent/pkg/config"
)

// OutputRecord tracks generated report artefacts.
type OutputRecord struct {
	Label string
	Path  string
}

// Summary provides an execution overview.
type Summary struct {
	Command  string
	Duration time.Duration
	Outputs  []OutputRecord
	Risks    map[string]int
	Notes    []string
	Status   string
}

// Manager coordinates report file creation and summarised output.
type Manager struct {
	baseDir string
	timeFn  func() time.Time

	once sync.Once
}

// NewManager instantiates a Manager based on configuration defaults.
func NewManager(cfg config.Config) *Manager {
	dir := cfg.Output.Dir
	if dir == "" {
		dir = config.Default().Output.Dir
	}
	abs, err := filepath.Abs(dir)
	if err == nil {
		dir = abs
	}
	return &Manager{
		baseDir: dir,
		timeFn:  time.Now,
	}
}

// BaseDir returns the root directory for generated artefacts.
func (m *Manager) BaseDir() string {
	return m.baseDir
}

// CreateFile prepares a new report file and returns its handle and full path.
func (m *Manager) CreateFile(command, name, ext string) (*os.File, string, error) {
	if ext == "" {
		ext = "txt"
	}
	if strings.HasPrefix(ext, ".") {
		ext = ext[1:]
	}
	if name == "" {
		name = "report"
	}
	normalisedCommand := sanitisePath(command)
	dir := filepath.Join(m.baseDir, normalisedCommand)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, "", fmt.Errorf("create report directory: %w", err)
	}
	filename := fmt.Sprintf("%s-%s.%s", m.timestamp(), sanitiseToken(name), ext)
	full := filepath.Join(dir, filename)
	f, err := os.Create(full)
	if err != nil {
		return nil, "", fmt.Errorf("create report file: %w", err)
	}
	return f, full, nil
}

// PrintSummary renders a unified command summary to stdout.
func (m *Manager) PrintSummary(summary Summary) {
	if summary.Command == "" {
		return
	}
	header := fmt.Sprintf("[D-Eyes] %s 完成", summary.Command)
	if summary.Status != "" {
		header = fmt.Sprintf("[D-Eyes] %s %s", summary.Command, summary.Status)
	}
	if summary.Duration > 0 {
		header = fmt.Sprintf("%s，用时 %.2f 秒", header, summary.Duration.Seconds())
	}
	fmt.Println(color.Cyan.Sprint(header))
	if len(summary.Outputs) > 0 {
		fmt.Println(color.Green.Sprint("生成报告:"))
		for _, out := range summary.Outputs {
			label := out.Label
			if label == "" {
				label = "输出"
			}
			fmt.Printf("  - %s: %s\n", label, out.Path)
		}
	}
	if len(summary.Risks) > 0 {
		fmt.Println(color.Magenta.Sprint("风险统计:"))
		for level, count := range summary.Risks {
			fmt.Printf("  - %s: %d\n", strings.ToUpper(level), count)
		}
	}
	for _, note := range summary.Notes {
		fmt.Printf("  * %s\n", note)
	}
}

func (m *Manager) timestamp() string {
	return m.timeFn().Format("20060102-150405")
}

func sanitisePath(command string) string {
	if command == "" {
		return "reports"
	}
	parts := strings.FieldsFunc(command, func(r rune) bool {
		return r == '/' || r == '\\'
	})
	if len(parts) == 0 {
		return "reports"
	}
	for i, part := range parts {
		parts[i] = sanitiseToken(part)
	}
	return filepath.Join(parts...)
}

func sanitiseToken(token string) string {
	token = strings.TrimSpace(token)
	if token == "" {
		return "report"
	}
	token = strings.ToLower(token)
	var builder strings.Builder
	for _, r := range token {
		switch {
		case r >= 'a' && r <= 'z':
			builder.WriteRune(r)
		case r >= '0' && r <= '9':
			builder.WriteRune(r)
		case r == '-' || r == '_' || r == '.':
			builder.WriteRune(r)
		default:
			builder.WriteRune('-')
		}
	}
	result := builder.String()
	result = strings.Trim(result, "-_.")
	if result == "" {
		return "report"
	}
	return result
}
