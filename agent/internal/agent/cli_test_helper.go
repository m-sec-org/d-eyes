package agent

import (
	"bytes"
	"context"
	"io"
	"os"
	"strings"
	"sync"

	internal "github.com/m-sec-org/d-eyes/agent/internal"
	"github.com/m-sec-org/d-eyes/agent/pkg/config"
)

// cliTestHelper 提供 CLI 集成测试所需的运行与捕获能力。
type cliTestHelper struct {
	stdout bytes.Buffer
	stderr bytes.Buffer
	mu     sync.Mutex
}

// run 执行 CLI 并返回退出码与错误，同时捕获输出。
func (h *cliTestHelper) run(ctx context.Context, cfg config.Config, args ...string) (int, error) {
	return h.runWithRuntime(ctx, NewRuntime(), cfg, args...)
}

func (h *cliTestHelper) runWithRuntime(ctx context.Context, runtime *Runtime, cfg config.Config, args ...string) (int, error) {
	h.mu.Lock()
	defer h.mu.Unlock()

	origStdout := os.Stdout
	origStderr := os.Stderr
	stdoutR, stdoutW, _ := os.Pipe()
	stderrR, stderrW, _ := os.Pipe()
	os.Stdout = stdoutW
	os.Stderr = stderrW
	defer func() {
		stdoutW.Close()
		stderrW.Close()
		os.Stdout = origStdout
		os.Stderr = origStderr

		io.Copy(&h.stdout, stdoutR)
		io.Copy(&h.stderr, stderrR)
	}()

	h.stdout.Reset()
	h.stderr.Reset()

	internal.SetGlobalConfig(cfg)
	internal.SetQuietMode(false)

	if runtime == nil {
		runtime = NewRuntime()
	}
	if len(args) == 0 {
		args = []string{"d-eyes", "version"}
	} else if !strings.HasPrefix(args[0], "d-eyes") {
		args = append([]string{"d-eyes"}, args...)
	}
	return runtime.Run(args)
}

func (h *cliTestHelper) stdoutString() string {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.stdout.String()
}

func (h *cliTestHelper) stderrString() string {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.stderr.String()
}
