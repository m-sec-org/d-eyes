//go:build linux || windows || darwin

package checkers

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/m-sec-org/d-eyes/agent/internal/benchmark"
	"github.com/m-sec-org/d-eyes/agent/internal/benchmark/engine"
)

type osMockExecutor struct {
	outputs map[string]engineTestResponse
}

type engineTestResponse struct {
	stdout   string
	stderr   string
	exitCode int
	err      error
}

func (m *osMockExecutor) Run(ctx context.Context, command string, args []string, shell bool, timeout time.Duration) (string, string, int, error) {
	key := command + " " + strings.Join(args, " ")
	if resp, ok := m.outputs[key]; ok {
		return resp.stdout, resp.stderr, resp.exitCode, resp.err
	}
	return "", "", 0, nil
}

func TestLinuxOSChecker_Check(t *testing.T) {
	exec := &osMockExecutor{outputs: map[string]engineTestResponse{
		"grep PASS_MAX_DAYS /etc/login.defs": {stdout: "PASS_MAX_DAYS 90", exitCode: 0},
		"sshd -T":                            {stdout: "permitrootlogin no", exitCode: 0},
		"systemctl is-active firewalld":      {stdout: "active", exitCode: 0},
	}}
	checker := NewLinuxOSChecker(benchmark.Config{})
	checker.SetRunner(engine.NewRunner(engine.WithExecutor(exec)))

	results, err := checker.Check(context.Background())
	assert.NoError(t, err)
	assert.Len(t, results, 3)

	ids := map[string]bool{}
	for _, res := range results {
		ids[res.ID] = true
		assert.Equal(t, benchmark.StatusPass, res.Status)
	}

	assert.True(t, ids["os_linux_password_policy"])
	assert.True(t, ids["os_linux_sshd_root_login"])
	assert.True(t, ids["os_linux_firewall_active"])
}

func TestWindowsOSChecker_Check(t *testing.T) {
	exec := &osMockExecutor{outputs: map[string]engineTestResponse{
		"powershell -Command (Get-LocalUser -Name 'Administrator').Enabled":                    {stdout: "False", exitCode: 0},
		"powershell -Command (Get-Service -Name wuauserv).StartType":                           {stdout: "Automatic", exitCode: 0},
		"powershell -Command (Get-NetFirewallProfile | Where-Object {$_.Enabled -eq 0}).Count": {stdout: "0", exitCode: 0},
	}}
	checker := NewWindowsOSChecker(benchmark.Config{})
	checker.SetRunner(engine.NewRunner(engine.WithExecutor(exec)))

	results, err := checker.Check(context.Background())
	assert.NoError(t, err)
	assert.Len(t, results, 3)

	ids := map[string]bool{}
	for _, res := range results {
		ids[res.ID] = true
		assert.Equal(t, benchmark.StatusPass, res.Status)
	}

	assert.True(t, ids["os_windows_admin_account"])
	assert.True(t, ids["os_windows_auto_update"])
	assert.True(t, ids["os_windows_firewall"])
}
