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

type appMockExecutor struct {
	outputs map[string]engineResponse
}

func (m *appMockExecutor) Run(ctx context.Context, command string, args []string, shell bool, timeout time.Duration) (string, string, int, error) {
	key := command + " " + strings.Join(args, " ")
	if resp, ok := m.outputs[key]; ok {
		return resp.stdout, resp.stderr, resp.exitCode, resp.err
	}
	return "", "", 0, nil
}

func TestAppServerChecker_Check(t *testing.T) {
	exec := &appMockExecutor{outputs: map[string]engineResponse{
		"grep -E role=\\\"(manager-gui|admin-gui)\\\" $CATALINA_BASE/conf/tomcat-users.xml":                               {stdout: "", exitCode: 0},
		"grep -R sslEnabledProtocols $CATALINA_BASE/conf/server.xml":                                                      {stdout: "sslEnabledProtocols=\"TLSv1.2\"", exitCode: 0},
		"wlst.sh checkConsoleSecure.py":                                                                                   {stdout: "SECURE", exitCode: 0},
		"wlst.sh checkSSL.py":                                                                                             {stdout: "ENABLED", exitCode: 0},
		"jboss-cli.sh --connect --command=:read-attribute(name=security-realm)":                                           {stdout: "management-realm", exitCode: 0},
		"jboss-cli.sh --connect --command=/subsystem=undertow/server=default-server/https-listener=https:read-resource()": {stdout: "enabled => true", exitCode: 0},
	}}

	checker := NewAppServerChecker(benchmark.Config{})
	checker.SetRunner(engine.NewRunner(engine.WithExecutor(exec)))

	results, err := checker.Check(context.Background())
	assert.NoError(t, err)
	assert.Equal(t, 6, len(results))

	ids := map[string]benchmark.CheckResult{}
	for _, res := range results {
		ids[res.ID] = res
		assert.Equal(t, benchmark.StatusPass, res.Status)
	}

	expected := []string{
		"app_tomcat_default_accounts",
		"app_tomcat_ssl",
		"app_weblogic_console_secure",
		"app_weblogic_ssl",
		"app_jboss_admin_console",
		"app_jboss_ssl_enabled",
	}
	for _, id := range expected {
		_, ok := ids[id]
		assert.True(t, ok, "expected rule %s", id)
	}
}
