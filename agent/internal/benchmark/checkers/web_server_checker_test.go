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

type webMockExecutor struct {
	outputs map[string]engineResponse
}

func (m *webMockExecutor) Run(ctx context.Context, command string, args []string, shell bool, timeout time.Duration) (string, string, int, error) {
	key := command + " " + strings.Join(args, " ")
	if resp, ok := m.outputs[key]; ok {
		return resp.stdout, resp.stderr, resp.exitCode, resp.err
	}
	return "", "", 0, nil
}

func TestWebServerChecker_Check(t *testing.T) {
	exec := &webMockExecutor{outputs: map[string]engineResponse{
		"grep -i ^ServerTokens /etc/httpd/conf/httpd.conf":  {stdout: "ServerTokens Prod", exitCode: 0},
		"grep -R Options -Indexes /etc/httpd/conf":          {stdout: "Options -Indexes", exitCode: 0},
		"grep -i ^SSLProtocol /etc/httpd/conf.d/ssl.conf":   {stdout: "SSLProtocol -all +TLSv1.2", exitCode: 0},
		"grep -R server_tokens /etc/nginx/nginx.conf":       {stdout: "server_tokens off", exitCode: 0},
		"grep -R return 301 https /etc/nginx/sites-enabled": {stdout: "return 301 https://", exitCode: 0},
		"grep -R ssl_protocols /etc/nginx/nginx.conf":       {stdout: "ssl_protocols TLSv1.2 TLSv1.3", exitCode: 0},
		"powershell -Command (Get-WebConfigurationProperty -Filter system.webServer/httpProtocol/customHeaders/add -name . | Where-Object {$_.name -eq 'X-Powered-By'}).value": {stdout: "", exitCode: 0},
		"powershell -Command (Get-WebConfigurationProperty -Filter system.webServer/security/requestFiltering -name .).allowDoubleEscaping":                                    {stdout: "False", exitCode: 0},
	}}

	checker := NewWebServerChecker(benchmark.Config{})
	checker.SetRunner(engine.NewRunner(engine.WithExecutor(exec)))

	results, err := checker.Check(context.Background())
	assert.NoError(t, err)
	assert.Equal(t, 8, len(results))

	ids := map[string]benchmark.CheckResult{}
	for _, res := range results {
		ids[res.ID] = res
		assert.Equal(t, benchmark.StatusPass, res.Status)
	}

	expected := []string{
		"web_apache_server_tokens",
		"web_apache_directory_listing",
		"web_apache_ssl_protocols",
		"web_nginx_server_tokens",
		"web_nginx_https_redirect",
		"web_nginx_ssl_protocols",
		"web_iis_version_disclosure",
		"web_iis_request_filtering",
	}

	for _, id := range expected {
		_, ok := ids[id]
		assert.True(t, ok, "expected rule %s", id)
	}
}
