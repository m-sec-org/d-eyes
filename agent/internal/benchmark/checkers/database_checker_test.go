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

type dbMockExecutor struct {
	outputs map[string]engineResponse
}

type engineResponse struct {
	stdout   string
	stderr   string
	exitCode int
	err      error
}

func (m *dbMockExecutor) Run(ctx context.Context, command string, args []string, shell bool, timeout time.Duration) (string, string, int, error) {
	key := command + " " + strings.Join(args, " ")
	if resp, ok := m.outputs[key]; ok {
		return resp.stdout, resp.stderr, resp.exitCode, resp.err
	}
	return "", "", 0, nil
}

func TestDatabaseChecker_Check(t *testing.T) {
	exec := &dbMockExecutor{outputs: map[string]engineResponse{
		"mysql -NBe SHOW VARIABLES LIKE 'validate_password.policy';":                                                {stdout: "validate_password.policy\tMEDIUM", exitCode: 0},
		"mysql -NBe SELECT Host FROM mysql.user WHERE User='root' AND Host NOT IN ('localhost','127.0.0.1','::1');": {stdout: "", exitCode: 0},
		"mysql -NBe SHOW VARIABLES LIKE 'require_secure_transport';":                                                {stdout: "require_secure_transport\tON", exitCode: 0},
		"grep -i trust /var/lib/pgsql/data/pg_hba.conf":                                                             {stdout: "", exitCode: 0},
		"psql -tAc SHOW ssl;": {stdout: "on", exitCode: 0},
		"mongo --quiet --eval db.adminCommand({getParameter:1, authenticationMechanisms:1}).authenticationMechanisms": {stdout: "SCRAM-SHA-1 SCRAM-SHA-256", exitCode: 0},
		"mongo --quiet --eval db.adminCommand({getCmdLineOpts:1}).parsed.net.bindIp":                                  {stdout: "127.0.0.1", exitCode: 0},
		"redis-cli CONFIG GET requirepass":    {stdout: "requirepass strongpassword", exitCode: 0},
		"redis-cli CONFIG GET protected-mode": {stdout: "protected-mode yes", exitCode: 0},
	}}

	checker := NewDatabaseChecker(benchmark.Config{})
	checker.SetRunner(engine.NewRunner(engine.WithExecutor(exec)))

	results, err := checker.Check(context.Background())
	assert.NoError(t, err)
	assert.Equal(t, 9, len(results))

	ids := map[string]benchmark.CheckResult{}
	for _, res := range results {
		ids[res.ID] = res
		assert.Equal(t, benchmark.StatusPass, res.Status)
	}

	expected := []string{
		"db_mysql_password_policy",
		"db_mysql_remote_root",
		"db_mysql_tls_config",
		"db_postgresql_auth_method",
		"db_postgresql_ssl",
		"db_mongodb_auth",
		"db_mongodb_bind_ip",
		"db_redis_requirepass",
		"db_redis_protected_mode",
	}

	for _, id := range expected {
		_, ok := ids[id]
		assert.True(t, ok, "expected rule %s", id)
	}
}
