package tasks

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/m-sec-org/d-eyes/agent/pkg/config"
)

func TestEvaluatePolicyTriggersFailure(t *testing.T) {
	err := evaluatePolicy(config.PolicyConfig{FailOn: "medium"}, map[string]int{"high": 1})
	require.Error(t, err)
}

func TestEvaluatePolicyIgnoresBelowThreshold(t *testing.T) {
	err := evaluatePolicy(config.PolicyConfig{FailOn: "critical"}, map[string]int{"high": 1})
	require.NoError(t, err)
}
