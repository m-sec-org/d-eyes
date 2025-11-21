package v1

import (
	"context"
	"net/http"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	"github.com/m-sec-org/d-eyes/server/internal/basscenarios"
)

func TestScenarioRequestToScenarioValidatesDependencies(t *testing.T) {
	req := scenarioRequest{
		Name: "invalid",
		Steps: []basscenarios.ScenarioStep{
			{ID: "s1", Name: "Recon", Action: "noop"},
		},
		Dependencies: []string{"bad-value"},
	}
	_, err := req.toScenario()
	require.Error(t, err)
	require.Contains(t, err.Error(), "invalid dependency id")
}

func TestScenarioRequestToScenarioBuildsDependencies(t *testing.T) {
	dep := uuid.New()
	req := scenarioRequest{
		Name: "valid",
		Steps: []basscenarios.ScenarioStep{
			{ID: "s1", Name: "Recon", Action: "noop"},
		},
		Dependencies: []string{dep.String()},
	}
	scenario, err := req.toScenario()
	require.NoError(t, err)
	require.Equal(t, []uuid.UUID{dep}, scenario.Dependencies)
}

func TestStatusFromScenarioError(t *testing.T) {
	tests := []struct {
		name   string
		err    error
		status int
	}{
		{"not found", basscenarios.ErrNotFound, http.StatusNotFound},
		{"invalid transition", basscenarios.ErrInvalidStatusTransition, http.StatusBadRequest},
		{"context canceled", context.Canceled, http.StatusRequestTimeout},
		{"context deadline", context.DeadlineExceeded, http.StatusRequestTimeout},
		{"default", assertErr("boom"), http.StatusBadRequest},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require.Equal(t, tt.status, statusFromScenarioError(tt.err))
		})
	}
}

type assertErr string

func (e assertErr) Error() string {
	return string(e)
}
