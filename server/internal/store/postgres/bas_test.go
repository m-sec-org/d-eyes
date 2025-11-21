package postgres

import (
	"fmt"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/stretchr/testify/require"

	"github.com/m-sec-org/d-eyes/server/internal/store"
)

func TestScanBASScenarioDecodesFields(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	published := now.Add(time.Minute)
	scenarioID := uuid.New()
	dependency := uuid.New()
	stepsJSON := []byte(`[{"id":"s1","name":"Recon","action":"noop"}]`)
	limitsJSON := []byte(`{"max_targets":5,"max_parallel_steps":1,"max_duration_minutes":30,"max_cpu_percent":80}`)
	approvalJSON := []byte(`{"approved_by":"secops","notes":"ok"}`)
	recordsJSON := []byte(fmt.Sprintf(`[{"role":"secops","status":"approved","actor":"secops","updated_at":"%s"}]`, now.Format(time.RFC3339Nano)))
	policyJSON := []byte(`[{"role":"secops"},{"role":"ciso"}]`)
	executionPlanJSON := []byte(`{"mode":"serial","max_parallel":1}`)

	row := fakeRow{values: []any{
		scenarioID,
		"Scenario",
		2,
		"desc",
		[]string{"purple"},
		"pending",
		stepsJSON,
		limitsJSON,
		[]string{"dmz"},
		true,
		approvalJSON,
		recordsJSON,
		policyJSON,
		[]uuid.UUID{dependency},
		[]string{"zone=dmz"},
		executionPlanJSON,
		"author",
		"editor",
		now,
		now,
		published,
	}}

	scenario, err := scanBASScenario(row)
	require.NoError(t, err)
	require.Equal(t, scenarioID, scenario.ID)
	require.Equal(t, "Scenario", scenario.Name)
	require.Equal(t, "pending", scenario.Status)
	require.Len(t, scenario.Steps, 1)
	require.Equal(t, 5, scenario.ResourceLimits.MaxTargets)
	require.True(t, scenario.RequiresApproval)
	require.Equal(t, dependency, scenario.Dependencies[0])
	require.Equal(t, "serial", scenario.ExecutionPlan.Mode)
	require.Equal(t, "secops", scenario.Approval.ApprovedBy)
	require.NotNil(t, scenario.PublishedAt)
	require.Equal(t, published.Unix(), scenario.PublishedAt.Unix())
	require.Len(t, scenario.ApprovalRecords, 1)
	require.Equal(t, "secops", scenario.ApprovalRecords[0].Actor)
}

func TestScanBASScenarioNotFound(t *testing.T) {
	row := fakeRow{err: pgx.ErrNoRows}
	scenario, err := scanBASScenario(row)
	require.Nil(t, scenario)
	require.ErrorIs(t, err, store.ErrNotFound)
}

type fakeRow struct {
	values []any
	err    error
}

func (r fakeRow) Scan(dest ...any) error {
	if r.err != nil {
		return r.err
	}
	if len(dest) != len(r.values) {
		return fmt.Errorf("unexpected dest length")
	}
	for i, value := range r.values {
		switch out := dest[i].(type) {
		case *uuid.UUID:
			*out = value.(uuid.UUID)
		case *string:
			*out = value.(string)
		case *int:
			*out = value.(int)
		case *[]string:
			src := value.([]string)
			*out = append((*out)[:0], src...)
		case *[]uuid.UUID:
			src := value.([]uuid.UUID)
			*out = append((*out)[:0], src...)
		case *[]byte:
			src := value.([]byte)
			*out = append((*out)[:0], src...)
		case *bool:
			*out = value.(bool)
		case *time.Time:
			*out = value.(time.Time)
		case **time.Time:
			if value == nil {
				*out = nil
			} else {
				ts := value.(time.Time)
				tmp := ts
				*out = &tmp
			}
		default:
			return fmt.Errorf("unsupported scan dest %T", dest[i])
		}
	}
	return nil
}
