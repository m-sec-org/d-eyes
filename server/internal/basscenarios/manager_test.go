package basscenarios

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/m-sec-org/d-eyes/server/internal/store"
)

func newTestManager(t *testing.T) *Manager {
	return newTestManagerWithPolicy(t, nil)
}

func newTestManagerWithPolicy(t *testing.T, policy []ApprovalRule) *Manager {
	t.Helper()
	st := store.NewInMemoryStore()
	cfg := Config{
		Store: st,
		DefaultResourceLimits: ResourceLimits{
			MaxTargets:        10,
			MaxParallelSteps:  2,
			MaxDurationMinute: 10,
			MaxCPUPercent:     80,
		},
		DefaultApprovalPolicy: []ApprovalRule{
			{Role: "secops"},
			{Role: "ciso"},
		},
	}
	if len(policy) > 0 {
		cfg.DefaultApprovalPolicy = policy
	}
	mgr, err := NewManager(cfg, nil)
	require.NoError(t, err)
	return mgr
}

func sampleScenario() Scenario {
	return Scenario{
		Name:             "Sample BAS",
		Description:      "",
		Steps:            []ScenarioStep{{ID: "s1", Name: "Recon", Action: "noop"}},
		RequiresApproval: true,
	}
}

func TestManagerApprovalFlow(t *testing.T) {
	ctx := context.Background()
	mgr := newTestManager(t)

	created, err := mgr.Create(ctx, sampleScenario())
	require.NoError(t, err)
	require.Equal(t, StatusDraft.String(), created.Status)
	require.Len(t, created.ApprovalRecords, 2)

	published, err := mgr.Publish(ctx, created.ID, "author")
	require.NoError(t, err)
	require.Equal(t, StatusPending.String(), published.Status)
	require.Equal(t, 2, len(published.ApprovalRecords))

	first, err := mgr.UpdateApproval(ctx, published.ID, "", "secops-user", "approve", "ok")
	require.NoError(t, err)
	require.Equal(t, StatusPending.String(), first.Status)
	require.Equal(t, ScenarioApprovalApproved, first.ApprovalRecords[0].Status)
	require.Equal(t, ScenarioApprovalPending, first.ApprovalRecords[1].Status)

	final, err := mgr.UpdateApproval(ctx, published.ID, "", "ciso-user", "approve", "looks good")
	require.NoError(t, err)
	require.Equal(t, StatusApproved.String(), final.Status)
	require.Equal(t, ScenarioApprovalApproved, final.ApprovalRecords[1].Status)
	require.Equal(t, "ciso-user", final.ApprovalRecords[1].Actor)
	require.NotNil(t, final.ApprovalRecords[1].UpdatedAt)
}

func TestManagerRejectResetsFollowingApprovals(t *testing.T) {
	ctx := context.Background()
	policy := []ApprovalRule{
		{Role: "secops"},
		{Role: "security"},
		{Role: "ciso"},
	}
	mgr := newTestManagerWithPolicy(t, policy)

	created, err := mgr.Create(ctx, sampleScenario())
	require.NoError(t, err)
	_, err = mgr.Publish(ctx, created.ID, "author")
	require.NoError(t, err)

	_, err = mgr.UpdateApproval(ctx, created.ID, "secops", "secops-user", "approve", "")
	require.NoError(t, err)

	_, err = mgr.UpdateApproval(ctx, created.ID, "security", "security-user", "approve", "")
	require.NoError(t, err)

	approved, err := mgr.UpdateApproval(ctx, created.ID, "ciso", "ciso-user", "approve", "")
	require.NoError(t, err)
	require.Equal(t, StatusApproved.String(), approved.Status)

	rejected, err := mgr.UpdateApproval(ctx, created.ID, "security", "director", "reject", "need more controls")
	require.NoError(t, err)
	require.Equal(t, StatusPending.String(), rejected.Status)
	require.Equal(t, ScenarioApprovalRejected, rejected.ApprovalRecords[1].Status)
	require.Equal(t, "director", rejected.ApprovalRecords[1].Actor)
	require.NotNil(t, rejected.ApprovalRecords[1].UpdatedAt)
	require.Equal(t, ScenarioApprovalPending, rejected.ApprovalRecords[2].Status)
	require.Empty(t, rejected.ApprovalRecords[2].Actor)
	require.Nil(t, rejected.ApprovalRecords[2].UpdatedAt)
}

func TestManagerUpdateApprovalRequiresSequentialOrder(t *testing.T) {
	ctx := context.Background()
	mgr := newTestManager(t)

	created, err := mgr.Create(ctx, sampleScenario())
	require.NoError(t, err)
	_, err = mgr.Publish(ctx, created.ID, "author")
	require.NoError(t, err)

	_, err = mgr.UpdateApproval(ctx, created.ID, "ciso", "ciso-user", "approve", "")
	require.Error(t, err)
	require.Contains(t, err.Error(), "previous approval")

	current, err := mgr.Get(ctx, created.ID)
	require.NoError(t, err)
	require.Equal(t, ScenarioApprovalPending, current.ApprovalRecords[0].Status)
	require.Equal(t, ScenarioApprovalPending, current.ApprovalRecords[1].Status)
}
