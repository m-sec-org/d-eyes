package threatintel_test

import (
	"context"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	"github.com/m-sec-org/d-eyes/server/internal/config"
	"github.com/m-sec-org/d-eyes/server/internal/store"
	"github.com/m-sec-org/d-eyes/server/internal/threatintel"
)

func TestSubmitSampleStoresMetadata(t *testing.T) {
	ctx := context.Background()
	st := store.NewInMemoryStore()
	cfg := config.ThreatIntelConfig{
		Enabled:            true,
		WorkerConcurrency:  1,
		OpenTIPAPIKey:      "key",
		MetaDefenderAPIKey: "key",
	}
	orch := threatintel.New(st, cfg, nil, nil, nil)
	require.NotNil(t, orch)
	orch.Start(ctx)
	defer orch.Stop()

	taskRun := uuid.New()
	agentID := uuid.New()
	meta := map[string]string{"threatintel.artifact_encryption": "aes256-gcm"}
	sampleID, err := orch.SubmitSample(ctx, threatintel.SampleSubmission{
		ArtifactIDs: []uuid.UUID{uuid.New()},
		Hash:        "abc",
		Filename:    "sample.bin",
		Size:        42,
		TaskRunID:   taskRun,
		AgentID:     agentID,
		Metadata:    meta,
	})
	require.NoError(t, err)
	require.NotEqual(t, uuid.Nil, sampleID)

	stored, err := st.GetThreatIntelSample(ctx, sampleID)
	require.NoError(t, err)
	require.Equal(t, "aes256-gcm", stored.Metadata["threatintel.artifact_encryption"])
}
