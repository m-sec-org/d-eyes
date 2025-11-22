package v1_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	v1 "github.com/m-sec-org/d-eyes/server/internal/api/v1"
	"github.com/m-sec-org/d-eyes/server/internal/model"
	"github.com/m-sec-org/d-eyes/server/internal/store"
)

func TestThreatIntelListJobs(t *testing.T) {
	router, st := setupThreatIntelRouter(t)
	ctx := context.Background()

	sampleID := uuid.New()
	taskRunID := uuid.New()
	agentID := uuid.New()
	require.NoError(t, st.CreateThreatIntelSample(ctx, &model.ThreatIntelSample{
		ID:          sampleID,
		Hash:        "deadbeef",
		Filename:    "payload.bin",
		Size:        1024,
		Status:      model.ThreatIntelSampleStatusPending,
		ArtifactIDs: []uuid.UUID{uuid.New()},
		TaskRunID:   taskRunID,
		AgentID:     agentID,
		Metadata:    map[string]string{"source": "unit-test"},
	}))

	jobOlder := &model.ThreatIntelJob{
		ID:          uuid.New(),
		SampleID:    sampleID,
		Indicator:   "deadbeef",
		Kind:        "sample",
		Source:      model.ThreatIntelSourceMetaDefender,
		Status:      model.ThreatIntelJobStatusPending,
		TaskRunID:   taskRunID,
		AgentID:     agentID,
		ArtifactIDs: []uuid.UUID{uuid.New()},
		Metadata:    map[string]string{"priority": "low"},
		NextRunAt:   time.Now().Add(5 * time.Minute),
	}
	require.NoError(t, st.InsertThreatIntelJob(ctx, jobOlder))

	jobNewer := &model.ThreatIntelJob{
		ID:          uuid.New(),
		SampleID:    sampleID,
		Indicator:   "deadbeef",
		Kind:        "sample",
		Source:      model.ThreatIntelSourceOpenTIP,
		Status:      model.ThreatIntelJobStatusRunning,
		TaskRunID:   taskRunID,
		AgentID:     agentID,
		ArtifactIDs: []uuid.UUID{uuid.New(), uuid.New()},
		Metadata:    map[string]string{"priority": "high"},
	}
	require.NoError(t, st.InsertThreatIntelJob(ctx, jobNewer))

	req := httptest.NewRequest(http.MethodGet, "/api/v1/threat-intel/jobs?limit=1", nil)
	resp := httptest.NewRecorder()
	router.ServeHTTP(resp, req)
	require.Equal(t, http.StatusOK, resp.Code)

	var body struct {
		Jobs []struct {
			ID          string     `json:"id"`
			Source      string     `json:"source"`
			Status      string     `json:"status"`
			ArtifactIDs []string   `json:"artifact_ids"`
			NextRunAt   *time.Time `json:"next_run_at"`
		} `json:"jobs"`
	}
	require.NoError(t, json.Unmarshal(resp.Body.Bytes(), &body))
	require.Len(t, body.Jobs, 1)
	require.Equal(t, jobNewer.ID.String(), body.Jobs[0].ID)
	require.Equal(t, string(jobNewer.Source), body.Jobs[0].Source)
	require.Equal(t, jobNewer.Status, body.Jobs[0].Status)
	require.Len(t, body.Jobs[0].ArtifactIDs, len(jobNewer.ArtifactIDs))
	require.Nil(t, body.Jobs[0].NextRunAt)
}

func setupThreatIntelRouter(t *testing.T) (*gin.Engine, store.Store) {
	t.Helper()
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.Use(gin.Recovery())
	st := store.NewInMemoryStore()
	handler := &v1.ThreatIntelHandler{Store: st}
	apiGroup := router.Group("/api/v1")
	handler.RegisterRoutes(apiGroup)
	return router, st
}
