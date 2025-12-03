package v1_test

import (
	"context"
	"encoding/json"
	"fmt"
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
		Data []struct {
			ID          string     `json:"id"`
			Source      string     `json:"source"`
			Status      string     `json:"status"`
			ArtifactIDs []string   `json:"artifact_ids"`
			ErrorCode   string     `json:"error_code"`
			NextRunAt   *time.Time `json:"next_run_at"`
		} `json:"data"`
		PageSize int            `json:"page_size"`
		Summary  map[string]any `json:"summary"`
	}
	require.NoError(t, json.Unmarshal(resp.Body.Bytes(), &body))
	require.Len(t, body.Data, 1)
	require.Equal(t, jobNewer.ID.String(), body.Data[0].ID)
	require.Equal(t, string(jobNewer.Source), body.Data[0].Source)
	require.Equal(t, jobNewer.Status, body.Data[0].Status)
	require.Len(t, body.Data[0].ArtifactIDs, len(jobNewer.ArtifactIDs))
	require.Equal(t, "", body.Data[0].ErrorCode)
	require.Nil(t, body.Data[0].NextRunAt)
}

func TestThreatIntelSampleDetail(t *testing.T) {
	router, st := setupThreatIntelRouter(t)
	ctx := context.Background()

	sampleID := uuid.New()
	taskRunID := uuid.New()
	agentID := uuid.New()
	artifactID := uuid.New()
	require.NoError(t, st.SaveArtifacts(ctx, []model.Artifact{
		{
			ID:        artifactID,
			TaskRunID: taskRunID,
			Name:      "payload.bin",
			MIMEType:  "application/octet-stream",
		},
	}))
	require.NoError(t, st.CreateThreatIntelSample(ctx, &model.ThreatIntelSample{
		ID:              sampleID,
		Indicator:       "sha256:deadbeef",
		Hash:            "deadbeef",
		Filename:        "payload.bin",
		Size:            2048,
		Status:          model.ThreatIntelSampleStatusScanning,
		ArtifactIDs:     []uuid.UUID{artifactID},
		TaskRunID:       taskRunID,
		AgentID:         agentID,
		Source:          "opentip",
		Classification:  "malicious",
		ArtifactDetails: []model.ArtifactDetail{{ID: artifactID, MIMEType: "application/octet-stream", SHA256: "deadbeef"}},
		Metadata:        map[string]string{"classification": "malicious"},
		JobStatuses:     map[string]string{"opentip": "running"},
		LastErrorCode:   "TI_PROVIDER_TIMEOUT",
		LastError:       "timeout",
	}))

	job := &model.ThreatIntelJob{
		ID:          uuid.New(),
		SampleID:    sampleID,
		Indicator:   "sha256:deadbeef",
		Kind:        "sample",
		Source:      model.ThreatIntelSourceOpenTIP,
		Status:      model.ThreatIntelJobStatusFailed,
		TaskRunID:   taskRunID,
		AgentID:     agentID,
		ArtifactIDs: []uuid.UUID{artifactID},
		Attempt:     2,
		ErrorMsg:    "provider timeout",
		ErrorCode:   "TI_PROVIDER_TIMEOUT",
		Metadata:    map[string]string{"error_code": "TI_PROVIDER_TIMEOUT"},
	}
	require.NoError(t, st.InsertThreatIntelJob(ctx, job))

	req := httptest.NewRequest(http.MethodGet, fmt.Sprintf("/api/v1/threat-intel/samples/%s", sampleID), nil)
	resp := httptest.NewRecorder()
	router.ServeHTTP(resp, req)
	require.Equal(t, http.StatusOK, resp.Code)

	var body struct {
		Indicator      string                   `json:"indicator"`
		ArtifactIDs    []string                 `json:"artifact_ids"`
		ArtifactDetail []map[string]interface{} `json:"artifact_details"`
		JobStatuses    map[string]string        `json:"job_statuses"`
		Jobs           []map[string]interface{} `json:"jobs"`
	}
	require.NoError(t, json.Unmarshal(resp.Body.Bytes(), &body))
	require.Equal(t, "sha256:deadbeef", body.Indicator)
	require.Equal(t, 1, len(body.ArtifactDetail))
	require.Contains(t, body.JobStatuses, "opentip")
	require.Equal(t, "failed", body.JobStatuses["opentip"])
	require.NotEmpty(t, body.Jobs)
	require.Equal(t, "TI_PROVIDER_TIMEOUT", body.Jobs[0]["error_code"])
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
