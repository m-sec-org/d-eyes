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

func TestReportSummary(t *testing.T) {
	gin.SetMode(gin.TestMode)
	st := store.NewInMemoryStore()
	now := time.Now().UTC()
	require.NoError(t, st.InsertTaskResult(context.Background(), &model.TaskResult{
		TaskType:    model.TaskType("bas"),
		TaskID:      uuid.New(),
		RunID:       uuid.New(),
		Status:      model.TaskStatusSucceeded,
		CompletedAt: now,
		Metadata:    map[string]string{"scenario_id": "initial-access"},
	}))
	require.NoError(t, st.InsertTaskResult(context.Background(), &model.TaskResult{
		TaskType:    model.TaskType("baseline"),
		TaskID:      uuid.New(),
		RunID:       uuid.New(),
		Status:      model.TaskStatusFailed,
		CompletedAt: now.Add(-time.Minute),
		Metadata:    map[string]string{"scope": "os"},
	}))

	router := gin.New()
	handler := &v1.ReportHandler{Store: st}
	group := router.Group("/")
	handler.RegisterRoutes(group)

	req := httptest.NewRequest(http.MethodGet, "/reports/summary?limit=10", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	require.Equal(t, http.StatusOK, w.Code)

	var resp struct {
		Items  []map[string]any `json:"items"`
		Status map[string]int   `json:"status"`
	}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	require.Len(t, resp.Items, 2)
	require.Equal(t, 1, resp.Status["succeeded"])
	require.Equal(t, 1, resp.Status["failed"])
}

func TestReportSummaryTrends(t *testing.T) {
	gin.SetMode(gin.TestMode)
	st := store.NewInMemoryStore()
	now := time.Now().UTC()
	require.NoError(t, st.InsertTaskResult(context.Background(), &model.TaskResult{
		TaskType:    model.TaskType("bas"),
		TaskID:      uuid.New(),
		RunID:       uuid.New(),
		Status:      model.TaskStatusSucceeded,
		CompletedAt: now,
	}))
	require.NoError(t, st.InsertTaskResult(context.Background(), &model.TaskResult{
		TaskType:    model.TaskType("bas"),
		TaskID:      uuid.New(),
		RunID:       uuid.New(),
		Status:      model.TaskStatusSucceeded,
		CompletedAt: now.Add(-25 * time.Hour),
	}))
	require.NoError(t, st.InsertTaskResult(context.Background(), &model.TaskResult{
		TaskType:    model.TaskType("respond"),
		TaskID:      uuid.New(),
		RunID:       uuid.New(),
		Status:      model.TaskStatusRunning,
		CompletedAt: now.Add(-time.Hour),
	}))
	require.NoError(t, st.InsertTaskResult(context.Background(), &model.TaskResult{
		TaskType:    model.TaskType("baseline"),
		TaskID:      uuid.New(),
		RunID:       uuid.New(),
		Status:      model.TaskStatusFailed,
		CompletedAt: now.Add(-26 * time.Hour),
	}))

	router := gin.New()
	handler := &v1.ReportHandler{Store: st}
	group := router.Group("/")
	handler.RegisterRoutes(group)

	req := httptest.NewRequest(http.MethodGet, "/reports/summary?limit=10&window_hours=24", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	require.Equal(t, http.StatusOK, w.Code)

	var resp struct {
		Trends struct {
			Period string `json:"period"`
			Totals map[string]struct {
				Delta float64 `json:"delta"`
				Trend string  `json:"trend"`
			} `json:"totals"`
			Status map[string]struct {
				Delta float64 `json:"delta"`
				Trend string  `json:"trend"`
			} `json:"status"`
		} `json:"trends"`
	}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	require.Equal(t, "较前 24 小时", resp.Trends.Period)
	require.InDelta(t, 0, resp.Trends.Totals["bas"].Delta, 0.001)
	require.Equal(t, "flat", resp.Trends.Totals["bas"].Trend)
	require.InDelta(t, 100, resp.Trends.Totals["respond"].Delta, 0.001)
	require.Equal(t, "up", resp.Trends.Totals["respond"].Trend)
	require.Equal(t, "down", resp.Trends.Status["failed"].Trend)
}

func TestReportExportHTML(t *testing.T) {
	gin.SetMode(gin.TestMode)
	st := store.NewInMemoryStore()
	now := time.Now().UTC()
	require.NoError(t, st.InsertTaskResult(context.Background(), &model.TaskResult{
		TaskType:     model.TaskType("inventory"),
		TaskID:       uuid.New(),
		Status:       model.TaskStatusSucceeded,
		CompletedAt:  now,
		ScenarioName: "scan",
	}))

	router := gin.New()
	handler := &v1.ReportHandler{Store: st}
	group := router.Group("/")
	handler.RegisterRoutes(group)

	req := httptest.NewRequest(http.MethodGet, "/reports/export?format=html", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	require.Equal(t, http.StatusOK, w.Code)
	require.Contains(t, w.Body.String(), "<html>")
}
