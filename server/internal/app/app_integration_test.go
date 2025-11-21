package app_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	"github.com/m-sec-org/d-eyes/server/internal/api"
	v1 "github.com/m-sec-org/d-eyes/server/internal/api/v1"
	"github.com/m-sec-org/d-eyes/server/internal/config"
	"github.com/m-sec-org/d-eyes/server/internal/model"
	"github.com/m-sec-org/d-eyes/server/internal/queue/memory"
	"github.com/m-sec-org/d-eyes/server/internal/scheduler"
	"github.com/m-sec-org/d-eyes/server/internal/store"
)

func TestIntegration_ReportEndpoints(t *testing.T) {
	ctx := context.Background()
	st := store.NewInMemoryStore()
	queue := memory.New()
	cfg := config.Config{
		Security: config.SecurityConfig{APIKeys: []string{"changeme"}},
		Scheduler: config.SchedulerConfig{
			LeaseTTL:             2 * time.Minute,
			MaxRetries:           3,
			HeartbeatTimeout:     30 * time.Second,
			QueueCapacity:        128,
			LeasePollInterval:    time.Millisecond,
			ResultRetention:      time.Hour,
			MaxAgentConcurrency:  2,
			GlobalMaxConcurrency: 0,
		},
	}
	sched := scheduler.New(st, queue, cfg.Scheduler)
	handler := &v1.TaskHandler{Store: st, Sched: sched}
	router := api.NewRouter(cfg, handler, &v1.TemplateHandler{}, &v1.ReportHandler{Store: st}, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil)

	type testCase struct {
		TaskType string
		Payload  map[string]any
		Metadata map[string]string
		Exec     model.ExecutionResult
		Endpoint string
		Assert   func(t *testing.T, body []byte)
	}

	cases := []testCase{
		{
			TaskType: "respond",
			Payload:  map[string]any{"payload": map[string]any{"flags": map[string]any{"targets": "/tmp"}}},
			Metadata: map[string]string{"required_capabilities": "respond"},
			Exec: model.ExecutionResult{
				Status: "succeeded",
				Summary: model.ExecutionSummary{
					Command:         "respond",
					Status:          "完成",
					DurationSeconds: 1.2,
					Risks:           map[string]int{"low": 2},
					Outputs: []model.OutputRecord{
						{Path: "/tmp/respond.json", Label: "主机概要"},
					},
				},
				Metadata: map[string]string{"module": "respond"},
			},
			Endpoint: "/api/v1/tasks/%s/respond/report",
			Assert: func(t *testing.T, body []byte) {
				var resp struct {
					TaskType string                `json:"task_type"`
					Result   model.ExecutionResult `json:"result"`
				}
				require.NoError(t, json.Unmarshal(body, &resp))
				require.Equal(t, "respond", resp.TaskType)
				require.Equal(t, map[string]int{"low": 2}, resp.Result.Summary.Risks)
			},
		},
		{
			TaskType: "baseline",
			Payload:  map[string]any{"payload": map[string]any{"flags": map[string]any{"scope": "os"}}},
			Metadata: map[string]string{"required_capabilities": "baseline"},
			Exec: model.ExecutionResult{
				Status: "succeeded",
				Summary: model.ExecutionSummary{
					Command:         "baseline",
					Status:          "完成",
					DurationSeconds: 2.4,
					Risks:           map[string]int{"high": 1},
					Notes:           []string{"弱口令策略未启用"},
					Outputs: []model.OutputRecord{
						{Path: "/tmp/baseline.json", Label: "基线检查"},
					},
				},
				Metadata: map[string]string{"scope": "os"},
			},
			Endpoint: "/api/v1/tasks/%s/baseline/report",
			Assert: func(t *testing.T, body []byte) {
				var resp struct {
					TaskType string         `json:"task_type"`
					Severity map[string]int `json:"severity"`
				}
				require.NoError(t, json.Unmarshal(body, &resp))
				require.Equal(t, "baseline", resp.TaskType)
				require.Equal(t, map[string]int{"high": 1}, resp.Severity)
			},
		},
		{
			TaskType: "inventory",
			Payload:  map[string]any{"payload": map[string]any{"flags": map[string]any{"targets": "10.0.0.1"}}},
			Metadata: map[string]string{"required_capabilities": "inventory"},
			Exec: model.ExecutionResult{
				Status: "succeeded",
				Summary: model.ExecutionSummary{
					Command:         "inventory",
					Status:          "完成",
					DurationSeconds: 3.6,
					Risks:           map[string]int{"medium": 2},
					Outputs: []model.OutputRecord{
						{Path: "/tmp/inventory.json", Label: "资产扫描汇总"},
					},
				},
				Metadata: map[string]string{
					"total_hosts": "3",
					"targets":     "10.0.0.1",
				},
			},
			Endpoint: "/api/v1/tasks/%s/inventory/report",
			Assert: func(t *testing.T, body []byte) {
				var resp struct {
					TaskType string         `json:"task_type"`
					Totals   map[string]int `json:"totals"`
				}
				require.NoError(t, json.Unmarshal(body, &resp))
				require.Equal(t, "inventory", resp.TaskType)
				require.Equal(t, map[string]int{"hosts": 3}, resp.Totals)
			},
		},
		{
			TaskType: "supplychain",
			Payload:  map[string]any{"payload": map[string]any{"flags": map[string]any{"path": "/repo", "mode": "generate"}}},
			Metadata: map[string]string{"required_capabilities": "supplychain"},
			Exec: model.ExecutionResult{
				Status: "succeeded",
				Summary: model.ExecutionSummary{
					Command:         "supplychain",
					Status:          "完成",
					DurationSeconds: 4.5,
					Risks:           map[string]int{"low": 5},
					Outputs: []model.OutputRecord{
						{Path: "/tmp/sbom.json", Label: "供应链报告"},
					},
				},
				Metadata: map[string]string{
					"mode":            "generate",
					"component_count": "5",
					"sources":         "package.json",
				},
			},
			Endpoint: "/api/v1/tasks/%s/supplychain/report",
			Assert: func(t *testing.T, body []byte) {
				var resp struct {
					TaskType       string `json:"task_type"`
					ComponentCount int    `json:"component_count"`
				}
				require.NoError(t, json.Unmarshal(body, &resp))
				require.Equal(t, "supplychain", resp.TaskType)
				require.Equal(t, 5, resp.ComponentCount)
			},
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.TaskType, func(t *testing.T) {
			payload := map[string]any{
				"type":       tc.TaskType,
				"profile":    tc.Exec.Metadata["mode"],
				"priority":   1,
				"payload":    tc.Payload["payload"],
				"metadata":   tc.Metadata,
				"created_by": "tester",
			}
			if payload["profile"] == "" {
				payload["profile"] = "default"
			}
			raw, _ := json.Marshal(payload)
			req := httptest.NewRequest(http.MethodPost, "/api/v1/tasks", bytes.NewReader(raw))
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("X-API-Key", "changeme")
			resp := performRequest(router, req)
			require.Equal(t, http.StatusCreated, resp.Code)

			var created map[string]string
			require.NoError(t, json.Unmarshal(resp.Body.Bytes(), &created))
			taskID := uuid.MustParse(created["id"])

			agent := &model.Agent{
				ID:            uuid.New(),
				Name:          "agent-" + tc.TaskType,
				Capabilities:  []string{tc.TaskType},
				Status:        model.AgentStatusOnline,
				LastHeartbeat: time.Now(),
			}
			require.NoError(t, st.UpsertAgent(ctx, agent))
			require.NoError(t, sched.PrimeFromStore(ctx))

			leasedTask, run, err := sched.LeaseTask(ctx, agent)
			require.NoError(t, err)
			require.Equal(t, taskID, leasedTask.ID)
			require.NoError(t, sched.MarkRunStarted(ctx, run.LeaseID))

			summaryBytes, err := json.Marshal(tc.Exec)
			require.NoError(t, err)

			runStored, err := st.GetTaskRunByLease(ctx, run.LeaseID)
			require.NoError(t, err)
			require.NoError(t, sched.CompleteTask(ctx, runStored, model.TaskStatusSucceeded, summaryBytes, "", tc.Exec.Metadata, 0, "", nil))

			reportReq := httptest.NewRequest(http.MethodGet, fmt.Sprintf(tc.Endpoint, taskID.String()), nil)
			reportReq.Header.Set("X-API-Key", "changeme")
			reportResp := performRequest(router, reportReq)
			require.Equal(t, http.StatusOK, reportResp.Code)

			tc.Assert(t, reportResp.Body.Bytes())
		})
	}
}

func performRequest(handler http.Handler, req *http.Request) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	return rec
}
