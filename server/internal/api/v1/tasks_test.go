package v1_test

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	"github.com/m-sec-org/d-eyes/server/internal/api"
	v1 "github.com/m-sec-org/d-eyes/server/internal/api/v1"
	"github.com/m-sec-org/d-eyes/server/internal/basscenarios"
	"github.com/m-sec-org/d-eyes/server/internal/config"
	"github.com/m-sec-org/d-eyes/server/internal/model"
	"github.com/m-sec-org/d-eyes/server/internal/queue/memory"
	"github.com/m-sec-org/d-eyes/server/internal/scheduler"
	"github.com/m-sec-org/d-eyes/server/internal/store"
	"github.com/m-sec-org/d-eyes/server/internal/taskcatalog"
)

func setupTestRouter(t *testing.T) (*gin.Engine, store.Store, *scheduler.Scheduler) {
	t.Helper()
	gin.SetMode(gin.TestMode)

	st := store.NewInMemoryStore()
	queue := memory.New()
	cfg := config.Config{
		Security: config.SecurityConfig{
			APIKeys: []string{"changeme"},
		},
		Scheduler: config.SchedulerConfig{
			LeaseTTL:          2 * time.Minute,
			MaxRetries:        3,
			HeartbeatTimeout:  30 * time.Second,
			QueueCapacity:     128,
			LeasePollInterval: time.Millisecond,
		},
	}
	sched := scheduler.New(st, queue, cfg.Scheduler)
	handler := &v1.TaskHandler{Store: st, Sched: sched}
	reportHandler := &v1.ReportHandler{Store: st}
	router := api.NewRouter(
		cfg,
		handler,
		nil,
		&v1.TemplateHandler{},
		reportHandler,
		nil, // catalog
		nil, // plugin
		nil, // bas
		nil, // agent
		nil, // audit
		nil, // rbac
		nil, // artifact
		nil, // threat intel
		nil, // behavior
		nil, // compliance
		nil, // playbook
		nil, // cert
		nil, // security
		nil, // ops
		nil, // queue handler
		nil, // collector handler
		nil, // events handler
		nil, // mfa store
		nil, // metrics handler
		nil, // task stream
		nil, // queue stream
		nil, // detection stream
		nil, // threat stream
		nil, // anomaly stream
	)
	return router, st, sched
}

func performRequest(r http.Handler, req *http.Request) *httptest.ResponseRecorder {
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	return w
}

func newTestCatalog(t *testing.T) *taskcatalog.Manager {
	t.Helper()
	log := slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelError}))
	catalog, err := taskcatalog.NewManager(taskcatalog.Config{}, log)
	require.NoError(t, err)
	return catalog
}

func newTestBASManager(t *testing.T) *basscenarios.Manager {
	t.Helper()
	log := slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelError}))
	basStore := store.NewInMemoryStore()
	mgr, err := basscenarios.NewManager(basscenarios.Config{
		Store: basStore,
		DefaultApprovalPolicy: []basscenarios.ApprovalRule{
			{Role: "secops", TimeoutSeconds: 3600},
		},
	}, log)
	require.NoError(t, err)
	return mgr
}

func TestTaskLifecycle(t *testing.T) {
	router, st, sched := setupTestRouter(t)
	ctx := context.Background()

	payload := map[string]any{"targets": []string{"/tmp"}}
	body, _ := json.Marshal(map[string]any{
		"type":       "respond",
		"profile":    "quick",
		"priority":   2,
		"payload":    payload,
		"metadata":   map[string]string{"required_capabilities": "respond"},
		"created_by": "tester",
	})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/tasks", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-API-Key", "changeme")
	resp := performRequest(router, req)
	require.Equal(t, http.StatusCreated, resp.Code)

	var created map[string]string
	require.NoError(t, json.Unmarshal(resp.Body.Bytes(), &created))
	taskID := uuid.MustParse(created["id"])

	task, err := st.GetTask(ctx, taskID)
	require.NoError(t, err)
	require.Equal(t, model.TaskStatusPending, task.Status)

	runAgent := &model.Agent{
		ID:            uuid.New(),
		Name:          "agent-1",
		Capabilities:  []string{"respond"},
		Status:        model.AgentStatusOnline,
		LastHeartbeat: time.Now(),
	}
	require.NoError(t, st.UpsertAgent(ctx, runAgent))
	require.NoError(t, sched.PrimeFromStore(ctx))

	leasedTask, run, err := sched.LeaseTask(ctx, runAgent)
	require.NoError(t, err)
	require.Equal(t, taskID, leasedTask.ID)
	require.NoError(t, sched.MarkRunStarted(ctx, run.LeaseID))
	runStored, err := st.GetTaskRunByLease(ctx, run.LeaseID)
	require.NoError(t, err)
	require.NoError(t, sched.CompleteTask(ctx, runStored, model.TaskStatusSucceeded, []byte(`{"ok":true}`), "", map[string]string{"module": "respond"}, 0, "", nil))

	getReq := httptest.NewRequest(http.MethodGet, "/api/v1/tasks/"+taskID.String(), nil)
	getReq.Header.Set("X-API-Key", "changeme")
	getResp := performRequest(router, getReq)
	require.Equal(t, http.StatusOK, getResp.Code)

	var getBody v1TaskResponse
	require.NoError(t, json.Unmarshal(getResp.Body.Bytes(), &getBody))
	require.Equal(t, "succeeded", getBody.Status)
	require.NotNil(t, getBody.LastRun)
	require.Equal(t, "succeeded", getBody.LastRun.Status)

	listReq := httptest.NewRequest(http.MethodGet, "/api/v1/tasks?status=succeeded", nil)
	listReq.Header.Set("X-API-Key", "changeme")
	listResp := performRequest(router, listReq)
	require.Equal(t, http.StatusOK, listResp.Code)

	var listBody struct {
		Data []v1TaskResponse `json:"data"`
	}
	require.NoError(t, json.Unmarshal(listResp.Body.Bytes(), &listBody))
	require.Len(t, listBody.Data, 1)
	require.Equal(t, "succeeded", listBody.Data[0].Status)

	retryReq := httptest.NewRequest(http.MethodPost, "/api/v1/tasks/"+taskID.String()+"/retry", nil)
	retryReq.Header.Set("X-API-Key", "changeme")
	retryResp := performRequest(router, retryReq)
	require.Equal(t, http.StatusAccepted, retryResp.Code)

	var retryBody v1TaskResponse
	require.NoError(t, json.Unmarshal(retryResp.Body.Bytes(), &retryBody))
	require.Equal(t, 1, retryBody.RetryCount)
	require.Equal(t, "pending", retryBody.Status)
}

func TestTaskListEnvelope(t *testing.T) {
	router, _, _ := setupTestRouter(t)
	create := func(payload map[string]any) {
		body, _ := json.Marshal(payload)
		req := httptest.NewRequest(http.MethodPost, "/api/v1/tasks", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-API-Key", "changeme")
		resp := performRequest(router, req)
		require.Equal(t, http.StatusCreated, resp.Code)
	}
	create(map[string]any{
		"type":       "respond",
		"profile":    "quick",
		"priority":   2,
		"payload":    map[string]any{"targets": []string{"/tmp"}},
		"metadata":   map[string]string{"required_capabilities": "respond"},
		"created_by": "tester",
	})
	create(map[string]any{
		"type":       "baseline",
		"profile":    "scan",
		"priority":   3,
		"payload":    map[string]any{"targets": []string{"/var"}},
		"metadata":   map[string]string{"required_capabilities": "baseline"},
		"created_by": "tester",
	})

	req := httptest.NewRequest(http.MethodGet, "/api/v1/tasks?status=pending&limit=1", nil)
	req.Header.Set("X-API-Key", "changeme")
	resp := performRequest(router, req)
	require.Equal(t, http.StatusOK, resp.Code)

	var body struct {
		Data     []v1TaskResponse `json:"data"`
		PageSize int              `json:"page_size"`
		Filters  struct {
			Status []string `json:"status"`
		} `json:"filters"`
		Summary struct {
			Total int `json:"total"`
		} `json:"summary"`
	}
	require.NoError(t, json.Unmarshal(resp.Body.Bytes(), &body))
	require.Equal(t, 1, body.PageSize)
	require.NotEmpty(t, body.Data)
	require.Contains(t, body.Filters.Status, "pending")
	require.GreaterOrEqual(t, body.Summary.Total, 1)
}

func TestTaskCreateValidatesProfilePayload(t *testing.T) {
	gin.SetMode(gin.TestMode)
	st := store.NewInMemoryStore()
	queue := memory.New()
	cfg := config.Config{
		Security: config.SecurityConfig{
			APIKeys: []string{"changeme"},
		},
		Scheduler: config.SchedulerConfig{
			LeaseTTL:          2 * time.Minute,
			MaxRetries:        1,
			HeartbeatTimeout:  30 * time.Second,
			QueueCapacity:     64,
			LeasePollInterval: time.Millisecond,
		},
	}
	sched := scheduler.New(st, queue, cfg.Scheduler)
	catalog := newTestCatalog(t)
	_, err := catalog.CreateTaskType(context.Background(), taskcatalog.TaskType{
		Name:        "respond",
		DisplayName: "Respond",
	})
	require.NoError(t, err)
	_, err = catalog.CreateTaskProfile(context.Background(), taskcatalog.TaskProfile{
		ID:          "respond_profile_v1",
		TaskType:    "respond",
		DisplayName: "Respond Quick",
		Version:     "1.0.0",
		Schema: taskcatalog.TaskProfileSchema{
			Parameters: []taskcatalog.ProfileParameter{
				{Key: "targets", Label: "Targets", Type: "string", Required: true},
			},
		},
	})
	require.NoError(t, err)

	handler := &v1.TaskHandler{Store: st, Sched: sched, Catalog: catalog}
	router := api.NewRouter(
		cfg,
		handler,
		nil,                   // task view handler
		&v1.TemplateHandler{}, // template handler
		&v1.ReportHandler{Store: st},
		nil, // catalog
		nil, // plugin
		nil, // bas scenario
		nil, // agent handler
		nil, // audit handler
		nil, // rbac handler
		nil, // artifact handler
		nil, // threat intel handler
		nil, // behavior handler
		nil, // compliance handler
		nil, // playbook handler
		nil, // cert handler
		nil, // security handler
		nil, // ops handler
		nil, // queue handler
		nil, // collector handler
		nil, // events handler
		nil, // mfa store
		nil, // metrics handler
		nil, // task stream
		nil, // queue stream
		nil, // detection stream
		nil, // threat stream
		nil, // anomaly stream
	)

	makeRequest := func(payload map[string]any) *httptest.ResponseRecorder {
		body, _ := json.Marshal(payload)
		req := httptest.NewRequest(http.MethodPost, "/api/v1/tasks", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-API-Key", "changeme")
		return performRequest(router, req)
	}

	t.Run("missing required parameter fails", func(t *testing.T) {
		resp := makeRequest(map[string]any{
			"type":     "respond",
			"profile":  "respond_profile_v1",
			"priority": 2,
			"payload":  map[string]any{},
		})
		require.Equal(t, http.StatusBadRequest, resp.Code)
	})

	t.Run("valid payload passes", func(t *testing.T) {
		resp := makeRequest(map[string]any{
			"type":     "respond",
			"profile":  "respond_profile_v1",
			"priority": 2,
			"payload": map[string]any{
				"targets": "/var/log",
			},
		})
		require.Equal(t, http.StatusCreated, resp.Code)
	})
}

func TestCreateBASTaskRequiresApprovedScenario(t *testing.T) {
	gin.SetMode(gin.TestMode)
	ctx := context.Background()
	st := store.NewInMemoryStore()
	queue := memory.New()
	cfg := config.Config{
		Security: config.SecurityConfig{
			APIKeys: []string{"changeme"},
		},
		Scheduler: config.SchedulerConfig{
			LeaseTTL:          2 * time.Minute,
			MaxRetries:        1,
			HeartbeatTimeout:  30 * time.Second,
			QueueCapacity:     64,
			LeasePollInterval: time.Millisecond,
		},
	}
	sched := scheduler.New(st, queue, cfg.Scheduler)
	basMgr := newTestBASManager(t)
	scenario, err := basMgr.Create(ctx, basscenarios.Scenario{
		Name: "Purple Team Drill",
		Steps: []basscenarios.ScenarioStep{
			{Name: "Recon", Action: "recon"},
		},
		RequiresApproval: true,
	})
	require.NoError(t, err)

	handler := &v1.TaskHandler{Store: st, Sched: sched, BASScenarios: basMgr}
	router := api.NewRouter(
		cfg,
		handler,
		nil,
		&v1.TemplateHandler{},
		&v1.ReportHandler{Store: st},
		nil, // catalog
		nil, // plugin
		&v1.BASScenarioHandler{Manager: basMgr},
		nil, // agent handler
		nil, // audit handler
		nil, // rbac handler
		nil, // artifact handler
		nil, // threat intel handler
		nil, // behavior handler
		nil, // compliance handler
		nil, // playbook handler
		nil, // cert handler
		nil, // security handler
		nil, // ops handler
		nil, // queue handler
		nil, // collector handler
		nil, // events handler
		nil, // mfa store
		nil, // metrics handler
		nil, // task stream
		nil, // queue stream
		nil, // detection stream
		nil, // threat stream
		nil, // anomaly stream
	)

	buildRequest := func() *http.Request {
		body, _ := json.Marshal(map[string]any{
			"type":     "bas",
			"profile":  "default",
			"priority": 5,
			"metadata": map[string]string{
				"scenario_id": scenario.ID.String(),
			},
		})
		req := httptest.NewRequest(http.MethodPost, "/api/v1/tasks", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-API-Key", "changeme")
		return req
	}

	resp := performRequest(router, buildRequest())
	require.Equal(t, http.StatusBadRequest, resp.Code)

	_, err = basMgr.Publish(ctx, scenario.ID, "secops")
	require.NoError(t, err)
	_, err = basMgr.Approve(ctx, scenario.ID, "secops", "ok")
	require.NoError(t, err)
	_, err = basMgr.SetStatus(ctx, scenario.ID, basscenarios.StatusActive)
	require.NoError(t, err)

	resp = performRequest(router, buildRequest())
	require.Equal(t, http.StatusCreated, resp.Code)
}

func TestTaskVisualsEndpoint(t *testing.T) {
	router, st, _ := setupTestRouter(t)
	ctx := context.Background()

	task := &model.Task{
		ID:        uuid.New(),
		Type:      "respond",
		Profile:   "quick",
		Priority:  3,
		Status:    model.TaskStatusSucceeded,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}
	require.NoError(t, st.CreateTask(ctx, task))

	execResult := model.ExecutionResult{
		Status: "succeeded",
		Summary: model.ExecutionSummary{
			Command:         "respond --profile quick",
			DurationSeconds: 10,
		},
		Metadata: map[string]string{
			"visual.network_graph": `{"nodes":[{"id":"host","label":"10.0.0.8","kind":"host"}],"edges":[]}`,
		},
		ReportedAt: time.Now(),
	}
	summaryBytes, err := json.Marshal(execResult)
	require.NoError(t, err)

	run := &model.TaskRun{
		ID:           uuid.New(),
		TaskID:       task.ID,
		TaskType:     task.Type,
		AgentID:      uuid.New(),
		LeaseID:      uuid.New(),
		LeaseExpires: time.Now().Add(time.Minute),
		Status:       model.TaskStatusSucceeded,
		Summary:      summaryBytes,
		Metadata: map[string]string{
			"visual.file_risk": `{"total_files": 5, "risk_counts":{"high":1}}`,
		},
	}
	require.NoError(t, st.CreateTaskRun(ctx, run))

	req := httptest.NewRequest(http.MethodGet, "/api/v1/tasks/"+task.ID.String()+"/visuals", nil)
	req.Header.Set("X-API-Key", "changeme")
	resp := performRequest(router, req)
	require.Equal(t, http.StatusOK, resp.Code)

	var payload struct {
		Items []map[string]any `json:"items"`
	}
	require.NoError(t, json.Unmarshal(resp.Body.Bytes(), &payload))
	require.GreaterOrEqual(t, len(payload.Items), 1)

	foundNetwork := false
	for _, item := range payload.Items {
		if item["visual_type"] == "network_graph" {
			foundNetwork = true
		}
	}
	require.True(t, foundNetwork, "expected network_graph visual payload")
}

type v1TaskResponse struct {
	ID         string           `json:"id"`
	Status     string           `json:"status"`
	LastRun    *v1TaskRunOutput `json:"last_run"`
	RetryCount int              `json:"retry_count"`
}

type v1TaskRunOutput struct {
	Status string `json:"status"`
}

func TestGetRespondReport(t *testing.T) {
	router, st, sched := setupTestRouter(t)
	ctx := context.Background()

	payload := map[string]any{"targets": []string{"/var"}}
	body, _ := json.Marshal(map[string]any{
		"type":       "respond",
		"profile":    "quick",
		"priority":   1,
		"payload":    payload,
		"metadata":   map[string]string{"required_capabilities": "respond"},
		"created_by": "tester",
	})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/tasks", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-API-Key", "changeme")
	resp := performRequest(router, req)
	require.Equal(t, http.StatusCreated, resp.Code)

	var created map[string]string
	require.NoError(t, json.Unmarshal(resp.Body.Bytes(), &created))
	taskID := uuid.MustParse(created["id"])

	task, err := st.GetTask(ctx, taskID)
	require.NoError(t, err)
	require.Equal(t, model.TaskType("respond"), task.Type)

	agent := &model.Agent{
		ID:            uuid.New(),
		Name:          "agent-respond",
		Capabilities:  []string{"respond"},
		Status:        model.AgentStatusOnline,
		LastHeartbeat: time.Now(),
	}
	require.NoError(t, st.UpsertAgent(ctx, agent))
	require.NoError(t, sched.PrimeFromStore(ctx))

	leasedTask, run, err := sched.LeaseTask(ctx, agent)
	require.NoError(t, err)
	require.Equal(t, taskID, leasedTask.ID)
	require.NoError(t, sched.MarkRunStarted(ctx, run.LeaseID))

	execResult := model.ExecutionResult{
		Status: "succeeded",
		Summary: model.ExecutionSummary{
			Command:         "respond",
			Status:          "完成",
			DurationSeconds: 2.5,
			Notes:           []string{"host scan success"},
			Risks:           map[string]int{"low": 1},
			Outputs: []model.OutputRecord{
				{Path: "/tmp/report.json", Label: "主机概要"},
			},
		},
		Artifacts: []model.OutputRecord{
			{Path: "/tmp/report.json", Label: "主机概要"},
		},
		Metadata: map[string]string{"module": "respond"},
	}
	summaryBytes, err := json.Marshal(execResult)
	require.NoError(t, err)

	runStored, err := st.GetTaskRunByLease(ctx, run.LeaseID)
	require.NoError(t, err)
	require.NoError(t, sched.CompleteTask(ctx, runStored, model.TaskStatusSucceeded, summaryBytes, "", map[string]string{"module": "respond"}, 0, "", nil))

	reportReq := httptest.NewRequest(http.MethodGet, "/api/v1/tasks/"+taskID.String()+"/respond/report", nil)
	reportReq.Header.Set("X-API-Key", "changeme")
	reportResp := performRequest(router, reportReq)
	require.Equal(t, http.StatusOK, reportResp.Code)

	var report struct {
		TaskID     string                `json:"task_id"`
		TaskType   string                `json:"task_type"`
		Profile    string                `json:"profile"`
		RunID      string                `json:"run_id"`
		TaskStatus string                `json:"task_status"`
		Result     model.ExecutionResult `json:"result"`
		RunMeta    map[string]string     `json:"run_metadata"`
		ExitCode   int32                 `json:"exit_code"`
		ErrorCode  string                `json:"error_code"`
		Completed  *time.Time            `json:"completed_at"`
	}
	require.NoError(t, json.Unmarshal(reportResp.Body.Bytes(), &report))
	require.Equal(t, taskID.String(), report.TaskID)
	require.Equal(t, "respond", report.TaskType)
	require.Equal(t, "quick", report.Profile)
	require.Equal(t, "succeeded", report.TaskStatus)
	require.Equal(t, "respond", report.Result.Summary.Command)
	require.Len(t, report.Result.Summary.Outputs, 1)
	require.Equal(t, "主机概要", report.Result.Summary.Outputs[0].Label)
	require.NotNil(t, report.Completed)
}

func TestGetBASReport(t *testing.T) {
	router, st, sched := setupTestRouter(t)
	ctx := context.Background()

	payload := map[string]any{"flags": map[string]any{"scenario-id": "initial-access"}}
	body, _ := json.Marshal(map[string]any{
		"type":       "bas",
		"profile":    "default",
		"priority":   3,
		"payload":    payload,
		"metadata":   map[string]string{"required_capabilities": "bas"},
		"created_by": "bas-tester",
	})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/tasks", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-API-Key", "changeme")
	resp := performRequest(router, req)
	require.Equal(t, http.StatusCreated, resp.Code)

	var created map[string]string
	require.NoError(t, json.Unmarshal(resp.Body.Bytes(), &created))
	taskID := uuid.MustParse(created["id"])

	task, err := st.GetTask(ctx, taskID)
	require.NoError(t, err)
	require.Equal(t, model.TaskType("bas"), task.Type)

	agent := &model.Agent{
		ID:            uuid.New(),
		Name:          "agent-bas",
		Capabilities:  []string{"bas"},
		Status:        model.AgentStatusOnline,
		LastHeartbeat: time.Now(),
	}
	require.NoError(t, st.UpsertAgent(ctx, agent))
	require.NoError(t, sched.PrimeFromStore(ctx))

	leasedTask, run, err := sched.LeaseTask(ctx, agent)
	require.NoError(t, err)
	require.Equal(t, taskID, leasedTask.ID)
	require.NoError(t, sched.MarkRunStarted(ctx, run.LeaseID))

	stepStart := time.Now().Add(-1 * time.Minute).UTC()
	stepEnd := time.Now().UTC()
	steps := []map[string]any{
		{
			"id":         "enumerate-environment",
			"name":       "枚举系统环境",
			"status":     "succeeded",
			"exit_code":  0,
			"sandbox":    false,
			"started_at": stepStart,
			"ended_at":   stepStart.Add(10 * time.Second),
			"message":    "completed",
		},
		{
			"id":         "exploit-attempt",
			"name":       "执行提权验证",
			"status":     "failed",
			"exit_code":  1,
			"sandbox":    true,
			"started_at": stepEnd.Add(-30 * time.Second),
			"ended_at":   stepEnd,
			"message":    "exit code 1",
		},
		{
			"id":         "cleanup-artifacts",
			"name":       "清理临时文件",
			"status":     "skipped",
			"exit_code":  0,
			"sandbox":    true,
			"started_at": stepEnd,
			"ended_at":   stepEnd,
			"message":    "skipped due to previous failure",
		},
	}
	stepJSON, err := json.Marshal(steps)
	require.NoError(t, err)

	execResult := model.ExecutionResult{
		Status: "failed",
		Summary: model.ExecutionSummary{
			Command:         "bas",
			Status:          "failed",
			DurationSeconds: 30,
			Notes:           []string{"执行提权验证: exit code 1"},
			Risks:           map[string]int{"critical": 1},
			Outputs: []model.OutputRecord{
				{Path: "/tmp/bas-report.json", Label: "BAS 场景报告"},
			},
			ErrorMessage: "BAS 场景 privilege-escalation 执行失败，失败步骤: exploit-attempt",
		},
		Artifacts: []model.OutputRecord{
			{Path: "/tmp/bas-report.json", Label: "BAS 场景报告"},
		},
		Metadata: map[string]string{
			"scenario_id":          "privilege-escalation",
			"scenario_name":        "提权验证与回滚模拟",
			"scenario_description": "模拟提权场景",
		},
	}
	meta := map[string]string{
		"scenario_id":      "privilege-escalation",
		"scenario_name":    "提权验证与回滚模拟",
		"scenario_tags":    "execution, privilege-escalation",
		"scenario_summary": string(stepJSON),
		"scenario_steps":   "3",
		"steps_success":    "1",
		"steps_failed":     "1",
		"steps_skipped":    "1",
		"failed_steps":     "exploit-attempt",
	}
	summaryBytes, err := json.Marshal(execResult)
	require.NoError(t, err)

	runStored, err := st.GetTaskRunByLease(ctx, run.LeaseID)
	require.NoError(t, err)
	require.NoError(t, sched.CompleteTask(ctx, runStored, model.TaskStatusFailed, summaryBytes, execResult.Summary.ErrorMessage, meta, 1, "bas.step_failed", nil))

	getReq := httptest.NewRequest(http.MethodGet, "/api/v1/tasks/"+taskID.String()+"/bas/report", nil)
	getReq.Header.Set("X-API-Key", "changeme")
	getResp := performRequest(router, getReq)
	require.Equal(t, http.StatusOK, getResp.Code)

	var report struct {
		TaskType   string `json:"task_type"`
		ScenarioID string `json:"scenario_id"`
		Steps      []struct {
			Status string `json:"status"`
		} `json:"steps"`
		FailedSteps []string `json:"failed_steps"`
		ErrorCode   string   `json:"error_code"`
		ExitCode    int32    `json:"exit_code"`
	}
	require.NoError(t, json.Unmarshal(getResp.Body.Bytes(), &report))
	require.Equal(t, "bas", report.TaskType)
	require.Equal(t, "privilege-escalation", report.ScenarioID)
	require.Len(t, report.Steps, 3)
	require.Equal(t, "failed", report.Steps[1].Status)
	require.Equal(t, []string{"exploit-attempt"}, report.FailedSteps)
	require.Equal(t, "bas.step_failed", report.ErrorCode)
	require.Equal(t, int32(1), report.ExitCode)
}

func TestGetBaselineReport(t *testing.T) {
	router, st, sched := setupTestRouter(t)
	ctx := context.Background()

	body, _ := json.Marshal(map[string]any{
		"type":       "baseline",
		"profile":    "os",
		"priority":   1,
		"payload":    map[string]any{"flags": map[string]any{"scope": "os"}},
		"metadata":   map[string]string{"required_capabilities": "baseline"},
		"created_by": "tester",
	})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/tasks", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-API-Key", "changeme")
	resp := performRequest(router, req)
	require.Equal(t, http.StatusCreated, resp.Code)

	var created map[string]string
	require.NoError(t, json.Unmarshal(resp.Body.Bytes(), &created))
	taskID := uuid.MustParse(created["id"])

	agent := &model.Agent{
		ID:            uuid.New(),
		Name:          "agent-baseline",
		Capabilities:  []string{"baseline"},
		Status:        model.AgentStatusOnline,
		LastHeartbeat: time.Now(),
	}
	require.NoError(t, st.UpsertAgent(ctx, agent))
	require.NoError(t, sched.PrimeFromStore(ctx))

	leasedTask, run, err := sched.LeaseTask(ctx, agent)
	require.NoError(t, err)
	require.Equal(t, taskID, leasedTask.ID)
	require.NoError(t, sched.MarkRunStarted(ctx, run.LeaseID))

	execResult := model.ExecutionResult{
		Status: "succeeded",
		Summary: model.ExecutionSummary{
			Command:         "baseline",
			Status:          "完成",
			DurationSeconds: 5.2,
			Risks:           map[string]int{"high": 1, "medium": 3},
			Notes:           []string{"弱口令策略未启用"},
			Outputs: []model.OutputRecord{
				{Path: "/tmp/baseline.json", Label: "基线检查"},
			},
		},
		Metadata: map[string]string{"scope": "os"},
	}
	summaryBytes, err := json.Marshal(execResult)
	require.NoError(t, err)

	runStored, err := st.GetTaskRunByLease(ctx, run.LeaseID)
	require.NoError(t, err)
	require.NoError(t, sched.CompleteTask(ctx, runStored, model.TaskStatusSucceeded, summaryBytes, "", map[string]string{"scope": "os"}, 0, "", nil))

	reportReq := httptest.NewRequest(http.MethodGet, "/api/v1/tasks/"+taskID.String()+"/baseline/report", nil)
	reportReq.Header.Set("X-API-Key", "changeme")
	reportResp := performRequest(router, reportReq)
	require.Equal(t, http.StatusOK, reportResp.Code)

	var report struct {
		TaskID     string                `json:"task_id"`
		Severity   map[string]int        `json:"severity"`
		Warnings   []string              `json:"warnings"`
		Result     model.ExecutionResult `json:"result"`
		Profile    string                `json:"profile"`
		TaskType   string                `json:"task_type"`
		TaskStatus string                `json:"task_status"`
	}
	require.NoError(t, json.Unmarshal(reportResp.Body.Bytes(), &report))
	require.Equal(t, taskID.String(), report.TaskID)
	require.Equal(t, "baseline", report.TaskType)
	require.Equal(t, "os", report.Profile)
	require.Equal(t, "succeeded", report.TaskStatus)
	require.Equal(t, map[string]int{"high": 1, "medium": 3}, report.Severity)
	require.Equal(t, []string{"弱口令策略未启用"}, report.Warnings)
	require.Len(t, report.Result.Summary.Outputs, 1)
	require.Equal(t, "基线检查", report.Result.Summary.Outputs[0].Label)
}

func TestGetInventoryReport(t *testing.T) {
	router, st, sched := setupTestRouter(t)
	ctx := context.Background()

	body, _ := json.Marshal(map[string]any{
		"type":       "inventory",
		"profile":    "deep",
		"priority":   1,
		"payload":    map[string]any{"flags": map[string]any{"targets": "10.0.0.1,10.0.0.2"}},
		"metadata":   map[string]string{"required_capabilities": "inventory"},
		"created_by": "tester",
	})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/tasks", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-API-Key", "changeme")
	resp := performRequest(router, req)
	require.Equal(t, http.StatusCreated, resp.Code)

	var created map[string]string
	require.NoError(t, json.Unmarshal(resp.Body.Bytes(), &created))
	taskID := uuid.MustParse(created["id"])

	agent := &model.Agent{
		ID:            uuid.New(),
		Name:          "agent-inventory",
		Capabilities:  []string{"inventory"},
		Status:        model.AgentStatusOnline,
		LastHeartbeat: time.Now(),
	}
	require.NoError(t, st.UpsertAgent(ctx, agent))
	require.NoError(t, sched.PrimeFromStore(ctx))

	leasedTask, run, err := sched.LeaseTask(ctx, agent)
	require.NoError(t, err)
	require.Equal(t, taskID, leasedTask.ID)
	require.NoError(t, sched.MarkRunStarted(ctx, run.LeaseID))

	targets := []string{"10.0.0.1", "10.0.0.2"}
	execResult := model.ExecutionResult{
		Status: "succeeded",
		Summary: model.ExecutionSummary{
			Command:         "inventory",
			Status:          "完成",
			DurationSeconds: 3.2,
			Risks:           map[string]int{"high": 2, "low": 5},
			Outputs: []model.OutputRecord{
				{Path: "/tmp/inventory-10.0.0.1.json", Label: "资产扫描：10.0.0.1"},
				{Path: "/tmp/inventory-10.0.0.2.json", Label: "资产扫描：10.0.0.2"},
				{Path: "/tmp/inventory-summary.json", Label: "资产扫描汇总"},
			},
		},
		Metadata: map[string]string{
			"total_hosts":  "4",
			"total_ports":  "12",
			"targets":      strings.Join(targets, ","),
			"target_count": "2",
			"summary_path": "/tmp/inventory-summary.json",
		},
	}
	summaryBytes, err := json.Marshal(execResult)
	require.NoError(t, err)

	runStored, err := st.GetTaskRunByLease(ctx, run.LeaseID)
	require.NoError(t, err)
	require.NoError(t, sched.CompleteTask(ctx, runStored, model.TaskStatusSucceeded, summaryBytes, "", map[string]string{"targets": strings.Join(targets, ","), "target_count": "2"}, 0, "", nil))

	reportReq := httptest.NewRequest(http.MethodGet, "/api/v1/tasks/"+taskID.String()+"/inventory/report", nil)
	reportReq.Header.Set("X-API-Key", "changeme")
	reportResp := performRequest(router, reportReq)
	require.Equal(t, http.StatusOK, reportResp.Code)

	var report struct {
		TaskID  string                `json:"task_id"`
		Totals  map[string]int        `json:"totals"`
		Targets []string              `json:"targets"`
		Result  model.ExecutionResult `json:"result"`
	}
	require.NoError(t, json.Unmarshal(reportResp.Body.Bytes(), &report))
	require.Equal(t, taskID.String(), report.TaskID)
	require.Equal(t, map[string]int{"hosts": 4, "ports": 12}, report.Totals)
	require.ElementsMatch(t, targets, report.Targets)
	require.Len(t, report.Result.Summary.Outputs, 3)
	require.Equal(t, "资产扫描汇总", report.Result.Summary.Outputs[2].Label)
}

func TestGetSupplyChainReport(t *testing.T) {
	router, st, sched := setupTestRouter(t)
	ctx := context.Background()

	body, _ := json.Marshal(map[string]any{
		"type":       "supplychain",
		"profile":    "generate",
		"priority":   1,
		"payload":    map[string]any{"flags": map[string]any{"path": "/app", "mode": "generate"}},
		"metadata":   map[string]string{"required_capabilities": "supplychain"},
		"created_by": "tester",
	})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/tasks", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-API-Key", "changeme")
	resp := performRequest(router, req)
	require.Equal(t, http.StatusCreated, resp.Code)

	var created map[string]string
	require.NoError(t, json.Unmarshal(resp.Body.Bytes(), &created))
	taskID := uuid.MustParse(created["id"])

	agent := &model.Agent{
		ID:            uuid.New(),
		Name:          "agent-supplychain",
		Capabilities:  []string{"supplychain"},
		Status:        model.AgentStatusOnline,
		LastHeartbeat: time.Now(),
	}
	require.NoError(t, st.UpsertAgent(ctx, agent))
	require.NoError(t, sched.PrimeFromStore(ctx))

	leasedTask, run, err := sched.LeaseTask(ctx, agent)
	require.NoError(t, err)
	require.Equal(t, taskID, leasedTask.ID)
	require.NoError(t, sched.MarkRunStarted(ctx, run.LeaseID))

	execResult := model.ExecutionResult{
		Status: "succeeded",
		Summary: model.ExecutionSummary{
			Command:         "supplychain",
			Status:          "完成",
			DurationSeconds: 4.1,
			Risks:           map[string]int{"low": 15},
			Notes:           []string{"包含第三方组件"},
			Outputs: []model.OutputRecord{
				{Path: "/tmp/sbom.json", Label: "供应链报告"},
			},
		},
		Metadata: map[string]string{
			"mode":            "generate",
			"component_count": "15",
			"sources":         "package.json,requirements.txt",
			"report_path":     "/tmp/sbom.json",
		},
	}
	summaryBytes, err := json.Marshal(execResult)
	require.NoError(t, err)

	runStored, err := st.GetTaskRunByLease(ctx, run.LeaseID)
	require.NoError(t, err)
	require.NoError(t, sched.CompleteTask(ctx, runStored, model.TaskStatusSucceeded, summaryBytes, "", map[string]string{"mode": "generate"}, 0, "", nil))

	reportReq := httptest.NewRequest(http.MethodGet, "/api/v1/tasks/"+taskID.String()+"/supplychain/report", nil)
	reportReq.Header.Set("X-API-Key", "changeme")
	reportResp := performRequest(router, reportReq)
	require.Equal(t, http.StatusOK, reportResp.Code)

	var report struct {
		TaskID         string                `json:"task_id"`
		Mode           string                `json:"mode"`
		ComponentCount int                   `json:"component_count"`
		Sources        []string              `json:"sources"`
		Result         model.ExecutionResult `json:"result"`
	}
	require.NoError(t, json.Unmarshal(reportResp.Body.Bytes(), &report))
	require.Equal(t, taskID.String(), report.TaskID)
	require.Equal(t, "generate", report.Mode)
	require.Equal(t, 15, report.ComponentCount)
	require.ElementsMatch(t, []string{"package.json", "requirements.txt"}, report.Sources)
	require.Len(t, report.Result.Summary.Outputs, 1)
	require.Equal(t, "供应链报告", report.Result.Summary.Outputs[0].Label)
}
