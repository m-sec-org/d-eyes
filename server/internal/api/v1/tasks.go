package v1

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/m-sec-org/d-eyes/server/internal/model"
	"github.com/m-sec-org/d-eyes/server/internal/scheduler"
	"github.com/m-sec-org/d-eyes/server/internal/store"
)

type TaskHandler struct {
	Store store.Store
	Sched *scheduler.Scheduler
}

type createTaskRequest struct {
	Type      string            `json:"type" binding:"required"`
	Profile   string            `json:"profile"`
	Priority  int               `json:"priority"`
	Payload   interface{}       `json:"payload"`
	Metadata  map[string]string `json:"metadata"`
	CreatedBy string            `json:"created_by"`
}

type taskResponse struct {
	ID         string            `json:"id"`
	Type       string            `json:"type"`
	Profile    string            `json:"profile,omitempty"`
	Priority   int               `json:"priority"`
	Status     string            `json:"status"`
	RetryCount int               `json:"retry_count"`
	Metadata   map[string]string `json:"metadata"`
	CreatedBy  string            `json:"created_by"`
	CreatedAt  time.Time         `json:"created_at"`
	UpdatedAt  time.Time         `json:"updated_at"`
	LastRun    *taskRunResponse  `json:"last_run,omitempty"`
}

type taskRunResponse struct {
	ID         string            `json:"id"`
	AgentID    string            `json:"agent_id"`
	Status     string            `json:"status"`
	StartedAt  *time.Time        `json:"started_at,omitempty"`
	FinishedAt *time.Time        `json:"finished_at,omitempty"`
	Summary    json.RawMessage   `json:"summary,omitempty"`
	Error      string            `json:"error_message,omitempty"`
	Metadata   map[string]string `json:"metadata,omitempty"`
	ExitCode   int32             `json:"exit_code,omitempty"`
	ErrorCode  string            `json:"error_code,omitempty"`
	ExpiresAt  *time.Time        `json:"expires_at,omitempty"`
}

func (h *TaskHandler) RegisterRoutes(r *gin.RouterGroup) {
	r.POST("/tasks", h.createTask)
	r.GET("/tasks", h.listTasks)
	r.GET("/tasks/:id", h.getTask)
	r.GET("/tasks/:id/respond/report", h.getRespondReport)
	r.GET("/tasks/:id/baseline/report", h.getBaselineReport)
	r.GET("/tasks/:id/bas/report", h.getBASReport)
	r.GET("/tasks/:id/inventory/report", h.getInventoryReport)
	r.GET("/tasks/:id/supplychain/report", h.getSupplyChainReport)
	r.POST("/tasks/:id/cancel", h.cancelTask)
	r.POST("/tasks/:id/retry", h.retryTask)
}

func (h *TaskHandler) createTask(c *gin.Context) {
	var req createTaskRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if req.Priority == 0 {
		req.Priority = 5
	}
	payloadBytes, err := json.Marshal(req.Payload)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid payload"})
		return
	}
	ctx := c.Request.Context()
	metadata := make(map[string]string, len(req.Metadata))
	for k, v := range req.Metadata {
		metadata[k] = v
	}
	task := &model.Task{
		ID:        uuid.New(),
		Type:      model.TaskType(req.Type),
		Profile:   req.Profile,
		Priority:  req.Priority,
		Payload:   payloadBytes,
		Status:    model.TaskStatusPending,
		Metadata:  metadata,
		CreatedBy: req.CreatedBy,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}
	if err := h.Store.CreateTask(ctx, task); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	if h.Sched != nil {
		h.Sched.RecordNewTask(task.Status)
	}
	if err := h.Sched.EnqueueTask(ctx, task); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusCreated, gin.H{"id": task.ID.String()})
}

func (h *TaskHandler) listTasks(c *gin.Context) {
	ctx := c.Request.Context()
	limit := 20
	if v := c.Query("limit"); v != "" {
		if parsed, err := strconv.Atoi(v); err == nil && parsed > 0 {
			limit = parsed
		} else {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid limit"})
			return
		}
	}
	statuses, err := parseStatusFilter(c.Query("status"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	tasks, err := h.Store.ListTasks(ctx, statuses, limit)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	result := make([]taskResponse, 0, len(tasks))
	for _, task := range tasks {
		resp, err := h.buildTaskResponse(ctx, task)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		result = append(result, resp)
	}
	c.JSON(http.StatusOK, result)
}

func (h *TaskHandler) getTask(c *gin.Context) {
	ctx := c.Request.Context()
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid task id"})
		return
	}
	task, err := h.Store.GetTask(ctx, id)
	if err != nil {
		if err == store.ErrNotFound {
			c.JSON(http.StatusNotFound, gin.H{"error": "task not found"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	resp, err := h.buildTaskResponse(ctx, task)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, resp)
}

type supplyChainReportResponse struct {
	TaskID         string                `json:"task_id"`
	TaskType       string                `json:"task_type"`
	Profile        string                `json:"profile,omitempty"`
	RunID          string                `json:"run_id"`
	AgentID        string                `json:"agent_id"`
	TaskStatus     string                `json:"task_status"`
	Mode           string                `json:"mode,omitempty"`
	ComponentCount int                   `json:"component_count,omitempty"`
	Sources        []string              `json:"sources,omitempty"`
	Outputs        []model.OutputRecord  `json:"outputs,omitempty"`
	Result         model.ExecutionResult `json:"result"`
	RunMetadata    map[string]string     `json:"run_metadata,omitempty"`
	ExitCode       int32                 `json:"exit_code,omitempty"`
	ErrorCode      string                `json:"error_code,omitempty"`
	CompletedAt    *time.Time            `json:"completed_at,omitempty"`
	ExpiresAt      *time.Time            `json:"expires_at,omitempty"`
}

func (h *TaskHandler) getSupplyChainReport(c *gin.Context) {
	ctx := c.Request.Context()
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid task id"})
		return
	}
	task, err := h.Store.GetTask(ctx, id)
	if err != nil {
		if err == store.ErrNotFound {
			c.JSON(http.StatusNotFound, gin.H{"error": "task not found"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	if task.Type != model.TaskType("supplychain") {
		c.JSON(http.StatusBadRequest, gin.H{"error": "task is not supplychain type"})
		return
	}
	run, err := h.Store.GetLatestTaskRun(ctx, task.ID)
	if err != nil {
		if err == store.ErrNotFound {
			c.JSON(http.StatusNotFound, gin.H{"error": "task run not found"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	if len(run.Summary) == 0 {
		c.JSON(http.StatusNotFound, gin.H{"error": "supplychain summary not available"})
		return
	}

	var exec model.ExecutionResult
	if err := json.Unmarshal(run.Summary, &exec); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to decode supplychain summary"})
		return
	}

	resp := supplyChainReportResponse{
		TaskID:     task.ID.String(),
		TaskType:   string(task.Type),
		Profile:    task.Profile,
		RunID:      run.ID.String(),
		AgentID:    run.AgentID.String(),
		TaskStatus: string(run.Status),
		Outputs:    exec.Summary.Outputs,
		Result:     exec,
		RunMetadata: func() map[string]string {
			if len(run.Metadata) == 0 {
				return nil
			}
			copyMeta := make(map[string]string, len(run.Metadata))
			for k, v := range run.Metadata {
				copyMeta[k] = v
			}
			return copyMeta
		}(),
		ExitCode:  run.ExitCode,
		ErrorCode: run.ErrorCode,
	}
	if run.FinishedAt != nil && !run.FinishedAt.IsZero() {
		resp.CompletedAt = run.FinishedAt
	}
	if !run.ExpiresAt.IsZero() {
		resp.ExpiresAt = &run.ExpiresAt
	}

	if mode := exec.Metadata["mode"]; mode != "" {
		resp.Mode = mode
	}
	if countStr := exec.Metadata["component_count"]; countStr != "" {
		if count, err := strconv.Atoi(countStr); err == nil {
			resp.ComponentCount = count
		}
	}
	if srcs := exec.Metadata["sources"]; srcs != "" {
		parts := strings.Split(srcs, ",")
		for _, part := range parts {
			if trimmed := strings.TrimSpace(part); trimmed != "" {
				resp.Sources = append(resp.Sources, trimmed)
			}
		}
	}

	c.JSON(http.StatusOK, resp)
}

func (h *TaskHandler) cancelTask(c *gin.Context) {
	ctx := c.Request.Context()
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid task id"})
		return
	}
	if err := h.Store.UpdateTaskStatus(ctx, id, model.TaskStatusCanceled); err != nil {
		if err == store.ErrNotFound {
			c.JSON(http.StatusNotFound, gin.H{"error": "task not found"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.Status(http.StatusNoContent)
}

func (h *TaskHandler) retryTask(c *gin.Context) {
	ctx := c.Request.Context()
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid task id"})
		return
	}
	task, err := h.Store.GetTask(ctx, id)
	if err != nil {
		if err == store.ErrNotFound {
			c.JSON(http.StatusNotFound, gin.H{"error": "task not found"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	if err := h.Store.UpdateTaskStatus(ctx, id, model.TaskStatusPending); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	if err := h.Store.IncrementTaskRetry(ctx, id); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	task, err = h.Store.GetTask(ctx, id)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	if err := h.Sched.EnqueueTask(ctx, task); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	resp, err := h.buildTaskResponse(ctx, task)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusAccepted, resp)
}

func (h *TaskHandler) buildTaskResponse(ctx context.Context, task *model.Task) (taskResponse, error) {
	resp := taskResponse{
		ID:         task.ID.String(),
		Type:       string(task.Type),
		Profile:    task.Profile,
		Priority:   task.Priority,
		Status:     string(task.Status),
		RetryCount: task.RetryCount,
		Metadata:   task.Metadata,
		CreatedBy:  task.CreatedBy,
		CreatedAt:  task.CreatedAt,
		UpdatedAt:  task.UpdatedAt,
	}
	run, err := h.Store.GetLatestTaskRun(ctx, task.ID)
	if err == nil {
		resp.LastRun = toRunResponse(run)
	} else if err != nil && err != store.ErrNotFound {
		return resp, err
	}
	return resp, nil
}

func toRunResponse(run *model.TaskRun) *taskRunResponse {
	if run == nil {
		return nil
	}
	resp := &taskRunResponse{
		ID:        run.ID.String(),
		AgentID:   run.AgentID.String(),
		Status:    string(run.Status),
		Error:     run.ErrorMessage,
		StartedAt: run.StartedAt,
		FinishedAt: func() *time.Time {
			if run.FinishedAt == nil || run.FinishedAt.IsZero() {
				return nil
			}
			return run.FinishedAt
		}(),
	}
	if len(run.Summary) > 0 {
		resp.Summary = json.RawMessage(append([]byte(nil), run.Summary...))
	}
	if len(run.Metadata) > 0 {
		copyMeta := make(map[string]string, len(run.Metadata))
		for k, v := range run.Metadata {
			copyMeta[k] = v
		}
		resp.Metadata = copyMeta
	}
	if run.ExitCode != 0 {
		resp.ExitCode = run.ExitCode
	}
	if run.ErrorCode != "" {
		resp.ErrorCode = run.ErrorCode
	}
	if !run.ExpiresAt.IsZero() {
		resp.ExpiresAt = &run.ExpiresAt
	}
	return resp
}

type respondReportResponse struct {
	TaskID      string                `json:"task_id"`
	TaskType    string                `json:"task_type"`
	Profile     string                `json:"profile,omitempty"`
	RunID       string                `json:"run_id"`
	AgentID     string                `json:"agent_id"`
	TaskStatus  string                `json:"task_status"`
	Result      model.ExecutionResult `json:"result"`
	RunMetadata map[string]string     `json:"run_metadata,omitempty"`
	ExitCode    int32                 `json:"exit_code,omitempty"`
	ErrorCode   string                `json:"error_code,omitempty"`
	CompletedAt *time.Time            `json:"completed_at,omitempty"`
	ExpiresAt   *time.Time            `json:"expires_at,omitempty"`
}

func (h *TaskHandler) getRespondReport(c *gin.Context) {
	ctx := c.Request.Context()
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid task id"})
		return
	}
	task, err := h.Store.GetTask(ctx, id)
	if err != nil {
		if err == store.ErrNotFound {
			c.JSON(http.StatusNotFound, gin.H{"error": "task not found"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	if task.Type != model.TaskType("respond") {
		c.JSON(http.StatusBadRequest, gin.H{"error": "task is not respond type"})
		return
	}

	run, err := h.Store.GetLatestTaskRun(ctx, task.ID)
	if err != nil {
		if err == store.ErrNotFound {
			c.JSON(http.StatusNotFound, gin.H{"error": "task run not found"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	if len(run.Summary) == 0 {
		c.JSON(http.StatusNotFound, gin.H{"error": "respond summary not available"})
		return
	}

	var exec model.ExecutionResult
	if err := json.Unmarshal(run.Summary, &exec); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to decode respond summary"})
		return
	}

	resp := respondReportResponse{
		TaskID:     task.ID.String(),
		TaskType:   string(task.Type),
		Profile:    task.Profile,
		RunID:      run.ID.String(),
		AgentID:    run.AgentID.String(),
		TaskStatus: string(run.Status),
		Result:     exec,
		RunMetadata: func() map[string]string {
			if len(run.Metadata) == 0 {
				return nil
			}
			meta := make(map[string]string, len(run.Metadata))
			for k, v := range run.Metadata {
				meta[k] = v
			}
			return meta
		}(),
		ExitCode:  run.ExitCode,
		ErrorCode: run.ErrorCode,
	}
	if run.FinishedAt != nil && !run.FinishedAt.IsZero() {
		resp.CompletedAt = run.FinishedAt
	}
	if !run.ExpiresAt.IsZero() {
		resp.ExpiresAt = &run.ExpiresAt
	}

	c.JSON(http.StatusOK, resp)
}

type baselineReportResponse struct {
	TaskID      string                `json:"task_id"`
	TaskType    string                `json:"task_type"`
	Profile     string                `json:"profile,omitempty"`
	RunID       string                `json:"run_id"`
	AgentID     string                `json:"agent_id"`
	TaskStatus  string                `json:"task_status"`
	Severity    map[string]int        `json:"severity"`
	Warnings    []string              `json:"warnings,omitempty"`
	Outputs     []model.OutputRecord  `json:"outputs,omitempty"`
	Result      model.ExecutionResult `json:"result"`
	RunMetadata map[string]string     `json:"run_metadata,omitempty"`
	ExitCode    int32                 `json:"exit_code,omitempty"`
	ErrorCode   string                `json:"error_code,omitempty"`
	CompletedAt *time.Time            `json:"completed_at,omitempty"`
	ExpiresAt   *time.Time            `json:"expires_at,omitempty"`
}

type basScenarioStep struct {
	ID        string     `json:"id"`
	Name      string     `json:"name"`
	Status    string     `json:"status"`
	ExitCode  int        `json:"exit_code"`
	Message   string     `json:"message,omitempty"`
	Stdout    string     `json:"stdout,omitempty"`
	Stderr    string     `json:"stderr,omitempty"`
	Sandbox   bool       `json:"sandbox"`
	StartedAt *time.Time `json:"started_at,omitempty"`
	EndedAt   *time.Time `json:"ended_at,omitempty"`
}

type basScenarioSummary struct {
	Total   int `json:"total"`
	Success int `json:"success"`
	Failed  int `json:"failed"`
	Skipped int `json:"skipped"`
}

type basReportResponse struct {
	TaskID       string                `json:"task_id"`
	TaskType     string                `json:"task_type"`
	Profile      string                `json:"profile,omitempty"`
	RunID        string                `json:"run_id"`
	AgentID      string                `json:"agent_id"`
	TaskStatus   string                `json:"task_status"`
	ScenarioID   string                `json:"scenario_id,omitempty"`
	ScenarioName string                `json:"scenario_name,omitempty"`
	ScenarioTags []string              `json:"scenario_tags,omitempty"`
	Description  string                `json:"description,omitempty"`
	Steps        []basScenarioStep     `json:"steps,omitempty"`
	Summary      basScenarioSummary    `json:"summary"`
	Result       model.ExecutionResult `json:"result"`
	Outputs      []model.OutputRecord  `json:"outputs,omitempty"`
	RunMetadata  map[string]string     `json:"run_metadata,omitempty"`
	ExitCode     int32                 `json:"exit_code,omitempty"`
	ErrorCode    string                `json:"error_code,omitempty"`
	FailedSteps  []string              `json:"failed_steps,omitempty"`
	CompletedAt  *time.Time            `json:"completed_at,omitempty"`
	ExpiresAt    *time.Time            `json:"expires_at,omitempty"`
}

func (h *TaskHandler) getBaselineReport(c *gin.Context) {
	ctx := c.Request.Context()
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid task id"})
		return
	}
	task, err := h.Store.GetTask(ctx, id)
	if err != nil {
		if err == store.ErrNotFound {
			c.JSON(http.StatusNotFound, gin.H{"error": "task not found"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	if task.Type != model.TaskType("baseline") {
		c.JSON(http.StatusBadRequest, gin.H{"error": "task is not baseline type"})
		return
	}
	run, err := h.Store.GetLatestTaskRun(ctx, task.ID)
	if err != nil {
		if err == store.ErrNotFound {
			c.JSON(http.StatusNotFound, gin.H{"error": "task run not found"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	if len(run.Summary) == 0 {
		c.JSON(http.StatusNotFound, gin.H{"error": "baseline summary not available"})
		return
	}

	var exec model.ExecutionResult
	if err := json.Unmarshal(run.Summary, &exec); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to decode baseline summary"})
		return
	}

	resp := baselineReportResponse{
		TaskID:     task.ID.String(),
		TaskType:   string(task.Type),
		Profile:    task.Profile,
		RunID:      run.ID.String(),
		AgentID:    run.AgentID.String(),
		TaskStatus: string(run.Status),
		Severity:   exec.Summary.Risks,
		Warnings:   exec.Summary.Notes,
		Outputs:    exec.Summary.Outputs,
		Result:     exec,
		RunMetadata: func() map[string]string {
			if len(run.Metadata) == 0 {
				return nil
			}
			copyMeta := make(map[string]string, len(run.Metadata))
			for k, v := range run.Metadata {
				copyMeta[k] = v
			}
			return copyMeta
		}(),
		ExitCode:  run.ExitCode,
		ErrorCode: run.ErrorCode,
	}
	if run.FinishedAt != nil && !run.FinishedAt.IsZero() {
		resp.CompletedAt = run.FinishedAt
	}
	if !run.ExpiresAt.IsZero() {
		resp.ExpiresAt = &run.ExpiresAt
	}

	c.JSON(http.StatusOK, resp)
}

func (h *TaskHandler) getBASReport(c *gin.Context) {
	ctx := c.Request.Context()
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid task id"})
		return
	}
	task, err := h.Store.GetTask(ctx, id)
	if err != nil {
		if err == store.ErrNotFound {
			c.JSON(http.StatusNotFound, gin.H{"error": "task not found"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	if task.Type != model.TaskType("bas") {
		c.JSON(http.StatusBadRequest, gin.H{"error": "task is not bas type"})
		return
	}
	run, err := h.Store.GetLatestTaskRun(ctx, task.ID)
	if err != nil {
		if err == store.ErrNotFound {
			c.JSON(http.StatusNotFound, gin.H{"error": "task run not found"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	if len(run.Summary) == 0 {
		c.JSON(http.StatusNotFound, gin.H{"error": "bas summary not available"})
		return
	}

	var exec model.ExecutionResult
	if err := json.Unmarshal(run.Summary, &exec); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to decode bas summary"})
		return
	}

	steps, err := parseBASteps(run.Metadata["scenario_summary"])
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to decode bas scenario steps"})
		return
	}

	resp := basReportResponse{
		TaskID:       task.ID.String(),
		TaskType:     string(task.Type),
		Profile:      task.Profile,
		RunID:        run.ID.String(),
		AgentID:      run.AgentID.String(),
		TaskStatus:   string(run.Status),
		ScenarioID:   run.Metadata["scenario_id"],
		ScenarioName: run.Metadata["scenario_name"],
		Description:  run.Metadata["scenario_description"],
		Steps:        steps,
		Summary: basScenarioSummary{
			Total:   parseMetadataInt(run.Metadata["scenario_steps"]),
			Success: parseMetadataInt(run.Metadata["steps_success"]),
			Failed:  parseMetadataInt(run.Metadata["steps_failed"]),
			Skipped: parseMetadataInt(run.Metadata["steps_skipped"]),
		},
		Result:      exec,
		Outputs:     exec.Summary.Outputs,
		RunMetadata: cloneMetadata(run.Metadata),
		ExitCode:    run.ExitCode,
		ErrorCode:   run.ErrorCode,
	}

	if tags := strings.TrimSpace(run.Metadata["scenario_tags"]); tags != "" {
		resp.ScenarioTags = splitAndTrimList(tags)
	}
	if failed := strings.TrimSpace(run.Metadata["failed_steps"]); failed != "" {
		resp.FailedSteps = splitAndTrimList(failed)
	}
	if run.FinishedAt != nil && !run.FinishedAt.IsZero() {
		resp.CompletedAt = run.FinishedAt
	}
	if !run.ExpiresAt.IsZero() {
		resp.ExpiresAt = &run.ExpiresAt
	}

	c.JSON(http.StatusOK, resp)
}

type inventoryReportResponse struct {
	TaskID      string                `json:"task_id"`
	TaskType    string                `json:"task_type"`
	Profile     string                `json:"profile,omitempty"`
	RunID       string                `json:"run_id"`
	AgentID     string                `json:"agent_id"`
	TaskStatus  string                `json:"task_status"`
	Totals      map[string]int        `json:"totals,omitempty"`
	Targets     []string              `json:"targets,omitempty"`
	Risks       map[string]int        `json:"risks,omitempty"`
	Outputs     []model.OutputRecord  `json:"outputs,omitempty"`
	Result      model.ExecutionResult `json:"result"`
	RunMetadata map[string]string     `json:"run_metadata,omitempty"`
	ExitCode    int32                 `json:"exit_code,omitempty"`
	ErrorCode   string                `json:"error_code,omitempty"`
	CompletedAt *time.Time            `json:"completed_at,omitempty"`
	ExpiresAt   *time.Time            `json:"expires_at,omitempty"`
}

func (h *TaskHandler) getInventoryReport(c *gin.Context) {
	ctx := c.Request.Context()
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid task id"})
		return
	}
	task, err := h.Store.GetTask(ctx, id)
	if err != nil {
		if err == store.ErrNotFound {
			c.JSON(http.StatusNotFound, gin.H{"error": "task not found"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	if task.Type != model.TaskType("inventory") {
		c.JSON(http.StatusBadRequest, gin.H{"error": "task is not inventory type"})
		return
	}
	run, err := h.Store.GetLatestTaskRun(ctx, task.ID)
	if err != nil {
		if err == store.ErrNotFound {
			c.JSON(http.StatusNotFound, gin.H{"error": "task run not found"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	if len(run.Summary) == 0 {
		c.JSON(http.StatusNotFound, gin.H{"error": "inventory summary not available"})
		return
	}
	var exec model.ExecutionResult
	if err := json.Unmarshal(run.Summary, &exec); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to decode inventory summary"})
		return
	}

	resp := inventoryReportResponse{
		TaskID:     task.ID.String(),
		TaskType:   string(task.Type),
		Profile:    task.Profile,
		RunID:      run.ID.String(),
		AgentID:    run.AgentID.String(),
		TaskStatus: string(run.Status),
		Risks:      exec.Summary.Risks,
		Outputs:    exec.Summary.Outputs,
		Result:     exec,
		RunMetadata: func() map[string]string {
			if len(run.Metadata) == 0 {
				return nil
			}
			copyMeta := make(map[string]string, len(run.Metadata))
			for k, v := range run.Metadata {
				copyMeta[k] = v
			}
			return copyMeta
		}(),
		ExitCode:  run.ExitCode,
		ErrorCode: run.ErrorCode,
	}
	if run.FinishedAt != nil && !run.FinishedAt.IsZero() {
		resp.CompletedAt = run.FinishedAt
	}
	if !run.ExpiresAt.IsZero() {
		resp.ExpiresAt = &run.ExpiresAt
	}

	if totals := make(map[string]int); true {
		if totalHosts, err := strconv.Atoi(exec.Metadata["total_hosts"]); err == nil {
			totals["hosts"] = totalHosts
		}
		if totalPorts, err := strconv.Atoi(exec.Metadata["total_ports"]); err == nil {
			totals["ports"] = totalPorts
		}
		if len(totals) > 0 {
			resp.Totals = totals
		}
	}
	if targets := exec.Metadata["targets"]; targets != "" {
		for _, t := range strings.Split(targets, ",") {
			if trimmed := strings.TrimSpace(t); trimmed != "" {
				resp.Targets = append(resp.Targets, trimmed)
			}
		}
	}

	c.JSON(http.StatusOK, resp)
}

func parseStatusFilter(raw string) ([]model.TaskStatus, error) {
	if raw == "" {
		return nil, nil
	}
	parts := strings.Split(raw, ",")
	statuses := make([]model.TaskStatus, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(strings.ToLower(part))
		if part == "" {
			continue
		}
		status := model.TaskStatus(part)
		switch status {
		case model.TaskStatusPending, model.TaskStatusLeased, model.TaskStatusRunning, model.TaskStatusSucceeded, model.TaskStatusFailed, model.TaskStatusCanceled:
			statuses = append(statuses, status)
		default:
			return nil, fmt.Errorf("invalid status %q", part)
		}
	}
	return statuses, nil
}

func parseBASteps(raw string) ([]basScenarioStep, error) {
	if strings.TrimSpace(raw) == "" {
		return nil, nil
	}
	var tmp []struct {
		ID        string    `json:"id"`
		Name      string    `json:"name"`
		Status    string    `json:"status"`
		ExitCode  int       `json:"exit_code"`
		Message   string    `json:"message,omitempty"`
		Stdout    string    `json:"stdout,omitempty"`
		Stderr    string    `json:"stderr,omitempty"`
		Sandbox   bool      `json:"sandbox"`
		StartedAt time.Time `json:"started_at"`
		EndedAt   time.Time `json:"ended_at"`
	}
	if err := json.Unmarshal([]byte(raw), &tmp); err != nil {
		return nil, err
	}
	steps := make([]basScenarioStep, 0, len(tmp))
	for _, step := range tmp {
		stepCopy := basScenarioStep{
			ID:       step.ID,
			Name:     step.Name,
			Status:   step.Status,
			ExitCode: step.ExitCode,
			Message:  step.Message,
			Stdout:   step.Stdout,
			Stderr:   step.Stderr,
			Sandbox:  step.Sandbox,
		}
		if !step.StartedAt.IsZero() {
			start := step.StartedAt
			stepCopy.StartedAt = &start
		}
		if !step.EndedAt.IsZero() {
			end := step.EndedAt
			stepCopy.EndedAt = &end
		}
		steps = append(steps, stepCopy)
	}
	return steps, nil
}

func parseMetadataInt(raw string) int {
	if strings.TrimSpace(raw) == "" {
		return 0
	}
	if v, err := strconv.Atoi(strings.TrimSpace(raw)); err == nil {
		return v
	}
	return 0
}

func cloneMetadata(src map[string]string) map[string]string {
	if len(src) == 0 {
		return nil
	}
	cp := make(map[string]string, len(src))
	for k, v := range src {
		cp[k] = v
	}
	return cp
}

func splitAndTrimList(raw string) []string {
	if strings.TrimSpace(raw) == "" {
		return nil
	}
	parts := strings.FieldsFunc(raw, func(r rune) bool {
		return r == ',' || r == ';'
	})
	result := make([]string, 0, len(parts))
	for _, part := range parts {
		p := strings.TrimSpace(part)
		if p != "" {
			result = append(result, p)
		}
	}
	if len(result) == 0 {
		return nil
	}
	return result
}
