package v1

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/m-sec-org/d-eyes/server/internal/auditlog"
	"github.com/m-sec-org/d-eyes/server/internal/basscenarios"
	"github.com/m-sec-org/d-eyes/server/internal/model"
	"github.com/m-sec-org/d-eyes/server/internal/rbac"
	"github.com/m-sec-org/d-eyes/server/internal/scheduler"
	"github.com/m-sec-org/d-eyes/server/internal/security"
	"github.com/m-sec-org/d-eyes/server/internal/store"
	"github.com/m-sec-org/d-eyes/server/internal/streams"
	"github.com/m-sec-org/d-eyes/server/internal/taskcatalog"
)

type TaskHandler struct {
	Store        store.Store
	Sched        *scheduler.Scheduler
	Catalog      *taskcatalog.Manager
	BASScenarios *basscenarios.Manager
	RBAC         *rbac.Enforcer
	Audit        *auditlog.Manager
}

func (h *TaskHandler) requirePermission(c *gin.Context, permission string) bool {
	if h == nil || h.RBAC == nil {
		return true
	}
	principal := security.PrincipalFrom(c)
	if h.RBAC.Enforce(principal.Role, permission) {
		return true
	}
	c.JSON(http.StatusForbidden, gin.H{"error": "insufficient permissions"})
	return false
}

func (h *TaskHandler) recordAudit(c *gin.Context, action, resource, result string, metadata map[string]string) {
	if h == nil || h.Audit == nil {
		return
	}
	principal := security.PrincipalFrom(c)
	h.Audit.Record(auditlog.Event{
		Actor:    principal.User,
		Role:     principal.Role,
		Action:   action,
		Resource: resource,
		Result:   result,
		Metadata: metadata,
	})
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

type taskVisualResponse struct {
	TaskID      string      `json:"task_id"`
	TaskType    string      `json:"task_type"`
	VisualType  string      `json:"visual_type"`
	GeneratedAt time.Time   `json:"generated_at"`
	Payload     interface{} `json:"payload"`
}

func normalizePayloadMap(raw interface{}) (map[string]any, error) {
	if raw == nil {
		return map[string]any{}, nil
	}
	if payload, ok := raw.(map[string]any); ok {
		return payload, nil
	}
	bytes, err := json.Marshal(raw)
	if err != nil {
		return nil, err
	}
	if len(bytes) == 0 || string(bytes) == "null" {
		return map[string]any{}, nil
	}
	var out map[string]any
	if err := json.Unmarshal(bytes, &out); err != nil {
		return nil, err
	}
	if out == nil {
		out = map[string]any{}
	}
	return out, nil
}

func (h *TaskHandler) RegisterRoutes(r *gin.RouterGroup) {
	r.POST("/tasks", h.createTask)
	r.GET("/tasks", h.listTasks)
	r.GET("/tasks/:id", h.getTask)
	r.GET("/tasks/:id/visuals", h.getTaskVisuals)
	r.GET("/tasks/:id/respond/report", h.getRespondReport)
	r.GET("/tasks/:id/baseline/report", h.getBaselineReport)
	r.GET("/tasks/:id/bas/report", h.getBASReport)
	r.GET("/tasks/:id/inventory/report", h.getInventoryReport)
	r.GET("/tasks/:id/supplychain/report", h.getSupplyChainReport)
	r.POST("/tasks/:id/cancel", h.cancelTask)
	r.POST("/tasks/:id/retry", h.retryTask)
	r.POST("/tasks/:id/actions", h.handleTaskAction)
}

func (h *TaskHandler) createTask(c *gin.Context) {
	if !h.requirePermission(c, "tasks.create") {
		return
	}
	var req createTaskRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if req.Priority == 0 {
		req.Priority = 5
	}
	payloadMap, err := normalizePayloadMap(req.Payload)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid payload"})
		return
	}
	if h.Catalog != nil && strings.TrimSpace(req.Profile) != "" && strings.TrimSpace(req.Type) != "" {
		if err := h.Catalog.ValidateTaskPayload(req.Type, req.Profile, payloadMap); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
	}
	payloadBytes, err := json.Marshal(payloadMap)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid payload"})
		return
	}
	principal := security.PrincipalFrom(c)
	if req.CreatedBy == "" {
		req.CreatedBy = principal.User
	}
	ctx := c.Request.Context()
	metadata := make(map[string]string, len(req.Metadata))
	for k, v := range req.Metadata {
		metadata[k] = v
	}
	if h.BASScenarios != nil && isBASTaskType(req.Type) {
		scenarioID := strings.TrimSpace(metadata["scenario_id"])
		if scenarioID == "" {
			c.JSON(http.StatusBadRequest, gin.H{"error": "bas task requires scenario_id in metadata"})
			return
		}
		scenarioUUID, err := uuid.Parse(scenarioID)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid scenario_id"})
			return
		}
		scenario, err := h.BASScenarios.Get(ctx, scenarioUUID)
		if err != nil {
			if errors.Is(err, basscenarios.ErrNotFound) {
				c.JSON(http.StatusBadRequest, gin.H{"error": "scenario not found"})
				return
			}
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		status := basscenarios.ScenarioStatus(scenario.Status)
		if status == basscenarios.StatusDisabled || status == basscenarios.StatusDraft {
			c.JSON(http.StatusBadRequest, gin.H{"error": "scenario not active"})
			return
		}
		if scenario.RequiresApproval && !basscenarios.IsScenarioApproved(scenario) {
			c.JSON(http.StatusBadRequest, gin.H{"error": "scenario not approved"})
			return
		}
		metadata["scenario_name"] = scenario.Name
		if scenario.Description != "" {
			metadata["scenario_description"] = scenario.Description
		}
		if len(scenario.Tags) > 0 {
			metadata["scenario_tags"] = strings.Join(scenario.Tags, ",")
		}
		if len(scenario.NetworkBoundaries) > 0 {
			metadata["network_boundaries"] = strings.Join(scenario.NetworkBoundaries, ",")
		}
		metadata["sandbox_approval_required"] = strconv.FormatBool(scenario.RequiresApproval)
		if scenario.Approval.ApprovedBy != "" {
			metadata["sandbox_approved"] = "true"
		}
		metadata["sandbox_policy_id"] = scenario.ID.String()
		metadata["sandbox_policy_version"] = strconv.Itoa(scenario.Version)
		metadata["scenario_status"] = scenario.Status
		metadata["scenario_version"] = strconv.Itoa(scenario.Version)
		if encodedLimits, err := json.Marshal(scenario.ResourceLimits); err == nil {
			metadata["scenario_limits"] = string(encodedLimits)
		}
		if encodedPlan, err := json.Marshal(scenario.ExecutionPlan); err == nil {
			metadata["scenario_execution_plan"] = string(encodedPlan)
		}
		if len(scenario.ApprovalPolicy) > 0 {
			if encodedPolicy, err := json.Marshal(scenario.ApprovalPolicy); err == nil {
				metadata["scenario_approval_policy"] = string(encodedPolicy)
			}
		}
		if len(scenario.RequiredLabels) > 0 {
			metadata["scenario_required_labels"] = strings.Join(scenario.RequiredLabels, ",")
		}
		if len(scenario.Dependencies) > 0 {
			metadata["scenario_dependencies"] = joinUUIDs(scenario.Dependencies)
		}
		if scenario.PublishedAt != nil {
			metadata["scenario_published_at"] = scenario.PublishedAt.Format(time.RFC3339)
		}
		metadata["scenario_cross_agent"] = strconv.FormatBool(scenario.ExecutionPlan.CrossAgent)
		metadata["scenario_plan_mode"] = strings.ToLower(strings.TrimSpace(scenario.ExecutionPlan.Mode))
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
	h.recordAudit(c, "task.create", "task:"+task.ID.String(), "accepted", map[string]string{
		"type":    req.Type,
		"profile": req.Profile,
	})
	c.JSON(http.StatusCreated, gin.H{"id": task.ID.String()})
}

func (h *TaskHandler) listTasks(c *gin.Context) {
	if !h.requirePermission(c, "tasks.read") {
		return
	}
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
	if !h.requirePermission(c, "tasks.read") {
		return
	}
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

func (h *TaskHandler) getTaskVisuals(c *gin.Context) {
	if !h.requirePermission(c, "tasks.read") {
		return
	}
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
	run, err := h.Store.GetLatestTaskRun(ctx, task.ID)
	if err != nil {
		if err == store.ErrNotFound {
			c.JSON(http.StatusNotFound, gin.H{"error": "task run not found"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	var exec model.ExecutionResult
	if len(run.Summary) > 0 {
		if err := json.Unmarshal(run.Summary, &exec); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to decode summary"})
			return
		}
	}
	visualTypeFilter := c.Query("type")
	visuals := buildTaskVisuals(task, run, exec, visualTypeFilter)
	c.JSON(http.StatusOK, gin.H{"items": visuals})
}

func buildTaskVisuals(task *model.Task, run *model.TaskRun, exec model.ExecutionResult, filter string) []taskVisualResponse {
	var visuals []taskVisualResponse
	appendVisualsFromMetadata(&visuals, task, run, exec.Metadata, exec.ReportedAt, filter)
	appendVisualsFromMetadata(&visuals, task, run, run.Metadata, time.Time{}, filter)
	if len(visuals) == 0 && (filter == "" || filter == "host_summary") {
		payload := hostSummaryPayload(exec, run)
		visuals = append(visuals, newTaskVisual(task, run, exec.ReportedAt, "host_summary", payload))
	}
	return visuals
}

func appendVisualsFromMetadata(target *[]taskVisualResponse, task *model.Task, run *model.TaskRun, metadata map[string]string, reportedAt time.Time, filter string) {
	if len(metadata) == 0 {
		return
	}
	for key, raw := range metadata {
		if !strings.HasPrefix(key, "visual.") {
			continue
		}
		visualType := strings.TrimPrefix(key, "visual.")
		if filter != "" && filter != visualType {
			continue
		}
		var payload interface{}
		if err := json.Unmarshal([]byte(raw), &payload); err != nil {
			continue
		}
		*target = append(*target, newTaskVisual(task, run, reportedAt, visualType, payload))
	}
}

func newTaskVisual(task *model.Task, run *model.TaskRun, reportedAt time.Time, visualType string, payload interface{}) taskVisualResponse {
	generatedAt := reportedAt
	if generatedAt.IsZero() && run != nil && run.FinishedAt != nil && !run.FinishedAt.IsZero() {
		generatedAt = *run.FinishedAt
	}
	if generatedAt.IsZero() {
		generatedAt = time.Now().UTC()
	}
	return taskVisualResponse{
		TaskID:      task.ID.String(),
		TaskType:    string(task.Type),
		VisualType:  visualType,
		GeneratedAt: generatedAt,
		Payload:     payload,
	}
}

func hostSummaryPayload(exec model.ExecutionResult, run *model.TaskRun) map[string]any {
	payload := map[string]any{
		"status":           exec.Status,
		"command":          exec.Summary.Command,
		"duration_seconds": exec.Summary.DurationSeconds,
	}
	if len(exec.Summary.Risks) > 0 {
		payload["risks"] = exec.Summary.Risks
	}
	if len(exec.Summary.Notes) > 0 {
		payload["notes"] = exec.Summary.Notes
	}
	if len(exec.Summary.Outputs) > 0 {
		payload["outputs"] = exec.Summary.Outputs
	}
	if exec.Metadata != nil {
		payload["metadata"] = exec.Metadata
	}
	if run != nil {
		payload["agent_id"] = run.AgentID.String()
		if run.Metadata != nil {
			payload["run_metadata"] = run.Metadata
		}
	}
	return payload
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
	if !h.requirePermission(c, "reports.view") {
		return
	}
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
	if !h.requirePermission(c, "tasks.cancel") {
		return
	}
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
	h.recordAudit(c, "task.cancel", "task:"+id.String(), "accepted", nil)
	c.Status(http.StatusNoContent)
}

func (h *TaskHandler) retryTask(c *gin.Context) {
	if !h.requirePermission(c, "tasks.retry") {
		return
	}
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
	h.recordAudit(c, "task.retry", "task:"+id.String(), "accepted", nil)
	c.JSON(http.StatusAccepted, resp)
}

type taskActionRequest struct {
	Action string `json:"action" binding:"required"`
	Reason string `json:"reason"`
}

func (h *TaskHandler) handleTaskAction(c *gin.Context) {
	if !h.requirePermission(c, "tasks.actions") {
		return
	}
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid task id"})
		return
	}
	var req taskActionRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	action := strings.ToLower(strings.TrimSpace(req.Action))
	switch action {
	case "pause", "resume", "terminate", "ack":
	default:
		c.JSON(http.StatusBadRequest, gin.H{"error": "unsupported action"})
		return
	}
	ctx := c.Request.Context()
	task, err := h.Store.GetTask(ctx, id)
	if err != nil {
		if err == store.ErrNotFound {
			c.JSON(http.StatusNotFound, gin.H{"error": "task not found"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	principal := security.PrincipalFrom(c)
	severity := "info"
	if action == "terminate" {
		severity = "danger"
	} else if action == "pause" || action == "resume" {
		severity = "warning"
	}
	if h.Sched != nil {
		h.Sched.PublishExternalEvent(streams.TaskEvent{
			Event:    "manual_action",
			TaskID:   task.ID.String(),
			TaskType: string(task.Type),
			Status:   string(task.Status),
			Action:   action,
			Actor:    principal.User,
			Message:  req.Reason,
			Severity: severity,
		})
	}
	h.recordAudit(c, "task.action"+"."+action, "task:"+task.ID.String(), "accepted", map[string]string{"reason": req.Reason})
	c.JSON(http.StatusAccepted, gin.H{"status": "accepted"})
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
	if !h.requirePermission(c, "reports.view") {
		return
	}
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
	if !h.requirePermission(c, "reports.view") {
		return
	}
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
	if !h.requirePermission(c, "reports.view") {
		return
	}
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
	if !isBASTaskType(string(task.Type)) {
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
	if !h.requirePermission(c, "reports.view") {
		return
	}
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

func isBASTaskType(taskType string) bool {
	normalized := strings.ToLower(strings.TrimSpace(taskType))
	return normalized == "bas" || normalized == "bas.advanced"
}

func joinUUIDs(values []uuid.UUID) string {
	if len(values) == 0 {
		return ""
	}
	parts := make([]string, 0, len(values))
	for _, v := range values {
		parts = append(parts, v.String())
	}
	return strings.Join(parts, ",")
}
