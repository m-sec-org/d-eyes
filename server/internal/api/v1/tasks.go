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
	Priority  int               `json:"priority"`
	Payload   interface{}       `json:"payload"`
	Metadata  map[string]string `json:"metadata"`
	CreatedBy string            `json:"created_by"`
}

type taskResponse struct {
	ID         string            `json:"id"`
	Type       string            `json:"type"`
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
	ID         string          `json:"id"`
	AgentID    string          `json:"agent_id"`
	Status     string          `json:"status"`
	StartedAt  *time.Time      `json:"started_at,omitempty"`
	FinishedAt *time.Time      `json:"finished_at,omitempty"`
	Summary    json.RawMessage `json:"summary,omitempty"`
	Error      string          `json:"error_message,omitempty"`
}

func (h *TaskHandler) RegisterRoutes(r *gin.RouterGroup) {
	r.POST("/tasks", h.createTask)
	r.GET("/tasks", h.listTasks)
	r.GET("/tasks/:id", h.getTask)
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
	task := &model.Task{
		ID:        uuid.New(),
		Type:      model.TaskType(req.Type),
		Priority:  req.Priority,
		Payload:   payloadBytes,
		Status:    model.TaskStatusPending,
		Metadata:  req.Metadata,
		CreatedBy: req.CreatedBy,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}
	if err := h.Store.CreateTask(ctx, task); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
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
	return resp
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
