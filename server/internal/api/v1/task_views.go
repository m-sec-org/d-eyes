package v1

import (
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/m-sec-org/d-eyes/server/internal/model"
	"github.com/m-sec-org/d-eyes/server/internal/rbac"
	"github.com/m-sec-org/d-eyes/server/internal/security"
	"github.com/m-sec-org/d-eyes/server/internal/store"
)

type TaskViewHandler struct {
	Store store.Store
	RBAC  *rbac.Enforcer
}

func (h *TaskViewHandler) RegisterRoutes(r *gin.RouterGroup) {
	if h == nil || h.Store == nil {
		return
	}
	group := r.Group("/task-views")
	group.GET("", h.listViews)
	group.POST("", h.createView)
	group.PUT("/:id", h.updateView)
	group.DELETE("/:id", h.deleteView)
}

func (h *TaskViewHandler) listViews(c *gin.Context) {
	if !h.requirePermission(c, "tasks.read") {
		return
	}
	owner := security.PrincipalFrom(c).User
	views, err := h.Store.ListTaskViews(c.Request.Context(), owner)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	resp := make([]taskViewResponse, 0, len(views))
	for _, view := range views {
		resp = append(resp, newTaskViewResponse(view))
	}
	c.JSON(http.StatusOK, gin.H{"views": resp})
}

func (h *TaskViewHandler) createView(c *gin.Context) {
	if !h.requirePermission(c, "tasks.read") {
		return
	}
	var req taskViewRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if err := req.validate(); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	principal := security.PrincipalFrom(c)
	view := &model.TaskView{
		ID:        uuid.New(),
		Name:      strings.TrimSpace(req.Name),
		Owner:     principal.User,
		Filters:   req.Filters,
		PageSize:  clampViewPageSize(req.PageSize),
		IsDefault: req.IsDefault,
	}
	if view.Filters == nil {
		view.Filters = map[string]interface{}{}
	}
	if err := h.Store.CreateTaskView(c.Request.Context(), view); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusCreated, newTaskViewResponse(view))
}

func (h *TaskViewHandler) updateView(c *gin.Context) {
	if !h.requirePermission(c, "tasks.read") {
		return
	}
	id, err := uuid.Parse(strings.TrimSpace(c.Param("id")))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid id"})
		return
	}
	var req taskViewRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if err := req.validate(); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	principal := security.PrincipalFrom(c)
	view := &model.TaskView{
		ID:        id,
		Name:      strings.TrimSpace(req.Name),
		Owner:     principal.User,
		Filters:   req.Filters,
		PageSize:  clampViewPageSize(req.PageSize),
		IsDefault: req.IsDefault,
	}
	if view.Filters == nil {
		view.Filters = map[string]interface{}{}
	}
	if err := h.Store.UpdateTaskView(c.Request.Context(), view); err != nil {
		if err == store.ErrNotFound {
			c.JSON(http.StatusNotFound, gin.H{"error": "task view not found"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, newTaskViewResponse(view))
}

func (h *TaskViewHandler) deleteView(c *gin.Context) {
	if !h.requirePermission(c, "tasks.read") {
		return
	}
	id, err := uuid.Parse(strings.TrimSpace(c.Param("id")))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid id"})
		return
	}
	principal := security.PrincipalFrom(c)
	if err := h.Store.DeleteTaskView(c.Request.Context(), id, principal.User); err != nil {
		if err == store.ErrNotFound {
			c.JSON(http.StatusNotFound, gin.H{"error": "task view not found"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.Status(http.StatusNoContent)
}

func (h *TaskViewHandler) requirePermission(c *gin.Context, permission string) bool {
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

type taskViewRequest struct {
	Name      string                 `json:"name" binding:"required"`
	Filters   map[string]interface{} `json:"filters" binding:"required"`
	PageSize  int                    `json:"page_size"`
	IsDefault bool                   `json:"is_default"`
}

func (r *taskViewRequest) validate() error {
	if strings.TrimSpace(r.Name) == "" {
		return fmt.Errorf("name required")
	}
	if len(r.Filters) == 0 {
		return fmt.Errorf("filters required")
	}
	return nil
}

type taskViewResponse struct {
	ID        string                 `json:"id"`
	Name      string                 `json:"name"`
	Filters   map[string]interface{} `json:"filters"`
	PageSize  int                    `json:"page_size"`
	IsDefault bool                   `json:"is_default"`
	CreatedAt time.Time              `json:"created_at"`
	UpdatedAt time.Time              `json:"updated_at"`
}

func newTaskViewResponse(view *model.TaskView) taskViewResponse {
	return taskViewResponse{
		ID:        view.ID.String(),
		Name:      view.Name,
		Filters:   view.Filters,
		PageSize:  view.PageSize,
		IsDefault: view.IsDefault,
		CreatedAt: view.CreatedAt,
		UpdatedAt: view.UpdatedAt,
	}
}

func clampViewPageSize(size int) int {
	switch {
	case size <= 0:
		return 50
	case size > 200:
		return 200
	default:
		return size
	}
}
