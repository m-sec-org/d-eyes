package v1

import (
	"errors"
	"net/http"
	"os"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/m-sec-org/d-eyes/server/internal/templates"
)

// TemplateHandler 提供模板管理 API。
type TemplateHandler struct {
	Manager *templates.Manager
}

func (h *TemplateHandler) RegisterRoutes(r *gin.RouterGroup) {
	if h == nil || h.Manager == nil {
		return
	}
	group := r.Group("/task-templates")
	group.GET("", h.listTemplates)
	group.POST("", h.createTemplate)
	group.GET("/:id", h.getTemplate)
	group.PUT("/:id", h.updateTemplate)
	group.DELETE("/:id", h.deleteTemplate)
	group.POST("/:id/deploy", h.deployTemplate)
}

type templateResponse struct {
	ID          string              `json:"id"`
	Name        string              `json:"name"`
	Description string              `json:"description,omitempty"`
	TaskType    string              `json:"task_type"`
	Profile     string              `json:"profile,omitempty"`
	Flags       map[string]any      `json:"flags,omitempty"`
	Metadata    map[string]string   `json:"metadata,omitempty"`
	Targets     []string            `json:"targets,omitempty"`
	Priority    int                 `json:"priority,omitempty"`
	CreatedBy   string              `json:"created_by,omitempty"`
	CreatedAt   time.Time           `json:"created_at"`
	UpdatedAt   time.Time           `json:"updated_at"`
	Schedule    *templates.Schedule `json:"schedule,omitempty"`
}

type createTemplateRequest struct {
	Name        string              `json:"name"`
	Description string              `json:"description"`
	TaskType    string              `json:"task_type"`
	Profile     string              `json:"profile"`
	Flags       map[string]any      `json:"flags"`
	Metadata    map[string]string   `json:"metadata"`
	Targets     []string            `json:"targets"`
	Priority    int                 `json:"priority"`
	CreatedBy   string              `json:"created_by"`
	Schedule    *templates.Schedule `json:"schedule"`
}

type updateTemplateRequest createTemplateRequest

type deployTemplateRequest struct {
	Name        string            `json:"name"`
	Description string            `json:"description"`
	Profile     string            `json:"profile"`
	Flags       map[string]any    `json:"flags"`
	Metadata    map[string]string `json:"metadata"`
	Targets     []string          `json:"targets"`
	Priority    *int              `json:"priority"`
	CreatedBy   string            `json:"created_by"`
}

func (h *TemplateHandler) listTemplates(c *gin.Context) {
	items, err := h.Manager.ListTemplates(c.Request.Context())
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	resp := make([]templateResponse, 0, len(items))
	for _, item := range items {
		resp = append(resp, toTemplateResponse(item))
	}
	c.JSON(http.StatusOK, resp)
}

func (h *TemplateHandler) createTemplate(c *gin.Context) {
	var req createTemplateRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	tmpl, err := h.Manager.CreateTemplate(c.Request.Context(), templates.Template{
		Name:        req.Name,
		Description: req.Description,
		TaskType:    req.TaskType,
		Profile:     req.Profile,
		Flags:       req.Flags,
		Metadata:    req.Metadata,
		Targets:     req.Targets,
		Priority:    req.Priority,
		CreatedBy:   req.CreatedBy,
		Schedule:    req.Schedule,
	})
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusCreated, toTemplateResponse(*tmpl))
}

func (h *TemplateHandler) getTemplate(c *gin.Context) {
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid template id"})
		return
	}
	tmpl, err := h.Manager.GetTemplate(c.Request.Context(), id)
	if err != nil {
		status := http.StatusInternalServerError
		if errors.Is(err, os.ErrNotExist) {
			status = http.StatusNotFound
		}
		c.JSON(status, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, toTemplateResponse(*tmpl))
}

func (h *TemplateHandler) updateTemplate(c *gin.Context) {
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid template id"})
		return
	}
	var req updateTemplateRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	tmpl, err := h.Manager.UpdateTemplate(c.Request.Context(), id, templates.Template{
		Name:        req.Name,
		Description: req.Description,
		TaskType:    req.TaskType,
		Profile:     req.Profile,
		Flags:       req.Flags,
		Metadata:    req.Metadata,
		Targets:     req.Targets,
		Priority:    req.Priority,
		CreatedBy:   req.CreatedBy,
		Schedule:    req.Schedule,
	})
	if err != nil {
		status := http.StatusBadRequest
		if errors.Is(err, os.ErrNotExist) {
			status = http.StatusNotFound
		}
		c.JSON(status, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, toTemplateResponse(*tmpl))
}

func (h *TemplateHandler) deleteTemplate(c *gin.Context) {
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid template id"})
		return
	}
	if err := h.Manager.DeleteTemplate(c.Request.Context(), id); err != nil {
		status := http.StatusInternalServerError
		if errors.Is(err, os.ErrNotExist) {
			status = http.StatusNotFound
		}
		c.JSON(status, gin.H{"error": err.Error()})
		return
	}
	c.Status(http.StatusNoContent)
}

func (h *TemplateHandler) deployTemplate(c *gin.Context) {
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid template id"})
		return
	}
	var req deployTemplateRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	result, err := h.Manager.DeployTemplate(c.Request.Context(), id, templates.DeployRequest{
		Name:        req.Name,
		Description: req.Description,
		Profile:     req.Profile,
		Flags:       req.Flags,
		Metadata:    req.Metadata,
		Targets:     req.Targets,
		Priority:    req.Priority,
		CreatedBy:   req.CreatedBy,
	})
	if err != nil {
		status := http.StatusInternalServerError
		if errors.Is(err, os.ErrNotExist) {
			status = http.StatusNotFound
		}
		c.JSON(status, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, result)
}

func toTemplateResponse(t templates.Template) templateResponse {
	return templateResponse{
		ID:          t.ID.String(),
		Name:        t.Name,
		Description: t.Description,
		TaskType:    t.TaskType,
		Profile:     t.Profile,
		Flags:       t.Flags,
		Metadata:    t.Metadata,
		Targets:     t.Targets,
		Priority:    t.Priority,
		CreatedBy:   t.CreatedBy,
		CreatedAt:   t.CreatedAt,
		UpdatedAt:   t.UpdatedAt,
		Schedule:    t.Schedule,
	}
}
