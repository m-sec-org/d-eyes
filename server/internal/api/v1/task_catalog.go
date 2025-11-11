package v1

import (
	"context"
	"errors"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"

	"github.com/m-sec-org/d-eyes/server/internal/taskcatalog"
)

// TaskCatalogHandler exposes CRUD endpoints for task types & profiles.
type TaskCatalogHandler struct {
	Catalog *taskcatalog.Manager
}

// RegisterRoutes wires the handler under /api/v1.
func (h *TaskCatalogHandler) RegisterRoutes(r *gin.RouterGroup) {
	if h == nil || h.Catalog == nil {
		return
	}
	r.GET("/task-types", h.listTaskTypes)
	r.POST("/task-types", h.createTaskType)
	r.PUT("/task-types/:name", h.updateTaskType)
	r.DELETE("/task-types/:name", h.deleteTaskType)

	r.GET("/task-profiles", h.listTaskProfiles)
	r.POST("/task-profiles", h.createTaskProfile)
	r.GET("/task-profiles/:id", h.getTaskProfile)
	r.PUT("/task-profiles/:id", h.updateTaskProfile)
	r.DELETE("/task-profiles/:id", h.deleteTaskProfile)
}

func (h *TaskCatalogHandler) listTaskTypes(c *gin.Context) {
	items, err := h.Catalog.ListTaskTypes(c.Request.Context())
	if err != nil && !isContextCanceled(err) {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, items)
}

func (h *TaskCatalogHandler) createTaskType(c *gin.Context) {
	var body taskcatalog.TaskType
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	result, err := h.Catalog.CreateTaskType(c.Request.Context(), body)
	if err != nil {
		status := http.StatusBadRequest
		if !isValidationError(err) {
			status = http.StatusInternalServerError
		}
		c.JSON(status, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusCreated, result)
}

func (h *TaskCatalogHandler) updateTaskType(c *gin.Context) {
	var body taskcatalog.TaskType
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	result, err := h.Catalog.UpdateTaskType(c.Request.Context(), c.Param("name"), body)
	if err != nil {
		status := mapTaskCatalogError(err)
		c.JSON(status, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, result)
}

func (h *TaskCatalogHandler) deleteTaskType(c *gin.Context) {
	if err := h.Catalog.DeleteTaskType(c.Request.Context(), c.Param("name")); err != nil {
		status := mapTaskCatalogError(err)
		c.JSON(status, gin.H{"error": err.Error()})
		return
	}
	c.Status(http.StatusNoContent)
}

func (h *TaskCatalogHandler) listTaskProfiles(c *gin.Context) {
	taskType := c.Query("task_type")
	items, err := h.Catalog.ListTaskProfiles(c.Request.Context(), taskType)
	if err != nil && !isContextCanceled(err) {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, items)
}

func (h *TaskCatalogHandler) createTaskProfile(c *gin.Context) {
	var body taskcatalog.TaskProfile
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	result, err := h.Catalog.CreateTaskProfile(c.Request.Context(), body)
	if err != nil {
		status := mapTaskCatalogError(err)
		c.JSON(status, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusCreated, result)
}

func (h *TaskCatalogHandler) getTaskProfile(c *gin.Context) {
	result, err := h.Catalog.GetTaskProfile(c.Request.Context(), c.Param("id"))
	if err != nil {
		status := mapTaskCatalogError(err)
		c.JSON(status, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, result)
}

func (h *TaskCatalogHandler) updateTaskProfile(c *gin.Context) {
	var body taskcatalog.TaskProfile
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	result, err := h.Catalog.UpdateTaskProfile(c.Request.Context(), c.Param("id"), body)
	if err != nil {
		status := mapTaskCatalogError(err)
		c.JSON(status, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, result)
}

func (h *TaskCatalogHandler) deleteTaskProfile(c *gin.Context) {
	if err := h.Catalog.DeleteTaskProfile(c.Request.Context(), c.Param("id")); err != nil {
		status := mapTaskCatalogError(err)
		c.JSON(status, gin.H{"error": err.Error()})
		return
	}
	c.Status(http.StatusNoContent)
}

func mapTaskCatalogError(err error) int {
	if err == nil {
		return http.StatusOK
	}
	switch err {
	case taskcatalog.ErrUnknownTaskType:
		return http.StatusNotFound
	case taskcatalog.ErrUnknownProfile:
		return http.StatusNotFound
	default:
		if isValidationError(err) {
			return http.StatusBadRequest
		}
		return http.StatusInternalServerError
	}
}

func isValidationError(err error) bool {
	if err == nil {
		return false
	}
	lower := strings.ToLower(err.Error())
	return strings.Contains(lower, "required") || strings.Contains(lower, "invalid") || strings.Contains(lower, "expects")
}

func isContextCanceled(err error) bool {
	if err == nil {
		return false
	}
	return errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded)
}
