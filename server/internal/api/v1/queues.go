package v1

import (
	"net/http"

	"github.com/gin-gonic/gin"

	"github.com/m-sec-org/d-eyes/server/internal/rbac"
	"github.com/m-sec-org/d-eyes/server/internal/scheduler"
	"github.com/m-sec-org/d-eyes/server/internal/security"
)

type QueueHandler struct {
	Scheduler *scheduler.Scheduler
	RBAC      *rbac.Enforcer
}

func (h *QueueHandler) RegisterRoutes(r *gin.RouterGroup) {
	if h == nil || h.Scheduler == nil {
		return
	}
	group := r.Group("/queues")
	group.GET("/summary", h.getSummary)
}

func (h *QueueHandler) getSummary(c *gin.Context) {
	if !h.requirePermission(c, "tasks.read") {
		return
	}
	snapshot := h.Scheduler.QueueSummary()
	statusCounts := make(map[string]int64, len(snapshot.StatusCounts))
	for status, count := range snapshot.StatusCounts {
		statusCounts[string(status)] = count
	}
	c.JSON(http.StatusOK, gin.H{
		"queue_depth":     snapshot.QueueDepth,
		"bas_queue_depth": snapshot.BASQueueDepth,
		"in_flight":       snapshot.InFlight,
		"bas_in_flight":   snapshot.BASInFlight,
		"status_counts":   statusCounts,
		"updated_at":      snapshot.UpdatedAt,
	})
}

func (h *QueueHandler) requirePermission(c *gin.Context, permission string) bool {
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
