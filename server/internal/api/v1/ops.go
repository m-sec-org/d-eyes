package v1

import (
	"io"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/m-sec-org/d-eyes/server/internal/scheduler"
)

// OpsHandler exposes operational utilities (self-heal, DR checks).
type OpsHandler struct {
	Scheduler *scheduler.Scheduler
}

func (h *OpsHandler) RegisterRoutes(r *gin.RouterGroup) {
	if h == nil || h.Scheduler == nil {
		return
	}
	group := r.Group("/ops")
	group.POST("/self-heal", h.triggerSelfHeal)
}

func (h *OpsHandler) triggerSelfHeal(c *gin.Context) {
	if !requireAdmin(c) {
		return
	}
	var body struct {
		AgentID string `json:"agent_id"`
	}
	if err := c.ShouldBindJSON(&body); err != nil && err != io.EOF {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	ctx := c.Request.Context()
	agentID := strings.TrimSpace(body.AgentID)
	var summary map[string]int
	if agentID != "" {
		id, err := uuid.Parse(agentID)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid agent_id"})
			return
		}
		count, err := h.Scheduler.RecoverAgentTasks(ctx, id)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		summary = map[string]int{id.String(): count}
	} else {
		summary = make(map[string]int)
		countMap, err := h.Scheduler.RecoverOfflineAgents(ctx)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		summary = countMap
	}
	c.JSON(http.StatusOK, gin.H{"status": "self-heal triggered", "agents": summary})
}
