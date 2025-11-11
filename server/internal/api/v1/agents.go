package v1

import (
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/m-sec-org/d-eyes/server/internal/rbac"
	"github.com/m-sec-org/d-eyes/server/internal/security"
	"github.com/m-sec-org/d-eyes/server/internal/store"
)

// AgentHandler exposes read/write endpoints for agent registry data.
type AgentHandler struct {
	Store store.Store
	RBAC  *rbac.Enforcer
}

func (h *AgentHandler) RegisterRoutes(r *gin.RouterGroup) {
	if h == nil || h.Store == nil {
		return
	}
	group := r.Group("/agents")
	group.GET("", h.listAgents)
	group.PATCH(":id/labels", h.updateLabels)
}

type agentResponse struct {
	ID            string            `json:"id"`
	Name          string            `json:"name"`
	Status        string            `json:"status"`
	Platform      string            `json:"platform"`
	Version       string            `json:"version"`
	Capabilities  []string          `json:"capabilities"`
	Labels        map[string]string `json:"labels"`
	LastHeartbeat string            `json:"last_heartbeat"`
}

func (h *AgentHandler) listAgents(c *gin.Context) {
	agents, err := h.Store.ListAgents(c.Request.Context())
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	statusFilter := parseCSV(c.Query("status"))
	capability := strings.TrimSpace(c.Query("capability"))
	tag := strings.TrimSpace(c.Query("tag"))
	result := make([]agentResponse, 0, len(agents))
	for _, agent := range agents {
		if len(statusFilter) > 0 {
			if _, ok := statusFilter[strings.ToLower(string(agent.Status))]; !ok {
				continue
			}
		}
		if capability != "" && !contains(agent.Capabilities, capability) {
			continue
		}
		if tag != "" {
			if agent.Labels == nil {
				continue
			}
			found := false
			for _, v := range agent.Labels {
				if v == tag {
					found = true
					break
				}
			}
			if !found {
				continue
			}
		}
		resp := agentResponse{
			ID:            agent.ID.String(),
			Name:          agent.Name,
			Status:        string(agent.Status),
			Platform:      agent.Platform,
			Version:       agent.Version,
			Capabilities:  append([]string(nil), agent.Capabilities...),
			Labels:        cloneStringMap(agent.Labels),
			LastHeartbeat: agent.LastHeartbeat.Format(timeLayout),
		}
		result = append(result, resp)
	}
	c.JSON(http.StatusOK, result)
}

func (h *AgentHandler) updateLabels(c *gin.Context) {
	if h.RBAC != nil {
		principal := security.PrincipalFrom(c)
		if !h.RBAC.Enforce(principal.Role, "agents.update") {
			c.JSON(http.StatusForbidden, gin.H{"error": "insufficient permissions"})
			return
		}
	}
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid agent id"})
		return
	}
	var body struct {
		Labels map[string]string `json:"labels"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if err := h.Store.UpdateAgentMetadata(c.Request.Context(), id, body.Labels); err != nil {
		if err == store.ErrNotFound {
			c.JSON(http.StatusNotFound, gin.H{"error": "agent not found"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.Status(http.StatusNoContent)
}

func parseCSV(raw string) map[string]struct{} {
	result := make(map[string]struct{})
	parts := strings.Split(raw, ",")
	for _, part := range parts {
		p := strings.ToLower(strings.TrimSpace(part))
		if p != "" {
			result[p] = struct{}{}
		}
	}
	return result
}

func contains(list []string, needle string) bool {
	for _, item := range list {
		if strings.EqualFold(item, needle) {
			return true
		}
	}
	return false
}

func cloneStringMap(src map[string]string) map[string]string {
	if len(src) == 0 {
		return nil
	}
	dst := make(map[string]string, len(src))
	for k, v := range src {
		dst[k] = v
	}
	return dst
}

const timeLayout = time.RFC3339
