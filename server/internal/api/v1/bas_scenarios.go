package v1

import (
	"context"
	"errors"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/m-sec-org/d-eyes/server/internal/auditlog"
	"github.com/m-sec-org/d-eyes/server/internal/basscenarios"
	"github.com/m-sec-org/d-eyes/server/internal/rbac"
	"github.com/m-sec-org/d-eyes/server/internal/security"
)

// BASScenarioHandler exposes REST APIs for BAS scenario management.
type BASScenarioHandler struct {
	Manager *basscenarios.Manager
	RBAC    *rbac.Enforcer
	Audit   *auditlog.Manager
}

func (h *BASScenarioHandler) requirePermission(c *gin.Context, perm string) bool {
	if h.RBAC == nil {
		return true
	}
	principal := security.PrincipalFrom(c)
	if h.RBAC.Enforce(principal.Role, perm) {
		return true
	}
	c.JSON(http.StatusForbidden, gin.H{"error": "insufficient permissions"})
	return false
}

func (h *BASScenarioHandler) recordAudit(c *gin.Context, action, resource, result string, metadata map[string]string) {
	if h.Audit == nil {
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

// RegisterRoutes wires BAS scenario routes.
func (h *BASScenarioHandler) RegisterRoutes(r *gin.RouterGroup) {
	if h == nil || h.Manager == nil {
		return
	}
	group := r.Group("/bas-scenarios")
	group.GET("", h.listScenarios)
	group.POST("", h.createScenario)
	group.GET("/:id", h.getScenario)
	group.PUT("/:id", h.updateScenario)
	group.DELETE("/:id", h.deleteScenario)
	group.POST("/:id/approve", h.approveScenario)
	group.POST("/:id/activate", h.activateScenario)
	group.POST("/:id/deactivate", h.deactivateScenario)
}

func (h *BASScenarioHandler) listScenarios(c *gin.Context) {
	items, err := h.Manager.List(c.Request.Context())
	if err != nil && !isContextError(err) {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, items)
}

func (h *BASScenarioHandler) createScenario(c *gin.Context) {
	if !h.requirePermission(c, "bas.manage") {
		return
	}
	var req scenarioRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	entity := req.toScenario()
	created, err := h.Manager.Create(c.Request.Context(), entity)
	if err != nil {
		c.JSON(statusFromScenarioError(err), gin.H{"error": err.Error()})
		return
	}
	h.recordAudit(c, "bas.scenario.create", "bas:"+created.ID.String(), "accepted", map[string]string{"status": string(created.Status)})
	c.JSON(http.StatusCreated, created)
}

func (h *BASScenarioHandler) getScenario(c *gin.Context) {
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid id"})
		return
	}
	item, err := h.Manager.Get(c.Request.Context(), id)
	if err != nil {
		c.JSON(statusFromScenarioError(err), gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, item)
}

func (h *BASScenarioHandler) updateScenario(c *gin.Context) {
	if !h.requirePermission(c, "bas.manage") {
		return
	}
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid id"})
		return
	}
	var req scenarioRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	entity := req.toScenario()
	updated, err := h.Manager.Update(c.Request.Context(), id, entity)
	if err != nil {
		c.JSON(statusFromScenarioError(err), gin.H{"error": err.Error()})
		return
	}
	h.recordAudit(c, "bas.scenario.update", "bas:"+id.String(), "accepted", nil)
	c.JSON(http.StatusOK, updated)
}

func (h *BASScenarioHandler) deleteScenario(c *gin.Context) {
	if !h.requirePermission(c, "bas.manage") {
		return
	}
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid id"})
		return
	}
	if err := h.Manager.Delete(c.Request.Context(), id); err != nil {
		c.JSON(statusFromScenarioError(err), gin.H{"error": err.Error()})
		return
	}
	h.recordAudit(c, "bas.scenario.delete", "bas:"+id.String(), "accepted", nil)
	c.Status(http.StatusNoContent)
}

func (h *BASScenarioHandler) approveScenario(c *gin.Context) {
	if !h.requirePermission(c, "bas.approve") {
		return
	}
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid id"})
		return
	}
	var body struct {
		ApprovedBy string `json:"approved_by" binding:"required"`
		Notes      string `json:"notes"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	item, err := h.Manager.Approve(c.Request.Context(), id, body.ApprovedBy, body.Notes)
	if err != nil {
		c.JSON(statusFromScenarioError(err), gin.H{"error": err.Error()})
		return
	}
	h.recordAudit(c, "bas.scenario.approve", "bas:"+id.String(), "accepted", map[string]string{"notes": body.Notes})
	c.JSON(http.StatusOK, item)
}

func (h *BASScenarioHandler) activateScenario(c *gin.Context) {
	if !h.requirePermission(c, "bas.activate") {
		return
	}
	h.setStatus(c, basscenarios.StatusActive)
}

func (h *BASScenarioHandler) deactivateScenario(c *gin.Context) {
	if !h.requirePermission(c, "bas.activate") {
		return
	}
	h.setStatus(c, basscenarios.StatusDisabled)
}

func (h *BASScenarioHandler) setStatus(c *gin.Context, status basscenarios.ScenarioStatus) {
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid id"})
		return
	}
	item, err := h.Manager.SetStatus(c.Request.Context(), id, status)
	if err != nil {
		c.JSON(statusFromScenarioError(err), gin.H{"error": err.Error()})
		return
	}
	h.recordAudit(c, "bas.scenario.status", "bas:"+id.String(), string(status), nil)
	c.JSON(http.StatusOK, item)
}

type scenarioRequest struct {
	Name              string                      `json:"name" binding:"required"`
	Description       string                      `json:"description"`
	Tags              []string                    `json:"tags"`
	Steps             []basscenarios.ScenarioStep `json:"steps" binding:"required"`
	ResourceLimits    basscenarios.ResourceLimits `json:"resource_limits"`
	NetworkBoundaries []string                    `json:"network_boundaries"`
	RequiresApproval  bool                        `json:"requires_approval"`
	CreatedBy         string                      `json:"created_by"`
	UpdatedBy         string                      `json:"updated_by"`
}

func (r scenarioRequest) toScenario() basscenarios.Scenario {
	return basscenarios.Scenario{
		Name:              r.Name,
		Description:       r.Description,
		Tags:              r.Tags,
		Steps:             r.Steps,
		ResourceLimits:    r.ResourceLimits,
		NetworkBoundaries: r.NetworkBoundaries,
		RequiresApproval:  r.RequiresApproval,
		CreatedBy:         r.CreatedBy,
		UpdatedBy:         r.UpdatedBy,
	}
}

func statusFromScenarioError(err error) int {
	if err == nil {
		return http.StatusOK
	}
	switch {
	case errors.Is(err, basscenarios.ErrNotFound):
		return http.StatusNotFound
	case errors.Is(err, basscenarios.ErrInvalidStatusTransition):
		return http.StatusBadRequest
	default:
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return http.StatusRequestTimeout
		}
		return http.StatusBadRequest
	}
}

func isContextError(err error) bool {
	return errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded)
}
