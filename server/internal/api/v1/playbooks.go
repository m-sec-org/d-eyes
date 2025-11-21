package v1

import (
	"net/http"
	"strconv"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/m-sec-org/d-eyes/server/internal/model"
	"github.com/m-sec-org/d-eyes/server/internal/playbook"
	"github.com/m-sec-org/d-eyes/server/internal/rbac"
	"github.com/m-sec-org/d-eyes/server/internal/security"
)

type PlaybookHandler struct {
	Manager *playbook.Manager
	Engine  *playbook.Engine
	RBAC    *rbac.Enforcer
}

func (h *PlaybookHandler) RegisterRoutes(r *gin.RouterGroup) {
	if h == nil || h.Manager == nil {
		return
	}
	group := r.Group("/playbooks")
	group.POST("", h.createPlaybook)
	group.GET("", h.listPlaybooks)
	group.GET(":id", h.getPlaybook)
	group.GET(":id/approvals", h.listApprovals)
	group.POST(":id/approvals", h.updateApproval)
	group.POST(":id/activate", h.activatePlaybook)
	group.POST(":id/run", h.runPlaybook)
	group.GET(":id/runs", h.listRuns)
}

func (h *PlaybookHandler) requirePermission(c *gin.Context, permission string) bool {
	if h.RBAC == nil {
		return true
	}
	principal := security.PrincipalFrom(c)
	if h.RBAC.Enforce(principal.Role, permission) {
		return true
	}
	c.JSON(http.StatusForbidden, gin.H{"error": "insufficient permissions"})
	return false
}

func (h *PlaybookHandler) createPlaybook(c *gin.Context) {
	if !h.requirePermission(c, "playbook.create") {
		return
	}
	var req createPlaybookRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	pb := req.toModel(security.PrincipalFrom(c).User)
	if err := h.Manager.Create(c.Request.Context(), pb); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusCreated, pb)
}

func (h *PlaybookHandler) listPlaybooks(c *gin.Context) {
	if !h.requirePermission(c, "playbook.execute") {
		return
	}
	limit := queryLimit(c, 100)
	items, err := h.Manager.List(c.Request.Context(), limit)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"items": items})
}

func (h *PlaybookHandler) getPlaybook(c *gin.Context) {
	if !h.requirePermission(c, "playbook.execute") {
		return
	}
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid playbook id"})
		return
	}
	pb, err := h.Manager.Get(c.Request.Context(), id)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, pb)
}

func (h *PlaybookHandler) listApprovals(c *gin.Context) {
	if !h.requirePermission(c, "playbook.approve") {
		return
	}
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid playbook id"})
		return
	}
	pb, err := h.Manager.Get(c.Request.Context(), id)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"approvals":       pb.Approvals,
		"approval_states": pb.ApprovalStates,
	})
}

func (h *PlaybookHandler) updateApproval(c *gin.Context) {
	if !h.requirePermission(c, "playbook.approve") {
		return
	}
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid playbook id"})
		return
	}
	var body struct {
		Role   string `json:"role" binding:"required"`
		Action string `json:"action" binding:"required"`
		Notes  string `json:"notes"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	actor := security.PrincipalFrom(c).User
	pb, err := h.Manager.UpdateApproval(c.Request.Context(), id, body.Role, actor, body.Action, body.Notes)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, pb)
}

func (h *PlaybookHandler) activatePlaybook(c *gin.Context) {
	if !h.requirePermission(c, "playbook.approve") {
		return
	}
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid playbook id"})
		return
	}
	var req struct {
		Status string `json:"status"`
	}
	if err := c.ShouldBindJSON(&req); err != nil || req.Status == "" {
		req.Status = "active"
	}
	pb, err := h.Manager.SetStatus(c.Request.Context(), id, req.Status, security.PrincipalFrom(c).User)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, pb)
}

func (h *PlaybookHandler) runPlaybook(c *gin.Context) {
	if !h.requirePermission(c, "playbook.execute") {
		return
	}
	if h.Engine == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "playbook engine disabled"})
		return
	}
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid playbook id"})
		return
	}
	pb, err := h.Manager.Get(c.Request.Context(), id)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
		return
	}
	if strings.ToLower(pb.Status) != "active" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "playbook not active"})
		return
	}
	var req runPlaybookRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	event := playbook.TriggerEvent{Type: req.Type, Attributes: req.Attributes, Payload: req.Payload}
	h.Engine.ExecuteManual(pb, event)
	c.JSON(http.StatusAccepted, gin.H{"status": "scheduled"})
}

func (h *PlaybookHandler) listRuns(c *gin.Context) {
	if !h.requirePermission(c, "playbook.execute") {
		return
	}
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid playbook id"})
		return
	}
	limit := queryLimit(c, 50)
	runs, err := h.Manager.ListRuns(c.Request.Context(), id, limit)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"items": runs})
}

type createPlaybookRequest struct {
	Name        string                   `json:"name" binding:"required"`
	Description string                   `json:"description"`
	Trigger     model.PlaybookTrigger    `json:"trigger" binding:"required"`
	Conditions  []string                 `json:"conditions"`
	Approvals   []model.PlaybookApproval `json:"approvals"`
	Actions     []model.PlaybookAction   `json:"actions" binding:"required"`
	Rollback    []model.PlaybookAction   `json:"rollback"`
}

func (r createPlaybookRequest) toModel(user string) *model.Playbook {
	return &model.Playbook{
		Name:        r.Name,
		Description: r.Description,
		Trigger:     r.Trigger,
		Conditions:  r.Conditions,
		Approvals:   r.Approvals,
		Actions:     r.Actions,
		Rollback:    r.Rollback,
		Status:      "draft",
		CreatedBy:   user,
	}
}

type runPlaybookRequest struct {
	Type       string            `json:"type" binding:"required"`
	Attributes map[string]string `json:"attributes"`
	Payload    interface{}       `json:"payload"`
}

func queryLimit(c *gin.Context, max int) int {
	if max <= 0 {
		max = 50
	}
	limit := max
	if v := c.Query("limit"); v != "" {
		if parsed, err := strconv.Atoi(v); err == nil && parsed > 0 && parsed <= max {
			limit = parsed
		}
	}
	return limit
}
