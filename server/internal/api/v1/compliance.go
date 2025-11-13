package v1

import (
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/m-sec-org/d-eyes/server/internal/model"
	"github.com/m-sec-org/d-eyes/server/internal/security"
	"github.com/m-sec-org/d-eyes/server/internal/store"
)

// ComplianceHandler provides CRUD endpoints for frameworks/controls/mappings.
type ComplianceHandler struct {
	Store store.Store
}

func (h *ComplianceHandler) RegisterRoutes(r *gin.RouterGroup) {
	if h == nil || h.Store == nil {
		return
	}
	group := r.Group("/compliance")
	group.GET("/frameworks", h.listFrameworks)
	group.POST("/frameworks", h.createFramework)
	group.POST("/frameworks/:id/controls", h.createControl)
	group.GET("/frameworks/:id/controls", h.listControls)
	group.POST("/controls/:id/mappings", h.createMapping)
	group.GET("/controls/:id/mappings", h.listMappings)
	group.GET("/gaps", h.listGaps)
	group.POST("/findings/:id/remediation", h.addRemediation)
}

func (h *ComplianceHandler) requireAdmin(c *gin.Context) bool {
	principal := security.PrincipalFrom(c)
	if principal.Role == "admin" {
		return true
	}
	c.JSON(http.StatusForbidden, gin.H{"error": "insufficient permissions"})
	return false
}

func (h *ComplianceHandler) listFrameworks(c *gin.Context) {
	items, err := h.Store.ListComplianceFrameworks(c.Request.Context())
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"items": items})
}

func (h *ComplianceHandler) createFramework(c *gin.Context) {
	if !h.requireAdmin(c) {
		return
	}
	var req struct {
		Key         string `json:"key" binding:"required"`
		Title       string `json:"title" binding:"required"`
		Version     string `json:"version"`
		Description string `json:"description"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	framework := &model.ComplianceFramework{Key: req.Key, Title: req.Title, Version: req.Version, Description: req.Description}
	if err := h.Store.CreateComplianceFramework(c.Request.Context(), framework); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusCreated, framework)
}

func (h *ComplianceHandler) listControls(c *gin.Context) {
	frameworkID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid framework id"})
		return
	}
	items, err := h.Store.ListComplianceControls(c.Request.Context(), frameworkID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"items": items})
}

func (h *ComplianceHandler) createControl(c *gin.Context) {
	if !h.requireAdmin(c) {
		return
	}
	frameworkID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid framework id"})
		return
	}
	var req struct {
		Code        string            `json:"code" binding:"required"`
		Title       string            `json:"title" binding:"required"`
		Severity    string            `json:"severity" binding:"required"`
		Description string            `json:"description"`
		References  map[string]string `json:"references"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	control := &model.ComplianceControl{
		FrameworkID: frameworkID,
		Code:        req.Code,
		Title:       req.Title,
		Severity:    req.Severity,
		Description: req.Description,
		References:  req.References,
	}
	if err := h.Store.CreateComplianceControl(c.Request.Context(), control); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusCreated, control)
}

func (h *ComplianceHandler) createMapping(c *gin.Context) {
	if !h.requireAdmin(c) {
		return
	}
	controlID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid control id"})
		return
	}
	var req struct {
		TargetType string            `json:"target_type" binding:"required"`
		TargetRef  string            `json:"target_ref" binding:"required"`
		Metadata   map[string]string `json:"metadata"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	mapping := &model.ControlMapping{
		ControlID:  controlID,
		TargetType: req.TargetType,
		TargetRef:  req.TargetRef,
		Metadata:   req.Metadata,
	}
	if err := h.Store.CreateControlMapping(c.Request.Context(), mapping); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusCreated, mapping)
}

func (h *ComplianceHandler) listMappings(c *gin.Context) {
	controlID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid control id"})
		return
	}
	items, err := h.Store.ListControlMappings(c.Request.Context(), controlID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"items": items})
}

func (h *ComplianceHandler) listGaps(c *gin.Context) {
	var frameworkID uuid.UUID
	if id := c.Query("framework_id"); id != "" {
		parsed, err := uuid.Parse(id)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid framework_id"})
			return
		}
		frameworkID = parsed
	}
	status := c.Query("status")
	items, err := h.Store.ListComplianceFindings(c.Request.Context(), frameworkID, status)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"items": items})
}

func (h *ComplianceHandler) addRemediation(c *gin.Context) {
	if !h.requireAdmin(c) {
		return
	}
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid finding id"})
		return
	}
	var req struct {
		Note   string `json:"note" binding:"required"`
		Status string `json:"status"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	finding, err := h.Store.GetComplianceFinding(c.Request.Context(), id)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
		return
	}
	note := model.RemediationNote{
		Author:    security.PrincipalFrom(c).User,
		Note:      req.Note,
		Timestamp: time.Now(),
	}
	finding.RemediationLogs = append(finding.RemediationLogs, note)
	if req.Status != "" {
		finding.Status = req.Status
	}
	if err := h.Store.UpdateComplianceFinding(c.Request.Context(), finding); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, finding)
}
