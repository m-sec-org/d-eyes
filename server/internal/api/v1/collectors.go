package v1

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/m-sec-org/d-eyes/server/internal/auditlog"
	"github.com/m-sec-org/d-eyes/server/internal/collectorctrl"
	"github.com/m-sec-org/d-eyes/server/internal/metrics"
	"github.com/m-sec-org/d-eyes/server/internal/model"
	"github.com/m-sec-org/d-eyes/server/internal/rbac"
	"github.com/m-sec-org/d-eyes/server/internal/security"
	"github.com/m-sec-org/d-eyes/server/internal/store"
)

// CollectorHandler exposes REST/SSE endpoints for collector config/state.
type CollectorHandler struct {
	Store            store.Store
	Hub              *collectorctrl.Hub
	RBAC             *rbac.Enforcer
	Audit            *auditlog.Manager
	Metrics          *metrics.Metrics
	AllowedProviders []string
	AllowedProbes    []string

	allowedProviders map[string]struct{}
	allowedProbes    map[string]struct{}
}

// RegisterRoutes wires HTTP routes.
func (h *CollectorHandler) RegisterRoutes(r *gin.RouterGroup) {
	if h == nil {
		return
	}
	h.initAllowlists()
	r.POST("/collector/configs", h.upsertConfig)
	r.GET("/collector/configs", h.listConfigs)
	r.GET("/collector/configs/:agent_id", h.getConfig)
	r.POST("/collector/status", h.upsertStatus)
	r.GET("/collector/status", h.listStatuses)
	r.GET("/collector/status/stream", h.statusStream)
}

type collectorConfigRequest struct {
	AgentID   string          `json:"agent_id"`
	Version   *int64          `json:"version"`
	Config    json.RawMessage `json:"config"`
	UpdatedBy string          `json:"updated_by"`
}

func (h *CollectorHandler) upsertConfig(c *gin.Context) {
	if h.Store == nil {
		c.JSON(http.StatusNotImplemented, gin.H{"error": "store unavailable"})
		return
	}
	if h.RBAC != nil {
		principal := security.PrincipalFrom(c)
		if !h.RBAC.Enforce(principal.Role, "collector.config.write") {
			c.JSON(http.StatusForbidden, gin.H{"error": "insufficient permissions"})
			return
		}
	}
	var req collectorConfigRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid payload", "details": err.Error()})
		return
	}
	if req.AgentID == "" || len(req.Config) == 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "agent_id and config required"})
		return
	}
	agentID, err := uuid.Parse(req.AgentID)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid agent_id"})
		return
	}
	if err := h.validateCollectorConfigPayload(req.Config); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	version := int64(0)
	if req.Version != nil {
		version = *req.Version
	}
	principal := security.PrincipalFrom(c)
	updatedBy := strings.TrimSpace(req.UpdatedBy)
	if updatedBy == "" {
		updatedBy = principal.User
	}
	snapshot := &model.CollectorConfigSnapshot{
		AgentID:   agentID,
		Version:   version,
		Config:    req.Config,
		UpdatedBy: updatedBy,
		UpdatedAt: time.Now().UTC(),
	}
	if err := h.Store.UpsertCollectorConfig(c.Request.Context(), snapshot); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to persist config"})
		return
	}
	cfg, _ := h.Store.GetCollectorConfig(c.Request.Context(), agentID)
	if h.Audit != nil {
		h.Audit.Record(auditlog.Event{
			Actor:    principal.User,
			Role:     principal.Role,
			Action:   "collector.config.update",
			Result:   "success",
			Resource: agentID.String(),
			Metadata: map[string]string{
				"version": strconv.FormatInt(cfg.Version, 10),
			},
		})
	}
	if h.Metrics != nil {
		h.Metrics.CollectorConfigUpdates.Inc()
	}
	c.JSON(http.StatusOK, cfg)
}

func (h *CollectorHandler) listConfigs(c *gin.Context) {
	if h.Store == nil {
		c.JSON(http.StatusNotImplemented, gin.H{"error": "store unavailable"})
		return
	}
	if h.RBAC != nil {
		principal := security.PrincipalFrom(c)
		if !h.RBAC.Enforce(principal.Role, "collector.config.read") {
			c.JSON(http.StatusForbidden, gin.H{"error": "insufficient permissions"})
			return
		}
	}
	cfgs, err := h.Store.ListCollectorConfigs(c.Request.Context())
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to list configs"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"items": cfgs})
}

func (h *CollectorHandler) getConfig(c *gin.Context) {
	if h.Store == nil {
		c.JSON(http.StatusNotImplemented, gin.H{"error": "store unavailable"})
		return
	}
	if h.RBAC != nil {
		principal := security.PrincipalFrom(c)
		if !h.RBAC.Enforce(principal.Role, "collector.config.read") {
			c.JSON(http.StatusForbidden, gin.H{"error": "insufficient permissions"})
			return
		}
	}
	agentID, err := uuid.Parse(c.Param("agent_id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid agent_id"})
		return
	}
	cfg, err := h.Store.GetCollectorConfig(c.Request.Context(), agentID)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			c.JSON(http.StatusNotFound, gin.H{"error": "config not found"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to load config"})
		return
	}
	c.JSON(http.StatusOK, cfg)
}

type collectorStatusRequest struct {
	AgentID   string            `json:"agent_id" binding:"required"`
	AgentName string            `json:"agent_name"`
	Version   int64             `json:"version"`
	State     string            `json:"state"`
	LastError string            `json:"last_error"`
	Stats     map[string]any    `json:"stats"`
	Metadata  map[string]string `json:"metadata"`
}

func (h *CollectorHandler) upsertStatus(c *gin.Context) {
	if h.Store == nil {
		c.JSON(http.StatusNotImplemented, gin.H{"error": "store unavailable"})
		return
	}
	if h.RBAC != nil {
		principal := security.PrincipalFrom(c)
		if !h.RBAC.Enforce(principal.Role, "collector.status.write") {
			c.JSON(http.StatusForbidden, gin.H{"error": "insufficient permissions"})
			return
		}
	}
	var req collectorStatusRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid payload", "details": err.Error()})
		return
	}
	if req.AgentID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "agent_id required"})
		return
	}
	agentID, err := uuid.Parse(req.AgentID)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid agent_id"})
		return
	}
	status := &model.CollectorStatusSnapshot{
		AgentID:   agentID,
		AgentName: req.AgentName,
		Version:   req.Version,
		State:     req.State,
		LastError: req.LastError,
		Stats:     req.Stats,
		Metadata:  req.Metadata,
		UpdatedAt: time.Now().UTC(),
	}
	if err := h.Store.UpsertCollectorStatus(c.Request.Context(), status); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to persist status"})
		return
	}
	alert := deriveAlertLevel(status.Stats, defaultAlertThresholds)
	if h.Metrics != nil {
		h.Metrics.CollectorStatusAlerts.WithLabelValues(tenantFromMetadata(status.Metadata), alert).Inc()
	}
	if h.Hub != nil {
		h.Hub.Publish(*status)
	}
	c.JSON(http.StatusOK, gin.H{"status": "ok"})
}

func (h *CollectorHandler) listStatuses(c *gin.Context) {
	if h.Store == nil {
		c.JSON(http.StatusNotImplemented, gin.H{"error": "store unavailable"})
		return
	}
	if h.RBAC != nil {
		principal := security.PrincipalFrom(c)
		if !h.RBAC.Enforce(principal.Role, "collector.status.read") {
			c.JSON(http.StatusForbidden, gin.H{"error": "insufficient permissions"})
			return
		}
	}
	tenant := strings.TrimSpace(c.Query("tenant"))
	state := strings.ToLower(strings.TrimSpace(c.Query("state")))
	thresholds := parseAlertThresholds(c)
	statuses, err := h.Store.ListCollectorStatuses(c.Request.Context())
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to list statuses"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"items": filterStatuses(statuses, tenant, state, thresholds)})
}

func (h *CollectorHandler) statusStream(c *gin.Context) {
	if h.Hub == nil {
		c.Status(http.StatusNotImplemented)
		return
	}
	if h.RBAC != nil {
		principal := security.PrincipalFrom(c)
		if !h.RBAC.Enforce(principal.Role, "collector.status.read") {
			c.JSON(http.StatusForbidden, gin.H{"error": "insufficient permissions"})
			return
		}
	}
	tenant := strings.TrimSpace(c.Query("tenant"))
	state := strings.ToLower(strings.TrimSpace(c.Query("state")))
	thresholds := parseAlertThresholds(c)
	ctx := c.Request.Context()
	stream, cancel := h.Hub.Subscribe(ctx)
	defer cancel()

	flusher, ok := c.Writer.(http.Flusher)
	if !ok {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "streaming not supported"})
		return
	}
	c.Writer.Header().Set("Content-Type", "text/event-stream")
	c.Writer.Header().Set("Cache-Control", "no-cache")
	c.Writer.Header().Set("Connection", "keep-alive")
	flusher.Flush()

	for {
		select {
		case status, ok := <-stream:
			if !ok {
				return
			}
			if tenant != "" && !matchesTenant(status.Metadata, tenant) {
				continue
			}
			if state != "" && strings.ToLower(status.State) != state {
				continue
			}
			alert := deriveAlertLevel(status.Stats, thresholds)
			snapshot := status
			payload := collectorStatusResponse{
				CollectorStatusSnapshot: &snapshot,
				AlertLevel:              alert,
			}
			data, err := json.Marshal(payload)
			if err != nil {
				continue
			}
			if _, err := c.Writer.Write([]byte("data: ")); err != nil {
				return
			}
			if _, err := c.Writer.Write(data); err != nil {
				return
			}
			if _, err := c.Writer.Write([]byte("\n\n")); err != nil {
				return
			}
			flusher.Flush()
		case <-ctx.Done():
			return
		}
	}
}

type collectorStatusResponse struct {
	*model.CollectorStatusSnapshot
	AlertLevel string `json:"alert_level"`
}

type alertThresholds struct {
	WarnDrop      float64
	CritDrop      float64
	WarnLatencyMs float64
	CritLatencyMs float64
}

const (
	defaultWarnDrop      = 0.02
	defaultCriticalDrop  = 0.1
	defaultWarnLatencyMs = 250.0
	defaultCritLatencyMs = 500.0
)

var defaultAlertThresholds = alertThresholds{
	WarnDrop:      defaultWarnDrop,
	CritDrop:      defaultCriticalDrop,
	WarnLatencyMs: defaultWarnLatencyMs,
	CritLatencyMs: defaultCritLatencyMs,
}

func filterStatuses(statuses []*model.CollectorStatusSnapshot, tenant, state string, thresholds alertThresholds) []collectorStatusResponse {
	results := make([]collectorStatusResponse, 0, len(statuses))
	for _, status := range statuses {
		if tenant != "" && !matchesTenant(status.Metadata, tenant) {
			continue
		}
		if state != "" && strings.ToLower(status.State) != state {
			continue
		}
		results = append(results, collectorStatusResponse{
			CollectorStatusSnapshot: status,
			AlertLevel:              deriveAlertLevel(status.Stats, thresholds),
		})
	}
	return results
}

func matchesTenant(metadata map[string]string, tenant string) bool {
	if tenant == "" {
		return true
	}
	value := tenantFromMetadata(metadata)
	return value == strings.ToLower(tenant)
}

func parseAlertThresholds(c *gin.Context) alertThresholds {
	return alertThresholds{
		WarnDrop:      parseFloatParam(c.Query("warn_drop_threshold"), defaultWarnDrop),
		CritDrop:      parseFloatParam(c.Query("crit_drop_threshold"), defaultCriticalDrop),
		WarnLatencyMs: parseFloatParam(c.Query("warn_latency_ms"), defaultWarnLatencyMs),
		CritLatencyMs: parseFloatParam(c.Query("crit_latency_ms"), defaultCritLatencyMs),
	}
}

func parseFloatParam(raw string, fallback float64) float64 {
	if raw == "" {
		return fallback
	}
	if val, err := strconv.ParseFloat(raw, 64); err == nil && val > 0 {
		return val
	}
	return fallback
}

func deriveAlertLevel(stats map[string]any, thresholds alertThresholds) string {
	dropRate := asFloat(stats["drop_rate"])
	latency := asFloat(stats["latency_ms"])
	switch {
	case dropRate >= thresholds.CritDrop || latency >= thresholds.CritLatencyMs:
		return "critical"
	case dropRate >= thresholds.WarnDrop || latency >= thresholds.WarnLatencyMs:
		return "warning"
	default:
		return "normal"
	}
}

func asFloat(value any) float64 {
	switch v := value.(type) {
	case float64:
		return v
	case float32:
		return float64(v)
	case int:
		return float64(v)
	case int64:
		return float64(v)
	case json.Number:
		if f, err := v.Float64(); err == nil {
			return f
		}
	case string:
		if f, err := strconv.ParseFloat(v, 64); err == nil {
			return f
		}
	}
	return 0
}

func tenantFromMetadata(meta map[string]string) string {
	if len(meta) == 0 {
		return ""
	}
	return strings.ToLower(strings.TrimSpace(meta["tenant"]))
}

func (h *CollectorHandler) initAllowlists() {
	if h == nil {
		return
	}
	if h.allowedProviders == nil && len(h.AllowedProviders) > 0 {
		h.allowedProviders = make(map[string]struct{}, len(h.AllowedProviders))
		for _, p := range h.AllowedProviders {
			if key := strings.ToLower(strings.TrimSpace(p)); key != "" {
				h.allowedProviders[key] = struct{}{}
			}
		}
	}
	if h.allowedProbes == nil && len(h.AllowedProbes) > 0 {
		h.allowedProbes = make(map[string]struct{}, len(h.AllowedProbes))
		for _, p := range h.AllowedProbes {
			if key := strings.ToLower(strings.TrimSpace(p)); key != "" {
				h.allowedProbes[key] = struct{}{}
			}
		}
	}
}

func (h *CollectorHandler) validateCollectorConfigPayload(raw json.RawMessage) error {
	h.initAllowlists()
	var payload struct {
		Collectors []struct {
			Name      string   `json:"name"`
			Kind      string   `json:"kind"`
			Providers []string `json:"providers"`
			Probes    []string `json:"probes"`
		} `json:"collectors"`
	}
	if err := json.Unmarshal(raw, &payload); err != nil {
		return fmt.Errorf("invalid config json: %w", err)
	}
	if len(payload.Collectors) == 0 {
		return errors.New("config must include at least one collector")
	}
	for idx, collector := range payload.Collectors {
		if strings.TrimSpace(collector.Name) == "" {
			return fmt.Errorf("collector[%d] missing name", idx)
		}
		if strings.TrimSpace(collector.Kind) == "" {
			return fmt.Errorf("collector[%d] missing kind", idx)
		}
		if len(h.allowedProviders) > 0 {
			for _, provider := range collector.Providers {
				key := strings.ToLower(strings.TrimSpace(provider))
				if key == "" {
					continue
				}
				if _, ok := h.allowedProviders[key]; !ok {
					return fmt.Errorf("collector[%d] provider %q not allowed", idx, provider)
				}
			}
		}
		if len(h.allowedProbes) > 0 {
			for _, probe := range collector.Probes {
				key := strings.ToLower(strings.TrimSpace(probe))
				if key == "" {
					continue
				}
				if _, ok := h.allowedProbes[key]; !ok {
					return fmt.Errorf("collector[%d] probe %q not allowed", idx, probe)
				}
			}
		}
	}
	return nil
}
