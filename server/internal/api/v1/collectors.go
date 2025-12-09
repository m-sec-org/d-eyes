package v1

import (
	"context"
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
	"github.com/m-sec-org/d-eyes/server/internal/config"
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
	Control          config.CollectorControlConfig

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
	r.POST("/collector/configs/rollouts", h.createRollout)
	r.GET("/collector/configs/rollouts", h.listRollouts)
	r.GET("/collector/configs/rollouts/:rollout_id", h.getRollout)
	r.POST("/collector/configs/rollouts/:rollout_id/rollback", h.rollbackRollout)
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

type collectorRolloutRequest struct {
	Name               string            `json:"name"`
	Description        string            `json:"description"`
	Selector           map[string]string `json:"selector"`
	Agents             []string          `json:"agents"`
	Config             json.RawMessage   `json:"config" binding:"required"`
	Version            *int64            `json:"version"`
	GracePeriodSeconds int64             `json:"grace_period_seconds"`
	UpdatedBy          string            `json:"updated_by"`
	Strategy           string            `json:"strategy"`
	Notes              string            `json:"notes"`
}

type collectorRolloutRollbackRequest struct {
	Reason    string   `json:"reason"`
	AgentIDs  []string `json:"agent_ids"`
	UpdatedBy string   `json:"updated_by"`
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
	h.handleRolloutStatusUpdate(c.Request.Context(), status)
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
	c.JSON(http.StatusOK, gin.H{"items": filterStatuses(statuses, tenant, state, thresholds, h.Control.HeartbeatLagThreshold)})
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
			annotateLag(&payload, h.Control.HeartbeatLagThreshold)
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

func (h *CollectorHandler) resolveRolloutAgents(ctx context.Context, agentIDs []string, selector map[string]string) ([]*model.Agent, error) {
	if h.Store == nil {
		return nil, errors.New("store unavailable")
	}
	listed, err := h.Store.ListAgents(ctx)
	if err != nil {
		return nil, err
	}
	idFilter := make(map[uuid.UUID]struct{}, len(agentIDs))
	for _, raw := range agentIDs {
		val := strings.TrimSpace(raw)
		if val == "" {
			continue
		}
		id, parseErr := uuid.Parse(val)
		if parseErr != nil {
			return nil, fmt.Errorf("invalid agent_id %q", raw)
		}
		idFilter[id] = struct{}{}
	}
	results := make([]*model.Agent, 0, len(listed))
	for _, agent := range listed {
		if len(idFilter) > 0 {
			if _, ok := idFilter[agent.ID]; !ok {
				continue
			}
		}
		if len(selector) > 0 && !matchesSelector(agent, selector) {
			continue
		}
		copyAgent := *agent
		copyAgent.Labels = cloneStringMap(agent.Labels)
		results = append(results, &copyAgent)
	}
	if len(idFilter) > 0 && len(results) < len(idFilter) {
		return nil, fmt.Errorf("one or more agents not found")
	}
	return results, nil
}

func (h *CollectorHandler) handleRolloutStatusUpdate(ctx context.Context, status *model.CollectorStatusSnapshot) {
	if h.Store == nil || status == nil {
		return
	}
	targets, err := h.Store.FindCollectorRolloutTargetsByAgent(ctx, status.AgentID)
	if err != nil || len(targets) == 0 {
		return
	}
	updated := make(map[uuid.UUID]struct{})
	now := time.Now().UTC()
	for _, target := range targets {
		if target.State == model.CollectorRolloutTargetStateAcked || target.State == model.CollectorRolloutTargetStateRolledBack {
			continue
		}
		changed := false
		if status.Version >= target.DesiredVersion {
			target.State = model.CollectorRolloutTargetStateAcked
			target.AckedAt = &now
			target.LastError = ""
			target.LastHeartbeat = status.UpdatedAt
			target.UpdatedAt = now
			changed = true
		} else if status.LastError != "" {
			target.LastError = status.LastError
			target.LastHeartbeat = status.UpdatedAt
			target.UpdatedAt = now
			changed = true
		}
		if changed {
			_ = h.Store.UpdateCollectorRolloutTarget(ctx, target)
			updated[target.RolloutID] = struct{}{}
		}
	}
	for rolloutID := range updated {
		h.refreshRolloutStatsByID(ctx, rolloutID)
	}
}

func (h *CollectorHandler) refreshRolloutStatsByID(ctx context.Context, rolloutID uuid.UUID) *model.CollectorRollout {
	if h.Store == nil {
		return nil
	}
	rollout, err := h.Store.GetCollectorRollout(ctx, rolloutID)
	if err != nil {
		return nil
	}
	return h.refreshRolloutStats(ctx, rollout)
}

func (h *CollectorHandler) refreshRolloutStats(ctx context.Context, rollout *model.CollectorRollout) *model.CollectorRollout {
	if rollout == nil || h.Store == nil {
		return rollout
	}
	targets, err := h.Store.ListCollectorRolloutTargets(ctx, rollout.ID)
	if err != nil {
		return rollout
	}
	grace := rollout.GracePeriodSeconds
	if grace <= 0 && h.Control.RolloutGracePeriod > 0 {
		grace = int64(h.Control.RolloutGracePeriod.Seconds())
	}
	dur := time.Duration(grace) * time.Second
	ack := 0
	fails := 0
	now := time.Now().UTC()
	for _, target := range targets {
		if target.State == model.CollectorRolloutTargetStatePending && dur > 0 && now.Sub(target.CreatedAt) > dur {
			target.State = model.CollectorRolloutTargetStateFailed
			target.LastError = "timeout"
			target.UpdatedAt = now
			_ = h.Store.UpdateCollectorRolloutTarget(ctx, target)
		}
		switch target.State {
		case model.CollectorRolloutTargetStateAcked:
			ack++
		case model.CollectorRolloutTargetStateFailed:
			fails++
		}
	}
	total := len(targets)
	rollout.TargetCount = total
	rollout.AckCount = ack
	rollout.FailedCount = fails
	if rollout.Status != model.CollectorRolloutStatusRolledBack && rollout.Status != model.CollectorRolloutStatusRollingBack {
		if total > 0 && ack == total {
			rollout.Status = model.CollectorRolloutStatusCompleted
			if rollout.CompletedAt == nil {
				t := now
				rollout.CompletedAt = &t
			}
		} else if fails > 0 && ack+fails == total {
			rollout.Status = model.CollectorRolloutStatusFailed
			if rollout.CompletedAt == nil {
				t := now
				rollout.CompletedAt = &t
			}
		} else if rollout.Status == "" {
			rollout.Status = model.CollectorRolloutStatusInProgress
		}
	}
	_ = h.Store.UpdateCollectorRollout(ctx, rollout)
	h.updateRolloutMetrics(rollout.ID, total, ack, fails)
	return rollout
}

func (h *CollectorHandler) updateRolloutMetrics(id uuid.UUID, total, ack, fails int) {
	if h.Metrics == nil || h.Metrics.CollectorRolloutTargets == nil {
		return
	}
	rolloutID := id.String()
	pending := total - ack - fails
	if pending < 0 {
		pending = 0
	}
	h.Metrics.CollectorRolloutTargets.WithLabelValues(rolloutID, "acked").Set(float64(ack))
	h.Metrics.CollectorRolloutTargets.WithLabelValues(rolloutID, "failed").Set(float64(fails))
	h.Metrics.CollectorRolloutTargets.WithLabelValues(rolloutID, "pending").Set(float64(pending))
}

func (h *CollectorHandler) recordRolloutAction(action, result string) {
	if h.Metrics == nil || h.Metrics.CollectorRolloutActions == nil {
		return
	}
	h.Metrics.CollectorRolloutActions.WithLabelValues(action, result).Inc()
}

func (h *CollectorHandler) createRollout(c *gin.Context) {
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
	var req collectorRolloutRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid payload", "details": err.Error()})
		return
	}
	if len(req.Config) == 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "config required"})
		return
	}
	if len(req.Agents) == 0 && len(req.Selector) == 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "agents or selector required"})
		return
	}
	if err := h.validateCollectorConfigPayload(req.Config); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	ctx := c.Request.Context()
	agents, err := h.resolveRolloutAgents(ctx, req.Agents, req.Selector)
	if err != nil {
		if isRolloutRequestError(err) {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		} else {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to resolve agents"})
		}
		return
	}
	if len(agents) == 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "no agents match selector"})
		return
	}
	principal := security.PrincipalFrom(c)
	updatedBy := strings.TrimSpace(req.UpdatedBy)
	if updatedBy == "" {
		updatedBy = principal.User
	}
	now := time.Now().UTC()
	targets := make([]*model.CollectorRolloutTarget, 0, len(agents))
	for _, agent := range agents {
		prev, err := h.Store.GetCollectorConfig(ctx, agent.ID)
		if err != nil && !errors.Is(err, store.ErrNotFound) {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to load previous config"})
			return
		}
		snapshot := &model.CollectorConfigSnapshot{
			AgentID:   agent.ID,
			Config:    req.Config,
			UpdatedBy: updatedBy,
		}
		if req.Version != nil {
			snapshot.Version = *req.Version
		}
		if err := h.Store.UpsertCollectorConfig(ctx, snapshot); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to persist config"})
			return
		}
		cfg, err := h.Store.GetCollectorConfig(ctx, agent.ID)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to refresh config"})
			return
		}
		target := &model.CollectorRolloutTarget{
			AgentID:        agent.ID,
			AgentName:      agent.Name,
			DesiredVersion: cfg.Version,
			State:          model.CollectorRolloutTargetStatePending,
			CreatedAt:      now,
			UpdatedAt:      now,
			Metadata:       cloneStringMap(agent.Labels),
		}
		if prev != nil {
			target.PreviousVersion = prev.Version
			if len(prev.Config) > 0 {
				target.PreviousConfig = append([]byte(nil), prev.Config...)
			}
		}
		targets = append(targets, target)
	}
	rollout := &model.CollectorRollout{
		ID:                 uuid.New(),
		Name:               req.Name,
		Description:        req.Description,
		Selector:           cloneStringMap(req.Selector),
		Status:             model.CollectorRolloutStatusInProgress,
		Config:             append([]byte(nil), req.Config...),
		Version:            0,
		Strategy:           req.Strategy,
		CreatedBy:          updatedBy,
		CreatedAt:          now,
		StartedAt:          now,
		GracePeriodSeconds: req.GracePeriodSeconds,
		Notes:              req.Notes,
	}
	if rollout.GracePeriodSeconds <= 0 {
		if h.Control.RolloutGracePeriod > 0 {
			rollout.GracePeriodSeconds = int64(h.Control.RolloutGracePeriod.Seconds())
		} else {
			rollout.GracePeriodSeconds = 30
		}
	}
	if len(targets) > 0 {
		rollout.Version = targets[0].DesiredVersion
	}
	for _, target := range targets {
		target.RolloutID = rollout.ID
	}
	if err := h.Store.CreateCollectorRollout(ctx, rollout, targets); err != nil {
		h.recordRolloutAction("push", "failed")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to create rollout"})
		return
	}
	updated := h.refreshRolloutStats(ctx, rollout)
	if h.Audit != nil {
		h.Audit.Record(auditlog.Event{
			Actor:    updatedBy,
			Role:     principal.Role,
			Action:   "collector.rollout.create",
			Result:   "success",
			Resource: rollout.ID.String(),
			Metadata: map[string]string{
				"targets": fmt.Sprintf("%d", len(targets)),
			},
		})
	}
	h.recordRolloutAction("push", "success")
	c.JSON(http.StatusOK, gin.H{"rollout": updated})
}

func (h *CollectorHandler) listRollouts(c *gin.Context) {
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
	limit := 0
	if raw := strings.TrimSpace(c.Query("limit")); raw != "" {
		if val, err := strconv.Atoi(raw); err == nil {
			limit = val
		}
	}
	statuses, err := parseRolloutStatuses(c.Query("status"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	rollouts, err := h.Store.ListCollectorRollouts(c.Request.Context(), store.CollectorRolloutFilter{Statuses: statuses, Limit: limit})
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to list rollouts"})
		return
	}
	results := make([]*model.CollectorRollout, 0, len(rollouts))
	for _, rollout := range rollouts {
		results = append(results, h.refreshRolloutStats(c.Request.Context(), rollout))
	}
	c.JSON(http.StatusOK, gin.H{"items": results})
}

func (h *CollectorHandler) getRollout(c *gin.Context) {
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
	rolloutID, err := uuid.Parse(c.Param("rollout_id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid rollout_id"})
		return
	}
	rollout, err := h.Store.GetCollectorRollout(c.Request.Context(), rolloutID)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			c.JSON(http.StatusNotFound, gin.H{"error": "rollout not found"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to load rollout"})
		return
	}
	rollout = h.refreshRolloutStats(c.Request.Context(), rollout)
	targets, err := h.Store.ListCollectorRolloutTargets(c.Request.Context(), rolloutID)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			c.JSON(http.StatusOK, gin.H{"rollout": rollout, "targets": []any{}})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to list targets"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"rollout": rollout, "targets": targets})
}

func (h *CollectorHandler) rollbackRollout(c *gin.Context) {
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
	rolloutID, err := uuid.Parse(c.Param("rollout_id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid rollout_id"})
		return
	}
	var req collectorRolloutRollbackRequest
	_ = c.ShouldBindJSON(&req)
	rollout, err := h.Store.GetCollectorRollout(c.Request.Context(), rolloutID)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			c.JSON(http.StatusNotFound, gin.H{"error": "rollout not found"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to load rollout"})
		return
	}
	targets, err := h.Store.ListCollectorRolloutTargets(c.Request.Context(), rolloutID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to list targets"})
		return
	}
	selection := make(map[uuid.UUID]struct{}, len(req.AgentIDs))
	for _, raw := range req.AgentIDs {
		id, parseErr := uuid.Parse(strings.TrimSpace(raw))
		if parseErr != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": fmt.Sprintf("invalid agent_id %q", raw)})
			return
		}
		selection[id] = struct{}{}
	}
	principal := security.PrincipalFrom(c)
	updatedBy := strings.TrimSpace(req.UpdatedBy)
	if updatedBy == "" {
		updatedBy = principal.User
	}
	now := time.Now().UTC()
	success := false
	for _, target := range targets {
		if len(selection) > 0 {
			if _, ok := selection[target.AgentID]; !ok {
				continue
			}
		}
		if len(target.PreviousConfig) == 0 {
			target.State = model.CollectorRolloutTargetStateFailed
			target.LastError = "missing previous config"
			target.UpdatedAt = now
			_ = h.Store.UpdateCollectorRolloutTarget(c.Request.Context(), target)
			continue
		}
		snapshot := &model.CollectorConfigSnapshot{
			AgentID:   target.AgentID,
			Config:    target.PreviousConfig,
			Version:   target.PreviousVersion,
			UpdatedBy: updatedBy,
		}
		if err := h.Store.UpsertCollectorConfig(c.Request.Context(), snapshot); err != nil {
			target.State = model.CollectorRolloutTargetStateFailed
			target.LastError = "rollback_failed"
			target.UpdatedAt = now
			_ = h.Store.UpdateCollectorRolloutTarget(c.Request.Context(), target)
			continue
		}
		target.State = model.CollectorRolloutTargetStateRolledBack
		target.LastError = ""
		target.UpdatedAt = now
		_ = h.Store.UpdateCollectorRolloutTarget(c.Request.Context(), target)
		success = true
	}
	rollout.Status = model.CollectorRolloutStatusRolledBack
	rollout.RolledBackAt = &now
	rollout.RollbackReason = req.Reason
	if err := h.Store.UpdateCollectorRollout(c.Request.Context(), rollout); err != nil {
		h.recordRolloutAction("rollback", "failed")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to update rollout"})
		return
	}
	updated := h.refreshRolloutStats(c.Request.Context(), rollout)
	if h.Audit != nil {
		h.Audit.Record(auditlog.Event{
			Actor:    updatedBy,
			Role:     principal.Role,
			Action:   "collector.rollout.rollback",
			Result:   "success",
			Resource: rollout.ID.String(),
			Metadata: map[string]string{
				"reason":  strings.TrimSpace(req.Reason),
				"partial": fmt.Sprintf("%t", !success),
			},
		})
	}
	status := "failed"
	if success {
		status = "success"
	}
	h.recordRolloutAction("rollback", status)
	c.JSON(http.StatusOK, gin.H{"rollout": updated})
}

type collectorStatusResponse struct {
	*model.CollectorStatusSnapshot
	AlertLevel string  `json:"alert_level"`
	LagSeconds float64 `json:"lag_seconds,omitempty"`
	Lagging    bool    `json:"lagging,omitempty"`
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

func filterStatuses(statuses []*model.CollectorStatusSnapshot, tenant, state string, thresholds alertThresholds, lagThreshold time.Duration) []collectorStatusResponse {
	results := make([]collectorStatusResponse, 0, len(statuses))
	for _, status := range statuses {
		if tenant != "" && !matchesTenant(status.Metadata, tenant) {
			continue
		}
		if state != "" && strings.ToLower(status.State) != state {
			continue
		}
		resp := collectorStatusResponse{
			CollectorStatusSnapshot: status,
			AlertLevel:              deriveAlertLevel(status.Stats, thresholds),
		}
		annotateLag(&resp, lagThreshold)
		results = append(results, resp)
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

func matchesSelector(agent *model.Agent, selector map[string]string) bool {
	if agent == nil || len(selector) == 0 {
		return true
	}
	for key, expected := range selector {
		k := strings.TrimSpace(key)
		if k == "" {
			continue
		}
		value := ""
		if agent.Labels != nil {
			value = agent.Labels[k]
		}
		if !strings.EqualFold(strings.TrimSpace(value), strings.TrimSpace(expected)) {
			return false
		}
	}
	return true
}

func isRolloutRequestError(err error) bool {
	if err == nil {
		return false
	}
	msg := err.Error()
	return strings.Contains(msg, "invalid agent_id") || strings.Contains(msg, "agents not found")
}

func annotateLag(resp *collectorStatusResponse, threshold time.Duration) {
	if resp == nil || resp.CollectorStatusSnapshot == nil {
		return
	}
	lag := time.Since(resp.UpdatedAt)
	resp.LagSeconds = lag.Seconds()
	if threshold > 0 && lag > threshold {
		resp.Lagging = true
	}
}

func parseAlertThresholds(c *gin.Context) alertThresholds {
	return alertThresholds{
		WarnDrop:      parseFloatParam(c.Query("warn_drop_threshold"), defaultWarnDrop),
		CritDrop:      parseFloatParam(c.Query("crit_drop_threshold"), defaultCriticalDrop),
		WarnLatencyMs: parseFloatParam(c.Query("warn_latency_ms"), defaultWarnLatencyMs),
		CritLatencyMs: parseFloatParam(c.Query("crit_latency_ms"), defaultCritLatencyMs),
	}
}

func parseRolloutStatuses(raw string) ([]model.CollectorRolloutStatus, error) {
	if strings.TrimSpace(raw) == "" {
		return nil, nil
	}
	parts := strings.Split(raw, ",")
	statuses := make([]model.CollectorRolloutStatus, 0, len(parts))
	for _, part := range parts {
		val := strings.ToLower(strings.TrimSpace(part))
		if val == "" {
			continue
		}
		switch val {
		case string(model.CollectorRolloutStatusPending), string(model.CollectorRolloutStatusInProgress), string(model.CollectorRolloutStatusCompleted), string(model.CollectorRolloutStatusFailed), string(model.CollectorRolloutStatusCanceled), string(model.CollectorRolloutStatusRollingBack), string(model.CollectorRolloutStatusRolledBack):
			statuses = append(statuses, model.CollectorRolloutStatus(val))
		default:
			return nil, fmt.Errorf("invalid rollout status %q", part)
		}
	}
	return statuses, nil
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
