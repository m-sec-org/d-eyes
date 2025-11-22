package v1

import (
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/m-sec-org/d-eyes/server/internal/auditlog"
	"github.com/m-sec-org/d-eyes/server/internal/model"
	"github.com/m-sec-org/d-eyes/server/internal/security"
	"github.com/m-sec-org/d-eyes/server/internal/store"
	"github.com/m-sec-org/d-eyes/server/internal/threatintel"
)

// ThreatIntelHandler exposes REST endpoints for orchestrator operations.
type ThreatIntelHandler struct {
	Store        store.Store
	Orchestrator *threatintel.Orchestrator
	Audit        *auditlog.Manager
}

func (h *ThreatIntelHandler) RegisterRoutes(r *gin.RouterGroup) {
	if h == nil || h.Store == nil {
		return
	}
	group := r.Group("/threat-intel")
	group.GET("/iocs/:indicator", h.getIndicator)
	group.GET("/samples/:id", h.getSample)
	group.POST("/lookup", h.lookup)
	group.GET("/jobs", h.listJobs)
}

type lookupRequestBody struct {
	Indicator string   `json:"indicator" binding:"required"`
	Kind      string   `json:"kind"`
	Sources   []string `json:"sources"`
	Force     bool     `json:"force"`
}

type lookupResponse struct {
	JobIDs   []string             `json:"job_ids"`
	Cached   bool                 `json:"cached,omitempty"`
	Verdicts []threatIntelVerdict `json:"verdicts,omitempty"`
}

type threatIntelVerdict struct {
	ID             string            `json:"id"`
	Indicator      string            `json:"indicator"`
	Kind           string            `json:"kind"`
	Source         string            `json:"source"`
	Classification string            `json:"classification"`
	Confidence     string            `json:"confidence"`
	RetrievedAt    time.Time         `json:"retrieved_at"`
	ExpiresAt      time.Time         `json:"expires_at"`
	Metadata       map[string]string `json:"metadata,omitempty"`
}

func (h *ThreatIntelHandler) lookup(c *gin.Context) {
	if h.Orchestrator == nil || !h.Orchestrator.Enabled() {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "threat intel orchestrator not enabled"})
		return
	}
	var req lookupRequestBody
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	indicator := strings.TrimSpace(req.Indicator)
	if indicator == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "indicator required"})
		return
	}
	sources := make([]model.ThreatIntelSource, 0, len(req.Sources))
	for _, src := range req.Sources {
		src = strings.TrimSpace(strings.ToLower(src))
		switch src {
		case string(model.ThreatIntelSourceMetaDefender):
			sources = append(sources, model.ThreatIntelSourceMetaDefender)
		case string(model.ThreatIntelSourceOpenTIP):
			sources = append(sources, model.ThreatIntelSourceOpenTIP)
		}
	}
	submission := threatintel.LookupRequest{
		Indicator: indicator,
		Kind:      strings.TrimSpace(req.Kind),
		Sources:   sources,
		Force:     req.Force,
	}
	jobIDs, cachedVerdicts, err := h.Orchestrator.SubmitLookup(c.Request.Context(), submission)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	resp := lookupResponse{JobIDs: make([]string, 0, len(jobIDs))}
	for _, id := range jobIDs {
		resp.JobIDs = append(resp.JobIDs, id.String())
	}
	principal := security.PrincipalFrom(c)
	metadata := map[string]string{
		"sources": strings.Join(req.Sources, ","),
		"force":   strconv.FormatBool(req.Force),
	}
	if len(cachedVerdicts) > 0 && len(resp.JobIDs) == 0 {
		resp.Cached = true
		for _, v := range cachedVerdicts {
			resp.addVerdict(serializeVerdict(v))
		}
		metadata["verdict_count"] = strconv.Itoa(len(resp.Verdicts))
		h.recordAudit(principal, "threatintel.lookup", indicator, "cached", metadata)
		c.JSON(http.StatusOK, resp)
		return
	}
	metadata["job_count"] = strconv.Itoa(len(resp.JobIDs))
	h.recordAudit(principal, "threatintel.lookup", indicator, "queued", metadata)
	c.JSON(http.StatusAccepted, resp)
}

func (r *lookupResponse) addVerdict(verdict threatIntelVerdict) {
	if r == nil {
		return
	}
	if r.Verdicts == nil {
		r.Verdicts = make([]threatIntelVerdict, 0, 4)
	}
	r.Verdicts = append(r.Verdicts, verdict)
}

func serializeVerdict(v *model.ThreatIntelVerdict) threatIntelVerdict {
	if v == nil {
		return threatIntelVerdict{}
	}
	return threatIntelVerdict{
		ID:             v.ID.String(),
		Indicator:      v.Indicator,
		Kind:           v.Kind,
		Source:         string(v.Source),
		Classification: v.Classification,
		Confidence:     v.Confidence,
		RetrievedAt:    v.RetrievedAt,
		ExpiresAt:      v.ExpiresAt,
		Metadata:       v.Metadata,
	}
}

func (h *ThreatIntelHandler) recordAudit(principal security.Principal, action, resource, result string, metadata map[string]string) {
	if h == nil || h.Audit == nil {
		return
	}
	meta := make(map[string]string, len(metadata))
	for k, v := range metadata {
		meta[k] = v
	}
	h.Audit.Record(auditlog.Event{
		Actor:    principal.User,
		Role:     principal.Role,
		Action:   action,
		Resource: resource,
		Result:   result,
		Metadata: meta,
	})
}

func (h *ThreatIntelHandler) getIndicator(c *gin.Context) {
	indicator := strings.TrimSpace(c.Param("indicator"))
	if indicator == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "indicator required"})
		return
	}
	verdicts, err := h.Store.ListThreatIntelVerdicts(c.Request.Context(), indicator, 100)
	if err != nil {
		status := http.StatusInternalServerError
		if err == store.ErrNotFound {
			status = http.StatusNotFound
		}
		c.JSON(status, gin.H{"error": err.Error()})
		return
	}
	resp := make([]gin.H, 0, len(verdicts))
	for _, v := range verdicts {
		resp = append(resp, gin.H{
			"id":             v.ID.String(),
			"indicator":      v.Indicator,
			"kind":           v.Kind,
			"source":         v.Source,
			"classification": v.Classification,
			"confidence":     v.Confidence,
			"retrieved_at":   v.RetrievedAt,
			"metadata":       v.Metadata,
		})
	}
	c.JSON(http.StatusOK, gin.H{
		"indicator": indicator,
		"verdicts":  resp,
	})
}

func (h *ThreatIntelHandler) getSample(c *gin.Context) {
	idStr := c.Param("id")
	sampleID, err := uuid.Parse(strings.TrimSpace(idStr))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid sample id"})
		return
	}
	sample, err := h.Store.GetThreatIntelSample(c.Request.Context(), sampleID)
	if err != nil {
		status := http.StatusInternalServerError
		if err == store.ErrNotFound {
			status = http.StatusNotFound
		}
		c.JSON(status, gin.H{"error": err.Error()})
		return
	}
	jobs, err := h.Store.ListThreatIntelJobsBySample(c.Request.Context(), sampleID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	jobResp := make([]gin.H, 0, len(jobs))
	for _, job := range jobs {
		jobResp = append(jobResp, gin.H{
			"id":           job.ID.String(),
			"indicator":    job.Indicator,
			"kind":         job.Kind,
			"source":       job.Source,
			"status":       job.Status,
			"attempt":      job.Attempt,
			"error":        job.ErrorMsg,
			"artifact_ids": uuidStrings(job.ArtifactIDs),
			"next_run_at": func() *time.Time {
				if job.NextRunAt.IsZero() {
					return nil
				}
				t := job.NextRunAt
				return &t
			}(),
			"updated_at": job.UpdatedAt,
		})
	}
	c.JSON(http.StatusOK, gin.H{
		"id":           sample.ID.String(),
		"hash":         sample.Hash,
		"filename":     sample.Filename,
		"size":         sample.Size,
		"status":       sample.Status,
		"artifact_ids": uuidStrings(sample.ArtifactIDs),
		"task_run_id":  sample.TaskRunID.String(),
		"agent_id":     sample.AgentID.String(),
		"metadata":     sample.Metadata,
		"last_error":   sample.LastError,
		"created_at":   sample.CreatedAt,
		"updated_at":   sample.UpdatedAt,
		"jobs":         jobResp,
	})
}

func (h *ThreatIntelHandler) listJobs(c *gin.Context) {
	limit := 100
	if raw := strings.TrimSpace(c.Query("limit")); raw != "" {
		if parsed, err := strconv.Atoi(raw); err == nil {
			switch {
			case parsed <= 0:
			case parsed > 500:
				limit = 500
			default:
				limit = parsed
			}
		}
	}
	jobs, err := h.Store.ListThreatIntelJobs(c.Request.Context(), limit)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	resp := make([]gin.H, 0, len(jobs))
	for _, job := range jobs {
		nextRun := func() *time.Time {
			if job.NextRunAt.IsZero() {
				return nil
			}
			t := job.NextRunAt
			return &t
		}()
		resp = append(resp, gin.H{
			"id":           job.ID.String(),
			"sample_id":    job.SampleID.String(),
			"indicator":    job.Indicator,
			"kind":         job.Kind,
			"source":       job.Source,
			"status":       job.Status,
			"attempt":      job.Attempt,
			"error":        job.ErrorMsg,
			"next_run_at":  nextRun,
			"task_run_id":  job.TaskRunID.String(),
			"agent_id":     job.AgentID.String(),
			"artifact_ids": uuidStrings(job.ArtifactIDs),
			"metadata":     job.Metadata,
			"created_at":   job.CreatedAt,
			"updated_at":   job.UpdatedAt,
		})
	}
	c.JSON(http.StatusOK, gin.H{
		"jobs": resp,
	})
}

func uuidStrings(ids []uuid.UUID) []string {
	if len(ids) == 0 {
		return []string{}
	}
	out := make([]string, 0, len(ids))
	for _, id := range ids {
		out = append(out, id.String())
	}
	return out
}
