package threatintel

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/m-sec-org/d-eyes/server/internal/auditlog"
	"github.com/m-sec-org/d-eyes/server/internal/config"
	"github.com/m-sec-org/d-eyes/server/internal/metrics"
	"github.com/m-sec-org/d-eyes/server/internal/model"
	"github.com/m-sec-org/d-eyes/server/internal/store"
)

// Orchestrator coordinates sample ingestion, job dispatching, and provider fan-out.
type Orchestrator struct {
	store     store.Store
	cfg       config.ThreatIntelConfig
	log       *slog.Logger
	metrics   *metrics.Metrics
	hub       *Hub
	providers map[model.ThreatIntelSource]Provider
	audit     auditRecorder

	workCh chan *model.ThreatIntelJob
	wg     sync.WaitGroup
	cancel context.CancelFunc
}

type auditRecorder interface {
	Record(event auditlog.Event)
}

// New constructs an orchestrator instance. Call Start to enable background workers.
func New(st store.Store, cfg config.ThreatIntelConfig, logger *slog.Logger, m *metrics.Metrics, audit auditRecorder) *Orchestrator {
	if logger == nil {
		logger = slog.Default()
	}
	hub := NewHub()
	providers := make(map[model.ThreatIntelSource]Provider)
	if strings.TrimSpace(cfg.OpenTIPAPIKey) != "" || cfg.OpenTIPBaseURL != "" {
		providers[model.ThreatIntelSourceOpenTIP] = newOpenTIPProvider(cfg.OpenTIPBaseURL, cfg.OpenTIPAPIKey, 15*time.Second)
	}
	if strings.TrimSpace(cfg.MetaDefenderAPIKey) != "" || cfg.MetaDefenderBaseURL != "" {
		providers[model.ThreatIntelSourceMetaDefender] = newMetaDefenderProvider(cfg.MetaDefenderBaseURL, cfg.MetaDefenderAPIKey, 15*time.Second)
	}
	return &Orchestrator{
		store:     st,
		cfg:       cfg,
		log:       logger,
		metrics:   m,
		hub:       hub,
		providers: providers,
		audit:     audit,
	}
}

// Enabled reports whether orchestration should run.
func (o *Orchestrator) Enabled() bool {
	return o != nil && o.cfg.Enabled && len(o.providers) > 0
}

// Start launches dispatcher & worker goroutines.
func (o *Orchestrator) Start(ctx context.Context) {
	if !o.Enabled() {
		return
	}
	if o.workCh != nil {
		return
	}
	o.workCh = make(chan *model.ThreatIntelJob, o.cfg.WorkerConcurrency*4)
	ctx, cancel := context.WithCancel(ctx)
	o.cancel = cancel
	o.wg.Add(1)
	go o.dispatcher(ctx)
	workers := o.cfg.WorkerConcurrency
	if workers <= 0 {
		workers = 2
	}
	for i := 0; i < workers; i++ {
		o.wg.Add(1)
		go o.worker(ctx, i)
	}
	o.log.Info("threat intel orchestrator started", "workers", workers)
}

// Stop halts worker goroutines.
func (o *Orchestrator) Stop() {
	if o.cancel != nil {
		o.cancel()
	}
	o.wg.Wait()
	if o.workCh != nil {
		close(o.workCh)
		o.workCh = nil
	}
	if o.hub != nil {
		o.hub.Close()
	}
}

// Hub exposes the SSE hub.
func (o *Orchestrator) Hub() *Hub {
	if o == nil {
		return nil
	}
	return o.hub
}

// SubmitSample records a sample upload and enqueues jobs for all active providers.
func (o *Orchestrator) SubmitSample(ctx context.Context, submission SampleSubmission) (uuid.UUID, error) {
	if !o.Enabled() {
		return uuid.Nil, nil
	}
	if len(submission.ArtifactIDs) == 0 {
		return uuid.Nil, errors.New("threatintel: sample missing artifacts")
	}
	sample := &model.ThreatIntelSample{
		ID:          uuid.New(),
		Hash:        strings.ToLower(strings.TrimSpace(submission.Hash)),
		Filename:    submission.Filename,
		Size:        submission.Size,
		Status:      model.ThreatIntelSampleStatusPending,
		ArtifactIDs: append([]uuid.UUID(nil), submission.ArtifactIDs...),
		TaskRunID:   submission.TaskRunID,
		AgentID:     submission.AgentID,
		Metadata:    cloneMetadata(submission.Metadata),
	}
	if err := o.store.CreateThreatIntelSample(ctx, sample); err != nil {
		return uuid.Nil, fmt.Errorf("create sample: %w", err)
	}
	o.recordAudit(fmt.Sprintf("agent:%s", sample.AgentID.String()), "agent", "threatintel.sample_enqueued", sample.ID.String(), sample.Status, map[string]string{
		"hash":           sample.Hash,
		"filename":       sample.Filename,
		"task_run":       sample.TaskRunID.String(),
		"artifact_count": fmt.Sprintf("%d", len(sample.ArtifactIDs)),
	})
	o.hub.Publish(Event{
		Type:     "sample.enqueued",
		SampleID: sample.ID.String(),
		Indicator: func() string {
			if sample.Hash != "" {
				return sample.Hash
			}
			return ""
		}(),
		Status:   sample.Status,
		Metadata: sample.Metadata,
	})
	for src, provider := range o.providers {
		if provider == nil {
			continue
		}
		job := &model.ThreatIntelJob{
			ID:          uuid.New(),
			SampleID:    sample.ID,
			Indicator:   sample.Hash,
			Kind:        "sample",
			Source:      src,
			Status:      model.ThreatIntelJobStatusPending,
			TaskRunID:   sample.TaskRunID,
			AgentID:     sample.AgentID,
			ArtifactIDs: append([]uuid.UUID(nil), sample.ArtifactIDs...),
			Metadata: mergeMetadata(sample.Metadata, map[string]string{
				"filename": sample.Filename,
			}),
		}
		if err := o.store.InsertThreatIntelJob(ctx, job); err != nil {
			return sample.ID, fmt.Errorf("insert threat intel job: %w", err)
		}
		o.hub.Publish(Event{
			Type:      "job.enqueued",
			SampleID:  sample.ID.String(),
			JobID:     job.ID.String(),
			Indicator: job.Indicator,
			Source:    string(job.Source),
			Status:    job.Status,
		})
	}
	return sample.ID, nil
}

// SubmitLookup enqueues indicator-based lookups (no artifact required).
func (o *Orchestrator) SubmitLookup(ctx context.Context, req LookupRequest) ([]uuid.UUID, []*model.ThreatIntelVerdict, error) {
	if !o.Enabled() {
		return nil, nil, nil
	}
	indicator := strings.TrimSpace(req.Indicator)
	if indicator == "" {
		return nil, nil, errors.New("threatintel: indicator required")
	}
	sources := req.Sources
	if len(sources) == 0 {
		for src := range o.providers {
			sources = append(sources, src)
		}
	}
	if !req.Force {
		cached, err := o.cachedVerdicts(ctx, indicator, sources)
		if err != nil {
			return nil, nil, err
		}
		if len(cached) > 0 {
			o.hub.Publish(Event{
				Type:      "lookup.cached",
				Indicator: indicator,
				Metadata: map[string]string{
					"sources": strings.Join(uniqueSources(cached), ","),
				},
			})
			return nil, cached, nil
		}
	}
	jobIDs := make([]uuid.UUID, 0, len(sources))
	for _, src := range sources {
		provider, ok := o.providers[src]
		if !ok || provider == nil {
			continue
		}
		job := &model.ThreatIntelJob{
			ID:        uuid.New(),
			Indicator: indicator,
			Kind:      strings.TrimSpace(req.Kind),
			Source:    src,
			Status:    model.ThreatIntelJobStatusPending,
			TaskRunID: req.TaskRunID,
			AgentID:   req.AgentID,
			Metadata:  cloneMetadata(req.Metadata),
		}
		if job.Kind == "" {
			job.Kind = "hash"
		}
		if err := o.store.InsertThreatIntelJob(ctx, job); err != nil {
			return jobIDs, nil, fmt.Errorf("insert lookup job: %w", err)
		}
		jobIDs = append(jobIDs, job.ID)
		o.hub.Publish(Event{
			Type:      "job.enqueued",
			JobID:     job.ID.String(),
			Indicator: job.Indicator,
			Source:    string(job.Source),
			Status:    job.Status,
		})
	}
	return jobIDs, nil, nil
}

func (o *Orchestrator) cachedVerdicts(ctx context.Context, indicator string, sources []model.ThreatIntelSource) ([]*model.ThreatIntelVerdict, error) {
	if o.store == nil {
		return nil, nil
	}
	verdicts, err := o.store.ListThreatIntelVerdicts(ctx, indicator, 100)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return nil, nil
		}
		return nil, err
	}
	if len(verdicts) == 0 {
		return nil, nil
	}
	required := make(map[model.ThreatIntelSource]struct{})
	for _, src := range sources {
		required[src] = struct{}{}
	}
	if len(required) == 0 {
		return verdicts, nil
	}
	for _, v := range verdicts {
		if _, ok := required[v.Source]; ok {
			delete(required, v.Source)
		}
	}
	if len(required) == 0 {
		return verdicts, nil
	}
	return nil, nil
}

func uniqueSources(verdicts []*model.ThreatIntelVerdict) []string {
	set := make(map[string]struct{})
	for _, v := range verdicts {
		set[string(v.Source)] = struct{}{}
	}
	res := make([]string, 0, len(set))
	for k := range set {
		res = append(res, k)
	}
	return res
}

func (o *Orchestrator) jobActor(job *model.ThreatIntelJob) string {
	if job == nil {
		return "system"
	}
	if job.AgentID != uuid.Nil {
		return fmt.Sprintf("agent:%s", job.AgentID.String())
	}
	if job.TaskRunID != uuid.Nil {
		return fmt.Sprintf("task:%s", job.TaskRunID.String())
	}
	return "system"
}

func (o *Orchestrator) jobRole(job *model.ThreatIntelJob) string {
	if job != nil && job.AgentID != uuid.Nil {
		return "agent"
	}
	return "system"
}

func (o *Orchestrator) recordAudit(actor, role, action, resource, result string, metadata map[string]string) {
	if o == nil || o.audit == nil {
		return
	}
	meta := make(map[string]string, len(metadata))
	for k, v := range metadata {
		meta[k] = v
	}
	o.audit.Record(auditlog.Event{
		Actor:    actor,
		Role:     role,
		Action:   action,
		Resource: resource,
		Result:   result,
		Metadata: meta,
	})
}

func (o *Orchestrator) observeAPILatency(source model.ThreatIntelSource, action string, d time.Duration) {
	if o == nil || o.metrics == nil || o.metrics.ThreatIntelLatency == nil {
		return
	}
	if d < 0 {
		d = 0
	}
	o.metrics.ThreatIntelLatency.WithLabelValues(string(source), action).Observe(d.Seconds())
}

func (o *Orchestrator) updateQueueMetrics(ctx context.Context) {
	if o == nil || o.metrics == nil || o.metrics.ThreatIntelQueue == nil {
		return
	}
	count, err := o.store.CountThreatIntelJobs(ctx, []string{model.ThreatIntelJobStatusPending, model.ThreatIntelJobStatusRetryBackoff})
	if err != nil {
		o.log.Debug("count threat intel jobs failed", "error", err)
		return
	}
	o.metrics.ThreatIntelQueue.Set(float64(count))
}

func (o *Orchestrator) dispatcher(ctx context.Context) {
	defer o.wg.Done()
	interval := o.cfg.QueuePollInterval
	if interval <= 0 {
		interval = 5 * time.Second
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			o.pollJobs(ctx)
		}
	}
}

func (o *Orchestrator) pollJobs(ctx context.Context) {
	defer o.updateQueueMetrics(ctx)
	limit := o.cfg.WorkerConcurrency * 2
	if limit <= 0 {
		limit = 4
	}
	jobs, err := o.store.LeaseThreatIntelJobs(ctx, limit)
	if err != nil {
		o.log.Warn("lease threat intel jobs failed", "error", err)
		return
	}
	for _, job := range jobs {
		select {
		case o.workCh <- job:
		case <-ctx.Done():
			return
		}
		o.hub.Publish(Event{
			Type:      "job.dispatched",
			JobID:     job.ID.String(),
			SampleID:  job.SampleID.String(),
			Indicator: job.Indicator,
			Source:    string(job.Source),
			Status:    job.Status,
		})
	}
}

func (o *Orchestrator) worker(ctx context.Context, idx int) {
	defer o.wg.Done()
	for {
		select {
		case <-ctx.Done():
			return
		case job, ok := <-o.workCh:
			if !ok {
				return
			}
			o.processJob(ctx, job)
		}
	}
}

func (o *Orchestrator) processJob(ctx context.Context, job *model.ThreatIntelJob) {
	provider, ok := o.providers[job.Source]
	if !ok || provider == nil {
		o.failJob(ctx, job, fmt.Errorf("%w: %s", ErrUnsupportedSource, job.Source))
		return
	}
	var sample *model.ThreatIntelSample
	var artifacts []model.Artifact
	var err error
	if job.SampleID != uuid.Nil {
		sample, err = o.store.GetThreatIntelSample(ctx, job.SampleID)
		if err != nil {
			o.failJob(ctx, job, fmt.Errorf("fetch sample: %w", err))
			return
		}
		if sample != nil {
			_ = o.store.UpdateThreatIntelSampleStatus(ctx, sample.ID, model.ThreatIntelSampleStatusScanning, "", nil)
		}
		artifacts, err = o.store.GetArtifacts(ctx, job.ArtifactIDs)
		if err != nil {
			o.failJob(ctx, job, fmt.Errorf("fetch artifacts: %w", err))
			return
		}
	}
	req := ProviderRequest{Job: job, Sample: sample, Artifacts: artifacts}
	callStart := time.Now()
	verdicts, err := provider.Process(ctx, req)
	o.observeAPILatency(job.Source, job.Kind, time.Since(callStart))
	if err != nil {
		o.handleJobError(ctx, job, sample, err)
		return
	}
	for _, verdict := range verdicts {
		if verdict == nil {
			continue
		}
		if verdict.JobID == uuid.Nil {
			verdict.JobID = job.ID
		}
		if verdict.TaskRunID == uuid.Nil {
			verdict.TaskRunID = job.TaskRunID
		}
		if verdict.Source == "" {
			verdict.Source = job.Source
		}
		if verdict.Indicator == "" {
			verdict.Indicator = job.Indicator
		}
		if verdict.Kind == "" {
			verdict.Kind = job.Kind
		}
		if verdict.Metadata == nil {
			verdict.Metadata = cloneMetadata(job.Metadata)
		} else {
			verdict.Metadata = mergeMetadata(job.Metadata, verdict.Metadata)
		}
		if verdict.RetrievedAt.IsZero() {
			verdict.RetrievedAt = time.Now().UTC()
		}
		ttl := o.verdictTTL()
		if ttl > 0 {
			verdict.ExpiresAt = verdict.RetrievedAt.Add(ttl)
		}
		if err := o.store.InsertThreatIntelVerdict(ctx, verdict); err != nil {
			o.log.Warn("failed to insert verdict", "job_id", job.ID, "error", err)
		} else {
			metadata := map[string]string{
				"source":         string(verdict.Source),
				"classification": verdict.Classification,
			}
			if verdict.Confidence != "" {
				metadata["confidence"] = verdict.Confidence
			}
			o.recordAudit(o.jobActor(job), o.jobRole(job), "threatintel.verdict", verdict.Indicator, verdict.Classification, metadata)
			o.hub.Publish(Event{
				Type:           "verdict",
				JobID:          job.ID.String(),
				SampleID:       job.SampleID.String(),
				Indicator:      verdict.Indicator,
				Source:         string(verdict.Source),
				Classification: verdict.Classification,
				Confidence:     verdict.Confidence,
				Timestamp:      verdict.RetrievedAt,
			})
		}
	}
	o.completeJob(ctx, job, sample)
}

func (o *Orchestrator) verdictTTL() time.Duration {
	if o == nil {
		return 0
	}
	if o.cfg.VerdictTTL <= 0 {
		return 0
	}
	return o.cfg.VerdictTTL
}

func (o *Orchestrator) handleJobError(ctx context.Context, job *model.ThreatIntelJob, sample *model.ThreatIntelSample, err error) {
	var retryErr *RetryableError
	if errors.As(err, &retryErr) && (o.cfg.MaxAttempts <= 0 || job.Attempt < o.cfg.MaxAttempts) {
		backoff := o.cfg.RetryBackoff
		if backoff <= 0 {
			backoff = 30 * time.Second
		}
		if retryErr != nil && retryErr.RetryAfter > 0 {
			backoff = retryErr.RetryAfter
		}
		next := time.Now().Add(backoff)
		_ = o.store.UpdateThreatIntelJobStatus(ctx, job.ID, model.ThreatIntelJobStatusRetryBackoff, next, err.Error(), nil)
		o.hub.Publish(Event{
			Type:     "job.retry",
			JobID:    job.ID.String(),
			SampleID: job.SampleID.String(),
			Source:   string(job.Source),
			Status:   model.ThreatIntelJobStatusRetryBackoff,
			Message:  err.Error(),
		})
		return
	}
	o.failJob(ctx, job, err)
	if sample != nil {
		_ = o.store.UpdateThreatIntelSampleStatus(ctx, sample.ID, model.ThreatIntelSampleStatusFailed, err.Error(), nil)
		o.recordAudit(fmt.Sprintf("agent:%s", sample.AgentID.String()), "agent", "threatintel.sample_failed", sample.ID.String(), "failed", map[string]string{
			"error":  err.Error(),
			"job_id": job.ID.String(),
		})
	}
}

func (o *Orchestrator) failJob(ctx context.Context, job *model.ThreatIntelJob, err error) {
	if err == nil {
		err = errors.New("unknown error")
	}
	_ = o.store.UpdateThreatIntelJobStatus(ctx, job.ID, model.ThreatIntelJobStatusFailed, time.Time{}, err.Error(), nil)
	o.hub.Publish(Event{
		Type:     "job.failed",
		JobID:    job.ID.String(),
		SampleID: job.SampleID.String(),
		Source:   string(job.Source),
		Status:   model.ThreatIntelJobStatusFailed,
		Message:  err.Error(),
	})
	if o.metrics != nil && o.metrics.ThreatIntelJobs != nil {
		o.metrics.ThreatIntelJobs.WithLabelValues(string(job.Source), "failed").Inc()
	}
	o.recordAudit(o.jobActor(job), o.jobRole(job), "threatintel.job_failed", job.ID.String(), "failed", map[string]string{
		"indicator": job.Indicator,
		"source":    string(job.Source),
		"attempt":   fmt.Sprintf("%d", job.Attempt),
		"error":     err.Error(),
	})
}

func (o *Orchestrator) completeJob(ctx context.Context, job *model.ThreatIntelJob, sample *model.ThreatIntelSample) {
	_ = o.store.UpdateThreatIntelJobStatus(ctx, job.ID, model.ThreatIntelJobStatusSucceeded, time.Time{}, "", nil)
	o.hub.Publish(Event{
		Type:     "job.succeeded",
		JobID:    job.ID.String(),
		SampleID: job.SampleID.String(),
		Source:   string(job.Source),
		Status:   model.ThreatIntelJobStatusSucceeded,
	})
	if o.metrics != nil && o.metrics.ThreatIntelJobs != nil {
		o.metrics.ThreatIntelJobs.WithLabelValues(string(job.Source), "succeeded").Inc()
	}
	o.recordAudit(o.jobActor(job), o.jobRole(job), "threatintel.job_succeeded", job.ID.String(), "succeeded", map[string]string{
		"indicator": job.Indicator,
		"source":    string(job.Source),
		"attempt":   fmt.Sprintf("%d", job.Attempt),
	})
	if sample == nil {
		return
	}
	jobs, err := o.store.ListThreatIntelJobsBySample(ctx, sample.ID)
	if err != nil {
		o.log.Warn("list sample jobs failed", "sample_id", sample.ID, "error", err)
		return
	}
	completed := true
	failed := false
	for _, j := range jobs {
		switch j.Status {
		case model.ThreatIntelJobStatusFailed:
			failed = true
		case model.ThreatIntelJobStatusPending, model.ThreatIntelJobStatusRetryBackoff, model.ThreatIntelJobStatusRunning:
			completed = false
		}
	}
	switch {
	case failed:
		_ = o.store.UpdateThreatIntelSampleStatus(ctx, sample.ID, model.ThreatIntelSampleStatusFailed, "one or more jobs failed", nil)
		o.hub.Publish(Event{
			Type:     "sample.failed",
			SampleID: sample.ID.String(),
			Status:   model.ThreatIntelSampleStatusFailed,
		})
		o.recordAudit(fmt.Sprintf("agent:%s", sample.AgentID.String()), "agent", "threatintel.sample_failed", sample.ID.String(), "failed", map[string]string{"task_run": sample.TaskRunID.String()})
	case completed:
		_ = o.store.UpdateThreatIntelSampleStatus(ctx, sample.ID, model.ThreatIntelSampleStatusCompleted, "", nil)
		o.hub.Publish(Event{
			Type:     "sample.completed",
			SampleID: sample.ID.String(),
			Status:   model.ThreatIntelSampleStatusCompleted,
		})
		o.recordAudit(fmt.Sprintf("agent:%s", sample.AgentID.String()), "agent", "threatintel.sample_completed", sample.ID.String(), "completed", map[string]string{"task_run": sample.TaskRunID.String()})
	default:
		_ = o.store.UpdateThreatIntelSampleStatus(ctx, sample.ID, model.ThreatIntelSampleStatusScanning, "", nil)
	}
}
