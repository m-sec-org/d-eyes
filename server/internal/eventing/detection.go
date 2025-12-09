package eventing

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/m-sec-org/d-eyes/server/internal/config"
	"github.com/m-sec-org/d-eyes/server/internal/metrics"
	"github.com/m-sec-org/d-eyes/server/internal/model"
	"github.com/m-sec-org/d-eyes/server/internal/scheduler"
	"github.com/m-sec-org/d-eyes/server/internal/store"
	"github.com/m-sec-org/d-eyes/server/internal/streams"
	"github.com/m-sec-org/d-eyes/server/internal/threatintel"
)

type threatIntelLookup interface {
	SubmitLookup(ctx context.Context, req threatintel.LookupRequest) ([]uuid.UUID, []*model.ThreatIntelVerdict, error)
}

// DetectionEngine evaluates ingested events using rules/ML and orchestrates responses.
type DetectionEngine struct {
	cfg       config.DetectionConfig
	retention config.EventRetentionConfig
	store     store.Store
	sched     *scheduler.Scheduler
	threat    threatIntelLookup
	log       *slog.Logger
	metrics   *metrics.Metrics
	hub       *streams.Hub

	queue  chan model.SystemEventRecord
	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup

	rules  []compiledRule
	models []mlModel
}

type compiledRule struct {
	name                string
	description         string
	severity            string
	eventTypes          map[string]struct{}
	sources             map[string]struct{}
	metadataMatches     map[string]string
	tagMatches          map[string]string
	payloadContains     []string
	indicators          []string
	respondProfile      string
	respondPriority     int
	respondMetadata     map[string]string
	submitThreatIntel   bool
	payloadSearchString bool
}

type mlModel struct {
	name              string
	severity          string
	threshold         float64
	weights           map[string]float64
	respondProfile    string
	respondPriority   int
	submitThreatIntel bool
}

type detectionMatch struct {
	Rule              string
	Severity          string
	Reason            string
	Indicators        []string
	Score             float64
	RespondProfile    string
	RespondPriority   int
	RespondMetadata   map[string]string
	SubmitThreatIntel bool
}

// NewDetectionEngine constructs the detection engine when enabled.
func NewDetectionEngine(cfg config.EventsConfig, st store.Store, sched *scheduler.Scheduler, threat threatIntelLookup, log *slog.Logger, metricsCollector *metrics.Metrics, hub *streams.Hub) *DetectionEngine {
	if !cfg.Detection.Enabled {
		return nil
	}
	rules := compileRules(cfg.Detection.Rules)
	models := compileModels(cfg.Detection.MLModels)
	if len(rules) == 0 && len(models) == 0 {
		return nil
	}
	queueSize := cfg.Detection.QueueSize
	if queueSize <= 0 {
		queueSize = 1024
	}
	ctx, cancel := context.WithCancel(context.Background())
	engine := &DetectionEngine{
		cfg:       cfg.Detection,
		retention: cfg.Retention,
		store:     st,
		sched:     sched,
		threat:    threat,
		log:       log,
		metrics:   metricsCollector,
		hub:       hub,
		queue:     make(chan model.SystemEventRecord, queueSize),
		ctx:       ctx,
		cancel:    cancel,
		rules:     rules,
		models:    models,
	}
	workers := cfg.Detection.MaxWorkers
	if workers <= 0 {
		workers = 1
	}
	for i := 0; i < workers; i++ {
		engine.wg.Add(1)
		go engine.worker()
	}
	if engine.log != nil {
		engine.log.Info("detection engine initialized", "rules", len(rules), "models", len(models), "workers", workers)
	}
	return engine
}

// Close stops the worker pool.
func (e *DetectionEngine) Close() {
	if e == nil {
		return
	}
	e.cancel()
	e.wg.Wait()
}

// Consume implements eventing.Consumer.
func (e *DetectionEngine) Consume(ctx context.Context, events []model.SystemEventRecord) {
	if e == nil {
		return
	}
	for _, evt := range events {
		select {
		case e.queue <- evt:
		case <-ctx.Done():
			return
		case <-e.ctx.Done():
			return
		}
	}
}

func (e *DetectionEngine) worker() {
	defer e.wg.Done()
	for {
		select {
		case <-e.ctx.Done():
			return
		case evt := <-e.queue:
			e.processEvent(evt)
		}
	}
}

func (e *DetectionEngine) processEvent(evt model.SystemEventRecord) {
	if strings.HasPrefix(strings.ToLower(strings.TrimSpace(evt.EventType)), "detection.") {
		return
	}
	payload := decodePayload(evt.Payload)
	matches := e.evaluateRules(&evt, payload)
	matches = append(matches, e.evaluateModels(&evt, payload)...)
	for _, match := range matches {
		e.handleMatch(evt, match)
	}
}

func (e *DetectionEngine) evaluateRules(evt *model.SystemEventRecord, payload map[string]any) []detectionMatch {
	if len(e.rules) == 0 || evt == nil {
		return nil
	}
	body := strings.ToLower(string(evt.Payload))
	var matches []detectionMatch
	for _, rule := range e.rules {
		if !rule.matches(evt, payload, body) {
			continue
		}
		reason := rule.description
		if reason == "" {
			reason = fmt.Sprintf("rule %s matched", rule.name)
		}
		matches = append(matches, detectionMatch{
			Rule:              rule.name,
			Severity:          rule.severity,
			Reason:            reason,
			Indicators:        rule.extractIndicators(evt, payload),
			Score:             1,
			RespondProfile:    rule.respondProfile,
			RespondPriority:   rule.respondPriority,
			RespondMetadata:   cloneMetadata(rule.respondMetadata),
			SubmitThreatIntel: rule.submitThreatIntel,
		})
	}
	return matches
}

func (e *DetectionEngine) evaluateModels(evt *model.SystemEventRecord, payload map[string]any) []detectionMatch {
	if len(e.models) == 0 || evt == nil {
		return nil
	}
	var matches []detectionMatch
	for _, model := range e.models {
		score := model.score(evt, payload)
		if score < model.threshold {
			continue
		}
		reason := fmt.Sprintf("model %s score %.2f exceeds threshold %.2f", model.name, score, model.threshold)
		matches = append(matches, detectionMatch{
			Rule:              model.name,
			Severity:          model.severity,
			Reason:            reason,
			Indicators:        nil,
			Score:             score,
			RespondProfile:    model.respondProfile,
			RespondPriority:   model.respondPriority,
			SubmitThreatIntel: model.submitThreatIntel,
		})
	}
	return matches
}

func (e *DetectionEngine) handleMatch(evt model.SystemEventRecord, match detectionMatch) {
	detectionID := uuid.New()
	var respondTaskID uuid.UUID
	if taskID, err := e.enqueueRespondTask(match, evt, detectionID); err != nil {
		if e.log != nil {
			e.log.Error("auto-respond task creation failed", "error", err, "rule", match.Rule, "event_id", evt.ID)
		}
	} else {
		respondTaskID = taskID
	}
	var threatJobs []uuid.UUID
	if match.SubmitThreatIntel && len(match.Indicators) > 0 {
		threatJobs = e.submitThreatIntel(match, evt)
	}
	e.persistDetectionEvent(evt, match, detectionID, respondTaskID, threatJobs)
	e.publishAlert(evt, match, detectionID, respondTaskID)
	if e.metrics != nil {
		e.metrics.DetectionsTriggered.WithLabelValues(match.Rule, strings.ToLower(match.Severity)).Inc()
		if respondTaskID != uuid.Nil {
			e.metrics.DetectionsAutoResponded.WithLabelValues(match.Rule).Inc()
		}
	}
}

func (e *DetectionEngine) enqueueRespondTask(match detectionMatch, evt model.SystemEventRecord, detectionID uuid.UUID) (uuid.UUID, error) {
	if e.sched == nil || e.store == nil {
		return uuid.Nil, errors.New("scheduler unavailable")
	}
	profile := strings.TrimSpace(match.RespondProfile)
	if profile == "" && e.cfg.AutoRespond.Enabled {
		profile = e.cfg.AutoRespond.DefaultProfile
	}
	if profile == "" {
		return uuid.Nil, nil
	}
	priority := match.RespondPriority
	if priority <= 0 && e.cfg.AutoRespond.DefaultPriority > 0 {
		priority = e.cfg.AutoRespond.DefaultPriority
	}
	if priority <= 0 {
		priority = 1
	}
	metadata := cloneMetadata(e.cfg.AutoRespond.Metadata)
	if metadata == nil {
		metadata = make(map[string]string)
	}
	for k, v := range match.RespondMetadata {
		metadata[k] = v
	}
	metadata["detection_rule"] = match.Rule
	metadata["detection_id"] = detectionID.String()
	metadata["detection_severity"] = match.Severity
	metadata["detection_reason"] = match.Reason
	payload := map[string]any{
		"detection_id": detectionID.String(),
		"rule":         match.Rule,
		"severity":     match.Severity,
		"reason":       match.Reason,
		"event_id":     evt.ID.String(),
		"event_type":   evt.EventType,
		"agent_id":     evt.AgentID.String(),
		"agent_name":   evt.AgentName,
		"indicators":   match.Indicators,
		"score":        match.Score,
	}
	payloadBytes, _ := json.Marshal(payload)
	task := &model.Task{
		ID:        uuid.New(),
		Type:      model.TaskType("respond"),
		Profile:   profile,
		Priority:  priority,
		Payload:   payloadBytes,
		Status:    model.TaskStatusPending,
		Metadata:  metadata,
		CreatedBy: chooseCreatedBy(e.cfg.AutoRespond.CreatedBy),
		CreatedAt: time.Now().UTC(),
		UpdatedAt: time.Now().UTC(),
	}
	if err := e.store.CreateTask(context.Background(), task); err != nil {
		return uuid.Nil, fmt.Errorf("create task: %w", err)
	}
	e.sched.RecordNewTask(task.Status)
	if err := e.sched.EnqueueTask(context.Background(), task); err != nil {
		return task.ID, fmt.Errorf("enqueue task: %w", err)
	}
	return task.ID, nil
}

func (e *DetectionEngine) submitThreatIntel(match detectionMatch, evt model.SystemEventRecord) []uuid.UUID {
	if e.threat == nil || len(match.Indicators) == 0 {
		return nil
	}
	var submitted []uuid.UUID
	for _, indicator := range uniqueStrings(match.Indicators) {
		if indicator == "" {
			continue
		}
		req := threatintel.LookupRequest{
			Indicator: indicator,
			Kind:      "detection",
			Metadata: map[string]string{
				"detection_rule": match.Rule,
				"detection_id":   evt.ID.String(),
				"severity":       match.Severity,
			},
			AgentID: evt.AgentID,
		}
		jobIDs, _, err := e.threat.SubmitLookup(context.Background(), req)
		if err != nil && e.log != nil {
			e.log.Warn("threat intel lookup failed", "indicator", indicator, "error", err)
			continue
		}
		submitted = append(submitted, jobIDs...)
	}
	return submitted
}

func (e *DetectionEngine) persistDetectionEvent(evt model.SystemEventRecord, match detectionMatch, detectionID uuid.UUID, respondTaskID uuid.UUID, threatJobs []uuid.UUID) {
	if e.store == nil {
		return
	}
	now := time.Now().UTC()
	payload := map[string]any{
		"detection_id":     detectionID.String(),
		"rule":             match.Rule,
		"severity":         match.Severity,
		"reason":           match.Reason,
		"score":            match.Score,
		"matched_event":    evt.ID.String(),
		"event_type":       evt.EventType,
		"agent_id":         evt.AgentID.String(),
		"agent_name":       evt.AgentName,
		"indicators":       match.Indicators,
		"respond_task":     respondTaskID.String(),
		"threatintel_jobs": uuidStrings(threatJobs),
	}
	payloadBytes, _ := json.Marshal(payload)
	metadata := map[string]string{
		"detection.id":       detectionID.String(),
		"detection.rule":     match.Rule,
		"detection.severity": match.Severity,
		"detection.reason":   match.Reason,
		"detection.score":    fmt.Sprintf("%.2f", match.Score),
		"matched_event_id":   evt.ID.String(),
		"matched_event_type": evt.EventType,
		"agent_id":           evt.AgentID.String(),
		"storage_tier":       "hot",
	}
	if respondTaskID != uuid.Nil {
		metadata["respond_task_id"] = respondTaskID.String()
	}
	if len(threatJobs) > 0 {
		metadata["threatintel_job_ids"] = strings.Join(uuidStrings(threatJobs), ",")
	}
	tags := map[string]string{
		"severity": strings.ToLower(match.Severity),
		"rule":     match.Rule,
	}
	record := model.SystemEventRecord{
		ID:            uuid.New(),
		AgentID:       evt.AgentID,
		AgentName:     evt.AgentName,
		Collector:     "server",
		CollectorKind: "detection-engine",
		EventType:     "detection.alert",
		Source:        "server",
		Priority:      alertPriorityFromSeverity(match.Severity),
		StorageTier:   "hot",
		Timestamp:     now,
		Sequence:      0,
		Payload:       payloadBytes,
		Metadata:      metadata,
		Tags:          tags,
		ReceivedAt:    now,
	}
	ApplyRetentionMetadata(e.retention, &record)
	if err := e.store.InsertSystemEvents(context.Background(), []model.SystemEventRecord{record}); err != nil && e.log != nil {
		e.log.Error("persist detection event failed", "error", err)
	}
}

func (e *DetectionEngine) publishAlert(evt model.SystemEventRecord, match detectionMatch, detectionID uuid.UUID, respondTaskID uuid.UUID) {
	if e.hub == nil {
		return
	}
	meta := map[string]string{
		"rule":         match.Rule,
		"event_id":     evt.ID.String(),
		"agent_id":     evt.AgentID.String(),
		"detection_id": detectionID.String(),
		"severity":     match.Severity,
	}
	if respondTaskID != uuid.Nil {
		meta["respond_task_id"] = respondTaskID.String()
	}
	e.hub.Publish(streams.TaskEvent{
		Event:    "detection.triggered",
		TaskID:   detectionID.String(),
		TaskType: "detection",
		Status:   strings.ToLower(match.Severity),
		AgentID:  evt.AgentID.String(),
		Metadata: meta,
		Severity: match.Severity,
		Message:  match.Reason,
	})
}

func (r compiledRule) matches(evt *model.SystemEventRecord, payload map[string]any, payloadBody string) bool {
	if len(r.eventTypes) > 0 && !matchSet(r.eventTypes, evt.EventType) {
		return false
	}
	if len(r.sources) > 0 && !matchSet(r.sources, evt.Source) {
		return false
	}
	for key, expected := range r.metadataMatches {
		actual := strings.ToLower(strings.TrimSpace(evt.Metadata[key]))
		if actual != expected {
			return false
		}
	}
	for key, expected := range r.tagMatches {
		actual := strings.ToLower(strings.TrimSpace(evt.Tags[key]))
		if actual != expected {
			return false
		}
	}
	for _, needle := range r.payloadContains {
		if needle == "" {
			continue
		}
		if payloadBody == "" {
			return false
		}
		if !strings.Contains(payloadBody, needle) {
			return false
		}
	}
	return true
}

func (r compiledRule) extractIndicators(evt *model.SystemEventRecord, payload map[string]any) []string {
	if len(r.indicators) == 0 {
		return nil
	}
	var values []string
	for _, path := range r.indicators {
		if val, ok := extractFieldValue(evt, payload, path); ok {
			values = append(values, val)
		}
	}
	return uniqueStrings(values)
}

func (m mlModel) score(evt *model.SystemEventRecord, payload map[string]any) float64 {
	if len(m.weights) == 0 {
		return 0
	}
	var total float64
	for key, weight := range m.weights {
		val, ok := extractNumericFeature(evt, payload, key)
		if !ok {
			continue
		}
		total += weight * val
	}
	return total
}

func compileRules(cfgs []config.DetectionRuleConfig) []compiledRule {
	var rules []compiledRule
	for _, cfg := range cfgs {
		if !cfg.Enabled {
			continue
		}
		rules = append(rules, compiledRule{
			name:              cfg.Name,
			description:       cfg.Description,
			severity:          normalizeSeverity(cfg.Severity),
			eventTypes:        toStringSet(cfg.EventTypes),
			sources:           toStringSet(cfg.Sources),
			metadataMatches:   lowerMap(cfg.Metadata),
			tagMatches:        lowerMap(cfg.Tags),
			payloadContains:   lowerSlice(cfg.PayloadContains),
			indicators:        cfg.Indicators,
			respondProfile:    strings.TrimSpace(cfg.AutoRespondProfile),
			respondPriority:   cfg.AutoRespondPriority,
			respondMetadata:   cloneMetadata(cfg.RespondMetadata),
			submitThreatIntel: cfg.SubmitToThreatIntel,
		})
	}
	return rules
}

func cloneMetadata(in map[string]string) map[string]string {
	if len(in) == 0 {
		return nil
	}
	out := make(map[string]string, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}

func compileModels(cfgs []config.DetectionMLModelConfig) []mlModel {
	var models []mlModel
	for _, cfg := range cfgs {
		if !cfg.Enabled {
			continue
		}
		models = append(models, mlModel{
			name:              cfg.Name,
			severity:          normalizeSeverity(cfg.Severity),
			threshold:         cfg.Threshold,
			weights:           cfg.FeatureWeights,
			respondProfile:    strings.TrimSpace(cfg.AutoRespondProfile),
			respondPriority:   cfg.AutoRespondPriority,
			submitThreatIntel: cfg.SubmitToThreatIntel,
		})
	}
	return models
}

func decodePayload(raw json.RawMessage) map[string]any {
	if len(raw) == 0 {
		return nil
	}
	var payload map[string]any
	if err := json.Unmarshal(raw, &payload); err != nil {
		return nil
	}
	return payload
}

func extractFieldValue(evt *model.SystemEventRecord, payload map[string]any, path string) (string, bool) {
	path = strings.TrimSpace(path)
	if path == "" {
		return "", false
	}
	switch {
	case strings.HasPrefix(path, "metadata."):
		key := strings.TrimPrefix(path, "metadata.")
		if evt.Metadata == nil {
			return "", false
		}
		val := evt.Metadata[key]
		if val == "" {
			return "", false
		}
		return val, true
	case strings.HasPrefix(path, "tags."):
		key := strings.TrimPrefix(path, "tags.")
		if evt.Tags == nil {
			return "", false
		}
		val := evt.Tags[key]
		if val == "" {
			return "", false
		}
		return val, true
	case strings.HasPrefix(path, "payload."):
		if payload == nil {
			return "", false
		}
		field := strings.TrimPrefix(path, "payload.")
		if val, ok := lookupField(payload, field); ok {
			return fmt.Sprint(val), true
		}
	case path == "agent_id":
		if evt.AgentID == uuid.Nil {
			return "", false
		}
		return evt.AgentID.String(), true
	case path == "agent_name":
		if evt.AgentName == "" {
			return "", false
		}
		return evt.AgentName, true
	default:
		if evt.Metadata != nil {
			if val := evt.Metadata[path]; val != "" {
				return val, true
			}
		}
	}
	return "", false
}

func extractNumericFeature(evt *model.SystemEventRecord, payload map[string]any, key string) (float64, bool) {
	val, ok := extractFieldValue(evt, payload, key)
	if !ok {
		return 0, false
	}
	var parsed float64
	if err := json.Unmarshal([]byte(val), &parsed); err == nil {
		return parsed, true
	}
	switch lower := strings.ToLower(strings.TrimSpace(val)); lower {
	case "critical":
		return 4, true
	case "high":
		return 3, true
	case "medium":
		return 2, true
	case "low":
		return 1, true
	}
	if f, err := strconv.ParseFloat(val, 64); err == nil {
		return f, true
	}
	return 0, false
}

func normalizeSeverity(severity string) string {
	switch strings.ToLower(strings.TrimSpace(severity)) {
	case "critical":
		return "critical"
	case "high":
		return "high"
	case "medium":
		return "medium"
	case "low":
		return "low"
	default:
		return "high"
	}
}

func lowerMap(input map[string]string) map[string]string {
	if len(input) == 0 {
		return nil
	}
	out := make(map[string]string, len(input))
	for k, v := range input {
		key := strings.ToLower(strings.TrimSpace(k))
		if key == "" {
			continue
		}
		out[key] = strings.ToLower(strings.TrimSpace(v))
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func lowerSlice(values []string) []string {
	if len(values) == 0 {
		return nil
	}
	out := make([]string, 0, len(values))
	for _, v := range values {
		if trimmed := strings.ToLower(strings.TrimSpace(v)); trimmed != "" {
			out = append(out, trimmed)
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func uniqueStrings(values []string) []string {
	if len(values) == 0 {
		return nil
	}
	seen := make(map[string]struct{}, len(values))
	out := make([]string, 0, len(values))
	for _, v := range values {
		trimmed := strings.TrimSpace(v)
		if trimmed == "" {
			continue
		}
		if _, ok := seen[trimmed]; ok {
			continue
		}
		seen[trimmed] = struct{}{}
		out = append(out, trimmed)
	}
	return out
}

func chooseCreatedBy(value string) string {
	if strings.TrimSpace(value) == "" {
		return "detection-engine"
	}
	return value
}

func alertPriorityFromSeverity(severity string) string {
	switch strings.ToLower(strings.TrimSpace(severity)) {
	case "critical", "high":
		return "high"
	case "medium":
		return "normal"
	default:
		return "low"
	}
}

func uuidStrings(ids []uuid.UUID) []string {
	if len(ids) == 0 {
		return nil
	}
	out := make([]string, 0, len(ids))
	for _, id := range ids {
		if id == uuid.Nil {
			continue
		}
		out = append(out, id.String())
	}
	return out
}
