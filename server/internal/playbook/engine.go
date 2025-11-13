package playbook

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/m-sec-org/d-eyes/server/internal/behavior"
	"github.com/m-sec-org/d-eyes/server/internal/config"
	"github.com/m-sec-org/d-eyes/server/internal/model"
	"github.com/m-sec-org/d-eyes/server/internal/scheduler"
	"github.com/m-sec-org/d-eyes/server/internal/store"
	"github.com/m-sec-org/d-eyes/server/internal/streams"
	"github.com/m-sec-org/d-eyes/server/internal/threatintel"
)

// Engine listens for trigger events and executes playbook actions.
type Engine struct {
	cfg         config.PlaybookConfig
	manager     *Manager
	store       store.Store
	sched       *scheduler.Scheduler
	logger      *slog.Logger
	taskHub     *streams.Hub
	behaviorHub *behavior.Hub
	threatHub   *threatintel.Hub

	cancel context.CancelFunc
	wg     sync.WaitGroup
}

func NewEngine(cfg config.PlaybookConfig, m *Manager, st store.Store, sched *scheduler.Scheduler, logger *slog.Logger, taskHub *streams.Hub, behaviorHub *behavior.Hub, threatHub *threatintel.Hub) *Engine {
	if !cfg.Enabled || m == nil {
		return nil
	}
	if logger == nil {
		logger = slog.Default()
	}
	return &Engine{cfg: cfg, manager: m, store: st, sched: sched, logger: logger, taskHub: taskHub, behaviorHub: behaviorHub, threatHub: threatHub}
}

func (e *Engine) Enabled() bool {
	return e != nil && e.manager != nil && e.sched != nil
}

func (e *Engine) Start(ctx context.Context) {
	if !e.Enabled() {
		return
	}
	runCtx, cancel := context.WithCancel(ctx)
	e.cancel = cancel
	if e.behaviorHub != nil {
		e.wg.Add(1)
		go e.consumeBehavior(runCtx)
	}
	if e.threatHub != nil {
		e.wg.Add(1)
		go e.consumeThreatIntel(runCtx)
	}
	if e.taskHub != nil {
		e.wg.Add(1)
		go e.consumeTasks(runCtx)
	}
	e.logger.Info("playbook engine started")
}

func (e *Engine) Stop() {
	if e.cancel != nil {
		e.cancel()
	}
	e.wg.Wait()
}

func (e *Engine) consumeBehavior(ctx context.Context) {
	defer e.wg.Done()
	events, cancel := e.behaviorHub.Subscribe(ctx)
	defer cancel()
	for {
		select {
		case <-ctx.Done():
			return
		case evt, ok := <-events:
			if !ok {
				return
			}
			if evt.Anomaly == nil {
				continue
			}
			attrs := map[string]string{
				"agent_id": evt.Anomaly.AgentID.String(),
				"severity": evt.Anomaly.Severity,
				"reason":   fmt.Sprint(evt.Anomaly.Summary["reason"]),
				"status":   evt.Anomaly.Status,
			}
			if evt.Anomaly.IOC != "" {
				attrs["ioc"] = evt.Anomaly.IOC
			}
			if evt.Anomaly.TaskID != uuid.Nil {
				attrs["task_id"] = evt.Anomaly.TaskID.String()
			}
			e.handleEvent(ctx, TriggerEvent{Type: "behavior.anomaly", Attributes: normalizeMap(attrs), Payload: evt})
		}
	}
}

func (e *Engine) consumeThreatIntel(ctx context.Context) {
	defer e.wg.Done()
	events, cancel := e.threatHub.Subscribe(ctx)
	defer cancel()
	for {
		select {
		case <-ctx.Done():
			return
		case evt, ok := <-events:
			if !ok {
				return
			}
			attrs := map[string]string{
				"event":          evt.Type,
				"indicator":      evt.Indicator,
				"source":         evt.Source,
				"status":         evt.Status,
				"classification": evt.Classification,
				"confidence":     evt.Confidence,
			}
			e.handleEvent(ctx, TriggerEvent{Type: "threatintel." + evt.Type, Attributes: normalizeMap(attrs), Payload: evt})
		}
	}
}

func (e *Engine) consumeTasks(ctx context.Context) {
	defer e.wg.Done()
	events, cancel := e.taskHub.Subscribe(ctx)
	defer cancel()
	for {
		select {
		case <-ctx.Done():
			return
		case evt, ok := <-events:
			if !ok {
				return
			}
			attrs := map[string]string{
				"event":     evt.Event,
				"task_id":   evt.TaskID,
				"task_type": evt.TaskType,
				"status":    evt.Status,
				"agent_id":  evt.AgentID,
			}
			e.handleEvent(ctx, TriggerEvent{Type: "task." + evt.Event, Attributes: normalizeMap(attrs), Payload: evt})
		}
	}
}

func (e *Engine) handleEvent(ctx context.Context, event TriggerEvent) {
	if !e.Enabled() {
		return
	}
	playbooks, err := e.manager.List(ctx, 200)
	if err != nil {
		e.logger.Warn("list playbooks failed", "error", err)
		return
	}
	for _, pb := range playbooks {
		if !strings.EqualFold(pb.Status, "active") {
			continue
		}
		if !matchesTrigger(pb.Trigger, event) {
			continue
		}
		if !matchesConditions(pb.Conditions, event.Attributes) {
			continue
		}
		go e.executePlaybook(context.Background(), pb, event)
	}
}

func (e *Engine) ExecuteManual(pb *model.Playbook, event TriggerEvent) {
	if !e.Enabled() {
		return
	}
	go e.executePlaybook(context.Background(), pb, event)
}

func matchesTrigger(trigger model.PlaybookTrigger, event TriggerEvent) bool {
	if !strings.EqualFold(trigger.Type, event.Type) {
		return false
	}
	for key, expected := range trigger.Filter {
		if actual := event.Attributes[strings.ToLower(key)]; actual != expected {
			return false
		}
	}
	return true
}

func matchesConditions(conditions []string, attrs map[string]string) bool {
	if len(conditions) == 0 {
		return true
	}
	for _, cond := range conditions {
		cond = strings.TrimSpace(cond)
		if cond == "" {
			continue
		}
		if !evaluateCondition(cond, attrs) {
			return false
		}
	}
	return true
}

func evaluateCondition(expr string, attrs map[string]string) bool {
	var op string
	switch {
	case strings.Contains(expr, "!="):
		op = "!="
	case strings.Contains(expr, "=="):
		op = "=="
	default:
		return false
	}
	parts := strings.SplitN(expr, op, 2)
	if len(parts) != 2 {
		return false
	}
	left := strings.TrimSpace(parts[0])
	right := strings.Trim(strings.TrimSpace(parts[1]), "\"'")
	actual := attrs[strings.ToLower(left)]
	if op == "==" {
		return actual == right
	}
	return actual != right
}

func normalizeMap(in map[string]string) map[string]string {
	if len(in) == 0 {
		return nil
	}
	out := make(map[string]string, len(in))
	for k, v := range in {
		if strings.TrimSpace(v) == "" {
			continue
		}
		out[strings.ToLower(k)] = v
	}
	return out
}

func (e *Engine) executePlaybook(ctx context.Context, pb *model.Playbook, event TriggerEvent) {
	run := &model.PlaybookRun{
		ID:          uuid.New(),
		PlaybookID:  pb.ID,
		Status:      "running",
		TriggerType: event.Type,
		Event:       map[string]interface{}{"attributes": event.Attributes, "payload": event.Payload},
		CreatedAt:   time.Now(),
		UpdatedAt:   time.Now(),
	}
	if err := e.manager.RecordRun(ctx, run); err != nil {
		e.logger.Warn("record playbook run failed", "error", err)
		return
	}
	for idx, action := range pb.Actions {
		step := model.PlaybookRunStep{
			Name:      fmt.Sprintf("action-%d", idx+1),
			Type:      action.Type,
			Status:    "running",
			StartedAt: time.Now(),
		}
		run.Steps = append(run.Steps, step)
		_ = e.manager.UpdateRun(ctx, run)
		result, err := e.executeAction(ctx, pb, run, action, event)
		run.Steps[idx].CompletedAt = pointerTo(time.Now())
		if err != nil {
			run.Steps[idx].Status = "failed"
			run.Steps[idx].Error = err.Error()
			run.Status = "failed"
			_ = e.manager.UpdateRun(ctx, run)
			e.logger.Warn("playbook action failed", "playbook", pb.Name, "action", action.Type, "error", err)
			return
		}
		run.Steps[idx].Status = "succeeded"
		run.Steps[idx].Result = result
		_ = e.manager.UpdateRun(ctx, run)
	}
	run.Status = "succeeded"
	completed := time.Now()
	run.CompletedAt = &completed
	run.UpdatedAt = completed
	_ = e.manager.UpdateRun(ctx, run)
}

func (e *Engine) executeAction(ctx context.Context, pb *model.Playbook, run *model.PlaybookRun, action model.PlaybookAction, event TriggerEvent) (map[string]interface{}, error) {
	switch action.Type {
	case "notify":
		e.logger.Info("playbook notify", "target", action.Target, "playbook", pb.Name)
		return map[string]interface{}{"notified": action.Target}, nil
	case "task.dispatch":
		id, err := e.dispatchTask(ctx, pb, run, action)
		if err != nil {
			return nil, err
		}
		return map[string]interface{}{"task_id": id.String()}, nil
	case "agent.command":
		id, err := e.dispatchAgentCommand(ctx, pb, run, action, event)
		if err != nil {
			return nil, err
		}
		return map[string]interface{}{"task_id": id.String(), "command": action.Command}, nil
	default:
		return nil, fmt.Errorf("unsupported action type %s", action.Type)
	}
}

func (e *Engine) dispatchTask(ctx context.Context, pb *model.Playbook, run *model.PlaybookRun, action model.PlaybookAction) (uuid.UUID, error) {
	payload, err := json.Marshal(action.Payload)
	if err != nil {
		return uuid.Nil, fmt.Errorf("marshal payload: %w", err)
	}
	metadata := mergeMetadata(action.Metadata, map[string]string{
		"playbook_id":     pb.ID.String(),
		"playbook_run_id": run.ID.String(),
		"origin":          "playbook",
	})
	task := &model.Task{
		ID:        uuid.New(),
		Type:      model.TaskType(action.TaskType),
		Profile:   "default",
		Priority:  5,
		Payload:   payload,
		Status:    model.TaskStatusPending,
		Metadata:  metadata,
		CreatedBy: fmt.Sprintf("playbook:%s", pb.Name),
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}
	if err := e.store.CreateTask(ctx, task); err != nil {
		return uuid.Nil, fmt.Errorf("create task: %w", err)
	}
	if err := e.sched.EnqueueTask(ctx, task); err != nil {
		return uuid.Nil, fmt.Errorf("enqueue task: %w", err)
	}
	return task.ID, nil
}

func (e *Engine) dispatchAgentCommand(ctx context.Context, pb *model.Playbook, run *model.PlaybookRun, action model.PlaybookAction, event TriggerEvent) (uuid.UUID, error) {
	argsJSON, err := json.Marshal(action.Args)
	if err != nil {
		return uuid.Nil, fmt.Errorf("marshal args: %w", err)
	}
	metadata := mergeMetadata(action.Metadata, map[string]string{
		"required_capabilities": "action",
		"playbook_id":           pb.ID.String(),
		"playbook_run_id":       run.ID.String(),
		"playbook_action":       action.Command,
		"playbook_action_args":  string(argsJSON),
		"playbook_event_agent":  event.Attributes["agent_id"],
	})
	payload := map[string]interface{}{
		"command": action.Command,
		"args":    action.Args,
	}
	data, err := json.Marshal(payload)
	if err != nil {
		return uuid.Nil, err
	}
	task := &model.Task{
		ID:        uuid.New(),
		Type:      model.TaskType("action"),
		Profile:   "default",
		Priority:  4,
		Payload:   data,
		Status:    model.TaskStatusPending,
		Metadata:  metadata,
		CreatedBy: fmt.Sprintf("playbook:%s", pb.Name),
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}
	if err := e.store.CreateTask(ctx, task); err != nil {
		return uuid.Nil, err
	}
	if err := e.sched.EnqueueTask(ctx, task); err != nil {
		return uuid.Nil, err
	}
	return task.ID, nil
}

func mergeMetadata(base map[string]string, extra map[string]string) map[string]string {
	if base == nil && extra == nil {
		return nil
	}
	result := make(map[string]string)
	for k, v := range base {
		result[k] = v
	}
	for k, v := range extra {
		if strings.TrimSpace(v) == "" {
			continue
		}
		result[k] = v
	}
	return result
}

func pointerTo(t time.Time) *time.Time {
	return &t
}
