package playbook

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/m-sec-org/d-eyes/server/internal/model"
	"github.com/m-sec-org/d-eyes/server/internal/store"
)

type Manager struct {
	store store.Store
	log   *slog.Logger
}

func NewManager(st store.Store, logger *slog.Logger) *Manager {
	if st == nil {
		return nil
	}
	if logger == nil {
		logger = slog.Default()
	}
	return &Manager{store: st, log: logger}
}

func (m *Manager) Enabled() bool {
	return m != nil && m.store != nil
}

func (m *Manager) Create(ctx context.Context, pb *model.Playbook) error {
	if !m.Enabled() {
		return fmt.Errorf("playbook manager disabled")
	}
	if err := validatePlaybook(pb); err != nil {
		return err
	}
	if pb.ID == uuid.Nil {
		pb.ID = uuid.New()
	}
	if pb.Status == "" {
		pb.Status = "draft"
	}
	pb.Version = 1
	pb.CreatedAt = time.Now()
	pb.UpdatedAt = pb.CreatedAt
	prepareApprovalStates(pb, pb.CreatedAt)
	return m.store.CreatePlaybook(ctx, pb)
}

func (m *Manager) Update(ctx context.Context, pb *model.Playbook) error {
	if err := validatePlaybook(pb); err != nil {
		return err
	}
	pb.UpdatedAt = time.Now()
	prepareApprovalStates(pb, pb.UpdatedAt)
	return m.store.UpdatePlaybook(ctx, pb)
}

func (m *Manager) Get(ctx context.Context, id uuid.UUID) (*model.Playbook, error) {
	if !m.Enabled() {
		return nil, fmt.Errorf("playbook manager disabled")
	}
	return m.store.GetPlaybook(ctx, id)
}

func (m *Manager) List(ctx context.Context, limit int) ([]*model.Playbook, error) {
	if !m.Enabled() {
		return nil, fmt.Errorf("playbook manager disabled")
	}
	return m.store.ListPlaybooks(ctx, limit)
}

func (m *Manager) SetStatus(ctx context.Context, id uuid.UUID, status, actor string) (*model.Playbook, error) {
	pb, err := m.Get(ctx, id)
	if err != nil {
		return nil, err
	}
	now := time.Now()
	prepareApprovalStates(pb, now)
	nextStatus := strings.ToLower(strings.TrimSpace(status))
	switch nextStatus {
	case "draft", "disabled", "inactive":
	case "approved":
		if len(pb.ApprovalStates) == 0 {
			return nil, fmt.Errorf("no approval chain configured")
		}
		if !allApprovalsApproved(pb.ApprovalStates) {
			return nil, fmt.Errorf("playbook approvals incomplete")
		}
	case "active":
		if len(pb.ApprovalStates) > 0 && !allApprovalsApproved(pb.ApprovalStates) {
			return nil, fmt.Errorf("playbook approvals incomplete")
		}
	default:
		return nil, fmt.Errorf("unsupported status %q", status)
	}
	pb.Status = nextStatus
	pb.UpdatedBy = actor
	if (nextStatus == "approved" || nextStatus == "active") && pb.ApprovedBy == "" {
		pb.ApprovedBy = actor
	}
	if err := m.store.UpdatePlaybook(ctx, pb); err != nil {
		return nil, err
	}
	return pb, nil
}

// UpdateApproval updates a specific approval step.
func (m *Manager) UpdateApproval(ctx context.Context, id uuid.UUID, role, actor, action, notes string) (*model.Playbook, error) {
	if !m.Enabled() {
		return nil, fmt.Errorf("playbook manager disabled")
	}
	pb, err := m.store.GetPlaybook(ctx, id)
	if err != nil {
		return nil, err
	}
	now := time.Now()
	prepareApprovalStates(pb, now)
	targetRole := strings.ToLower(strings.TrimSpace(role))
	if targetRole == "" {
		return nil, fmt.Errorf("approval role required")
	}
	idx := -1
	for i, state := range pb.ApprovalStates {
		if strings.ToLower(state.Role) == targetRole {
			idx = i
			break
		}
	}
	if idx == -1 {
		return nil, fmt.Errorf("role %q not found in approval chain", role)
	}
	for i := 0; i < idx; i++ {
		if pb.ApprovalStates[i].Status != model.PlaybookApprovalApproved {
			return nil, fmt.Errorf("previous approval %q pending", pb.ApprovalStates[i].Role)
		}
	}
	switch strings.ToLower(strings.TrimSpace(action)) {
	case "approve":
		pb.ApprovalStates[idx].Status = model.PlaybookApprovalApproved
	case "reject":
		pb.ApprovalStates[idx].Status = model.PlaybookApprovalRejected
	default:
		return nil, fmt.Errorf("unsupported approval action %q", action)
	}
	pb.ApprovalStates[idx].Actor = actor
	pb.ApprovalStates[idx].Notes = notes
	pb.ApprovalStates[idx].UpdatedAt = now
	pb.UpdatedBy = actor
	if pb.ApprovalStates[idx].Status == model.PlaybookApprovalRejected {
		pb.Status = "rejected"
	} else if allApprovalsApproved(pb.ApprovalStates) {
		pb.Status = "approved"
		pb.ApprovedBy = actor
	}
	if err := m.store.UpdatePlaybook(ctx, pb); err != nil {
		return nil, err
	}
	return pb, nil
}

func (m *Manager) RecordRun(ctx context.Context, run *model.PlaybookRun) error {
	if !m.Enabled() {
		return fmt.Errorf("playbook manager disabled")
	}
	return m.store.CreatePlaybookRun(ctx, run)
}

func (m *Manager) UpdateRun(ctx context.Context, run *model.PlaybookRun) error {
	if !m.Enabled() {
		return fmt.Errorf("playbook manager disabled")
	}
	return m.store.UpdatePlaybookRun(ctx, run)
}

func (m *Manager) ListRuns(ctx context.Context, playbookID uuid.UUID, limit int) ([]*model.PlaybookRun, error) {
	if !m.Enabled() {
		return nil, fmt.Errorf("playbook manager disabled")
	}
	return m.store.ListPlaybookRuns(ctx, playbookID, limit)
}

func validatePlaybook(pb *model.Playbook) error {
	if pb == nil {
		return fmt.Errorf("playbook required")
	}
	if strings.TrimSpace(pb.Name) == "" {
		return fmt.Errorf("playbook name required")
	}
	if strings.TrimSpace(pb.Trigger.Type) == "" {
		return fmt.Errorf("playbook trigger type required")
	}
	if len(pb.Actions) == 0 {
		return fmt.Errorf("playbook requires at least one action")
	}
	for idx, action := range pb.Actions {
		if err := validateAction(action); err != nil {
			return fmt.Errorf("action[%d]: %w", idx, err)
		}
	}
	return nil
}

func validateAction(action model.PlaybookAction) error {
	switch action.Type {
	case "notify":
		if strings.TrimSpace(action.Target) == "" && action.Metadata == nil {
			return fmt.Errorf("notify action missing target")
		}
	case "task.dispatch":
		if strings.TrimSpace(action.TaskType) == "" {
			return fmt.Errorf("task.dispatch requires task_type")
		}
		if action.Payload != nil {
			if _, err := json.Marshal(action.Payload); err != nil {
				return fmt.Errorf("task.dispatch payload invalid: %w", err)
			}
		}
	case "agent.command":
		if strings.TrimSpace(action.Command) == "" {
			return fmt.Errorf("agent.command requires command")
		}
	case "http.webhook":
		if strings.TrimSpace(action.Target) == "" {
			return fmt.Errorf("http.webhook requires target URL")
		}
	default:
		return fmt.Errorf("unsupported action type %q", action.Type)
	}
	return nil
}

func prepareApprovalStates(pb *model.Playbook, now time.Time) {
	if pb == nil {
		return
	}
	if len(pb.Approvals) == 0 {
		pb.ApprovalStates = nil
		return
	}
	states := make([]model.PlaybookApprovalState, len(pb.Approvals))
	for i, approval := range pb.Approvals {
		if i < len(pb.ApprovalStates) {
			state := pb.ApprovalStates[i]
			if strings.TrimSpace(state.Role) == "" {
				state.Role = approval.Role
			}
			if state.Status == "" {
				state.Status = model.PlaybookApprovalPending
				state.UpdatedAt = now
			}
			states[i] = state
		} else {
			states[i] = model.PlaybookApprovalState{
				Role:      approval.Role,
				Status:    model.PlaybookApprovalPending,
				UpdatedAt: now,
			}
		}
	}
	pb.ApprovalStates = states
}

func allApprovalsApproved(states []model.PlaybookApprovalState) bool {
	if len(states) == 0 {
		return false
	}
	for _, state := range states {
		if state.Status != model.PlaybookApprovalApproved {
			return false
		}
	}
	return true
}
