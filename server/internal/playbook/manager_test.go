package playbook

import (
	"context"
	"testing"

	"github.com/google/uuid"

	"github.com/m-sec-org/d-eyes/server/internal/model"
	"github.com/m-sec-org/d-eyes/server/internal/store"
)

type fakeStore struct {
	store.Store
	playbooks map[uuid.UUID]*model.Playbook
}

func newFakeStore() *fakeStore {
	return &fakeStore{playbooks: make(map[uuid.UUID]*model.Playbook)}
}

func (f *fakeStore) CreatePlaybook(_ context.Context, pb *model.Playbook) error {
	cp := *pb
	f.playbooks[pb.ID] = &cp
	return nil
}

func (f *fakeStore) UpdatePlaybook(_ context.Context, pb *model.Playbook) error {
	cp := *pb
	f.playbooks[pb.ID] = &cp
	return nil
}

func (f *fakeStore) GetPlaybook(_ context.Context, id uuid.UUID) (*model.Playbook, error) {
	if pb, ok := f.playbooks[id]; ok {
		cp := *pb
		return &cp, nil
	}
	return nil, store.ErrNotFound
}

func TestUpdateApprovalFlow(t *testing.T) {
	fs := newFakeStore()
	mgr := &Manager{store: fs}
	pb := &model.Playbook{
		ID:        uuid.New(),
		Name:      "Test",
		Trigger:   model.PlaybookTrigger{Type: "manual"},
		Actions:   []model.PlaybookAction{{Type: "notify", Target: "ops"}},
		Approvals: []model.PlaybookApproval{{Role: "sec"}, {Role: "ops"}},
		Status:    "draft",
	}
	if err := mgr.Create(context.Background(), pb); err != nil {
		t.Fatalf("create playbook: %v", err)
	}
	updated, err := mgr.UpdateApproval(context.Background(), pb.ID, "sec", "alice", "approve", "ok")
	if err != nil {
		t.Fatalf("first approval: %v", err)
	}
	if updated.ApprovalStates[0].Status != model.PlaybookApprovalApproved {
		t.Fatalf("expected first approval approved")
	}
	if updated.Status == "approved" {
		t.Fatalf("should not be fully approved yet")
	}
	updated, err = mgr.UpdateApproval(context.Background(), pb.ID, "ops", "bob", "approve", "")
	if err != nil {
		t.Fatalf("second approval: %v", err)
	}
	if updated.Status != "approved" {
		t.Fatalf("expected playbook approved, got %s", updated.Status)
	}
}
