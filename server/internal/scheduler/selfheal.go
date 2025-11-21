package scheduler

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/google/uuid"

	"github.com/m-sec-org/d-eyes/server/internal/model"
)

// StartSelfHeal launches a background routine that requeues tasks for offline agents.
func (s *Scheduler) StartSelfHeal(ctx context.Context, logger *slog.Logger) context.CancelFunc {
	if s == nil {
		return func() {}
	}
	interval := s.cfg.SelfHealInterval
	if interval <= 0 {
		interval = time.Minute
	}
	heartbeat := s.cfg.HeartbeatTimeout
	if heartbeat <= 0 {
		heartbeat = 30 * time.Second
	}
	ctx, cancel := context.WithCancel(ctx)
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				if _, err := s.selfHealTick(ctx, heartbeat, logger); err != nil && logger != nil {
					logger.Error("self-heal tick failed", "error", err)
				}
			}
		}
	}()
	return cancel
}

func (s *Scheduler) selfHealTick(ctx context.Context, heartbeat time.Duration, logger *slog.Logger) (map[string]int, error) {
	summary := make(map[string]int)
	agents, err := s.store.ListAgents(ctx)
	if err != nil {
		return summary, err
	}
	cutoff := time.Now().Add(-heartbeat)
	for _, agent := range agents {
		if agent == nil {
			continue
		}
		if s.agentHealthy(agent, cutoff) {
			continue
		}
		count, err := s.RecoverAgentTasks(ctx, agent.ID)
		if err != nil {
			return summary, err
		}
		if count > 0 {
			summary[agent.ID.String()] = count
			if logger != nil {
				logger.Info("self-heal recovered tasks", "agent", agent.Name, "agent_id", agent.ID.String(), "count", count)
			}
		}
	}
	return summary, nil
}

func (s *Scheduler) agentHealthy(agent *model.Agent, cutoff time.Time) bool {
	if agent == nil {
		return true
	}
	if agent.Status != model.AgentStatusOffline && (agent.LastHeartbeat.IsZero() || agent.LastHeartbeat.After(cutoff)) {
		return true
	}
	return false
}

// RecoverOfflineAgents manually requeues tasks for all offline agents.
func (s *Scheduler) RecoverOfflineAgents(ctx context.Context) (map[string]int, error) {
	heartbeat := s.cfg.HeartbeatTimeout
	if heartbeat <= 0 {
		heartbeat = 30 * time.Second
	}
	return s.selfHealTick(ctx, heartbeat, nil)
}

// RecoverAgentTasks requeues leased/running tasks for a single agent.
func (s *Scheduler) RecoverAgentTasks(ctx context.Context, agentID uuid.UUID) (int, error) {
	if s == nil {
		return 0, nil
	}
	if agentID == uuid.Nil {
		return 0, fmt.Errorf("empty agent id")
	}
	limit := s.cfg.SelfHealBatch
	if limit <= 0 {
		limit = 200
	}
	statuses := []model.TaskStatus{model.TaskStatusLeased, model.TaskStatusRunning}
	total := 0
	for {
		runs, err := s.store.ListTaskRunsByAgent(ctx, agentID, statuses, limit)
		if err != nil {
			return total, err
		}
		if len(runs) == 0 {
			break
		}
		for _, run := range runs {
			if run == nil {
				continue
			}
			run.LeaseExpires = time.Now().Add(-time.Second)
			if err := s.HandleLeaseTimeout(ctx, run); err != nil {
				return total, err
			}
			total++
		}
		if len(runs) < limit {
			break
		}
	}
	return total, nil
}
