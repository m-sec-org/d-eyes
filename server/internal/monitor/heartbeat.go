package monitor

import (
	"context"
	"log/slog"
	"time"

	"github.com/m-sec-org/d-eyes/server/internal/config"
	"github.com/m-sec-org/d-eyes/server/internal/model"
	"github.com/m-sec-org/d-eyes/server/internal/store"
)

func StartHeartbeat(ctx context.Context, st store.Store, cfg config.SchedulerConfig, logger *slog.Logger) context.CancelFunc {
	timeout := cfg.HeartbeatTimeout
	if timeout <= 0 {
		timeout = 30 * time.Second
	}
	interval := timeout / 2
	if interval <= 0 {
		interval = timeout
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
				checkAgents(ctx, st, timeout, logger)
			}
		}
	}()
	return cancel
}

func checkAgents(ctx context.Context, st store.Store, timeout time.Duration, logger *slog.Logger) {
	agents, err := st.ListAgents(ctx)
	if err != nil {
		logger.Error("list agents for heartbeat", "error", err)
		return
	}
	now := time.Now()
	for _, agent := range agents {
		if agent.LastHeartbeat.IsZero() {
			continue
		}
		if now.Sub(agent.LastHeartbeat) <= timeout {
			continue
		}
		if agent.Status == model.AgentStatusOffline {
			continue
		}
		if err := st.UpdateAgentStatus(ctx, agent.ID, model.AgentStatusOffline, agent.LastHeartbeat, 0, nil, nil); err != nil {
			logger.Error("mark agent offline", "agent", agent.ID, "error", err)
			continue
		}
		logger.Info("agent heartbeat timeout", "agent", agent.ID.String())
	}
}
