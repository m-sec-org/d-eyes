package adaptive

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/m-sec-org/d-eyes/agent/pkg/config"
)

func TestControllerAdjustsPollingIntervals(t *testing.T) {
	cfg := defaultAdaptiveTestConfig()
	ctrl := NewController(cfg)
	require.Equal(t, cfg.MinPollInterval, ctrl.NextDelay())

	ctrl.RecordResult(context.Background(), nil, 0, cfg.MinCPUResumePercent-10)
	require.Equal(t, cfg.MinPollInterval, ctrl.NextDelay())

	ctrl.RecordResult(context.Background(), nil, 0, cfg.CPUCeilPercent+5)
	require.GreaterOrEqual(t, ctrl.NextDelay(), cfg.MinPollInterval)
}

func defaultAdaptiveTestConfig() config.AdaptiveConfig {
	return config.AdaptiveConfig{
		CPUCeilPercent:      70,
		MinCPUResumePercent: 50,
		BackoffInitial:      time.Second,
		BackoffMax:          5 * time.Second,
		MinPollInterval:     time.Second,
		MaxPollInterval:     10 * time.Second,
		PriorityBoostLow:    0.5,
		PriorityBoostHigh:   1.5,
	}
}
