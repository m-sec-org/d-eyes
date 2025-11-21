package adaptive

import (
	"context"
	"math"
	"sync"
	"time"

	"github.com/m-sec-org/d-eyes/agent/internal/telemetry"
	"github.com/m-sec-org/d-eyes/agent/pkg/config"
)

// Controller implements adaptive throttle logic for remote polling loop.
type Controller struct {
	cfg        config.AdaptiveConfig
	mu         sync.Mutex
	poll       time.Duration
	backoff    time.Duration
	lastScaled time.Time
}

func NewController(cfg config.AdaptiveConfig) *Controller {
	if cfg.BackoffInitial <= 0 {
		cfg.BackoffInitial = 2 * time.Second
	}
	if cfg.BackoffMax <= 0 {
		cfg.BackoffMax = 15 * time.Second
	}
	if cfg.MinPollInterval <= 0 {
		cfg.MinPollInterval = 1 * time.Second
	}
	if cfg.MaxPollInterval < cfg.MinPollInterval {
		cfg.MaxPollInterval = cfg.MinPollInterval * 5
	}
	if cfg.CPUCeilPercent <= 0 {
		cfg.CPUCeilPercent = 75
	}
	if cfg.MinCPUResumePercent <= 0 || cfg.MinCPUResumePercent >= cfg.CPUCeilPercent {
		cfg.MinCPUResumePercent = cfg.CPUCeilPercent - 15
	}
	if cfg.PriorityBoostLow <= 0 {
		cfg.PriorityBoostLow = 0.5
	}
	if cfg.PriorityBoostHigh <= cfg.PriorityBoostLow {
		cfg.PriorityBoostHigh = cfg.PriorityBoostLow + 0.5
	}
	return &Controller{
		cfg:     cfg,
		poll:    cfg.MinPollInterval,
		backoff: cfg.BackoffInitial,
	}
}

// NextDelay returns current polling interval.
func (c *Controller) NextDelay() time.Duration {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.poll
}

// RecordResult updates adaptive state after each poll cycle.
func (c *Controller) RecordResult(ctx context.Context, err error, tasksRan int, cpu float64) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if cpu <= 0 {
		cpu = telemetry.LatestCPUPercent()
	}
	now := time.Now()
	switch {
	case err != nil:
		c.backoff = minDuration(c.backoff*2, c.cfg.BackoffMax)
		c.poll = minDuration(c.poll+c.backoff, c.cfg.MaxPollInterval)
	case cpu >= c.cfg.CPUCeilPercent:
		if now.Sub(c.lastScaled) > time.Second {
			c.poll = minDuration(c.poll+c.cfg.MinPollInterval, c.cfg.MaxPollInterval)
			c.lastScaled = now
		}
	case cpu <= c.cfg.MinCPUResumePercent:
		c.poll = maxDuration(c.poll-c.cfg.MinPollInterval, c.cfg.MinPollInterval)
		c.backoff = c.cfg.BackoffInitial
	default:
		c.poll = clampDuration(c.poll, c.cfg.MinPollInterval, c.cfg.MaxPollInterval)
	}
	if tasksRan > 0 && cpu <= c.cfg.MinCPUResumePercent {
		c.poll = maxDuration(c.poll-c.cfg.MinPollInterval, c.cfg.MinPollInterval)
	}
}

func (c *Controller) BoostPriority(base int, cpu float64) int {
	if base <= 0 {
		base = 1
	}
	switch {
	case cpu >= c.cfg.CPUCeilPercent:
		return int(math.Max(1, float64(base)*c.cfg.PriorityBoostLow))
	case cpu <= c.cfg.MinCPUResumePercent:
		return int(math.Max(1, float64(base)*c.cfg.PriorityBoostHigh))
	default:
		return base
	}
}

func minDuration(a, b time.Duration) time.Duration {
	if a < b {
		return a
	}
	return b
}

func maxDuration(a, b time.Duration) time.Duration {
	if a > b {
		return a
	}
	return b
}

func clampDuration(v, min, max time.Duration) time.Duration {
	if v < min {
		return min
	}
	if v > max {
		return max
	}
	return v
}
