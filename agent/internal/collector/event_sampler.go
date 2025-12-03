package collector

import (
	"math/rand"
	"time"
)

type eventSampler struct {
	probability float64
	randFn      func() float64
	interval    time.Duration
	burst       int
	tokens      int
	nextReset   time.Time
}

func newEventSampler(cfg Sampling) *eventSampler {
	var sampler eventSampler
	if cfg.Rate > 0 && cfg.Rate < 1 {
		src := rand.New(rand.NewSource(time.Now().UnixNano()))
		sampler.probability = cfg.Rate
		sampler.randFn = src.Float64
	}
	if cfg.Interval > 0 {
		sampler.interval = cfg.Interval
		if cfg.Burst > 0 {
			sampler.burst = cfg.Burst
		} else {
			sampler.burst = 1
		}
		sampler.tokens = sampler.burst
		sampler.nextReset = time.Now().Add(sampler.interval)
	}
	if sampler.probability == 0 && sampler.interval == 0 {
		return nil
	}
	return &sampler
}

func (s *eventSampler) allow(now time.Time) bool {
	if s == nil {
		return true
	}
	if s.probability > 0 && s.randFn != nil {
		if s.randFn() > s.probability {
			return false
		}
	}
	if s.interval <= 0 {
		return true
	}
	if now.After(s.nextReset) {
		s.tokens = s.burst
		s.nextReset = now.Add(s.interval)
	}
	if s.tokens <= 0 {
		return false
	}
	s.tokens--
	return true
}
