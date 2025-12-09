package collector

import (
	"math/rand"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

type dynamicSampler struct {
	mu        sync.RWMutex
	baseRate  float64
	rules     []SamplingRule
	rng       *rand.Rand
	sampled   uint64
	skipped   uint64
	updatedAt atomic.Int64
	scale     float64
}

func newDynamicSampler(cfg Sampling) *dynamicSampler {
	ds := &dynamicSampler{
		rng:   rand.New(rand.NewSource(time.Now().UnixNano())),
		scale: 1.0,
	}
	_ = ds.UpdateConfig(cfg)
	return ds
}

func (s *dynamicSampler) ShouldSample(eventType string, metadata map[string]string) bool {
	rate := s.determineRate(eventType, metadata)
	if rate >= 1 {
		atomic.AddUint64(&s.sampled, 1)
		return true
	}
	if rate <= 0 {
		atomic.AddUint64(&s.skipped, 1)
		return false
	}
	if s.random() <= rate {
		atomic.AddUint64(&s.sampled, 1)
		return true
	}
	atomic.AddUint64(&s.skipped, 1)
	return false
}

func (s *dynamicSampler) UpdateConfig(cfg Sampling) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if cfg.Rate <= 0 {
		s.baseRate = 1.0
	} else if cfg.Rate > 1 {
		s.baseRate = 1.0
	} else {
		s.baseRate = cfg.Rate
	}
	if len(cfg.Rules) > 0 {
		s.rules = make([]SamplingRule, len(cfg.Rules))
		copy(s.rules, cfg.Rules)
	} else {
		s.rules = nil
	}
	s.updatedAt.Store(time.Now().Unix())
	if s.scale <= 0 {
		s.scale = 1.0
	}
	return nil
}

func (s *dynamicSampler) Stats() SamplerStats {
	return SamplerStats{
		Sampled:   atomic.LoadUint64(&s.sampled),
		Skipped:   atomic.LoadUint64(&s.skipped),
		UpdatedAt: s.updatedAt.Load(),
		Scale:     s.currentScale(),
	}
}

func (s *dynamicSampler) determineRate(eventType string, metadata map[string]string) float64 {
	s.mu.RLock()
	base := s.baseRate
	rules := s.rules
	scale := s.scale
	s.mu.RUnlock()
	for _, rule := range rules {
		if !rule.Enabled {
			continue
		}
		if len(rule.EventTypes) > 0 && !contains(rule.EventTypes, eventType) {
			continue
		}
		if len(rule.Match) > 0 && !matchesMetadata(rule.Match, metadata) {
			continue
		}
		return clampRate(rule.Rate * scale)
	}
	return clampRate(base * scale)
}

func (s *dynamicSampler) random() float64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.rng.Float64()
}

func clampRate(rate float64) float64 {
	if rate <= 0 {
		return 0
	}
	if rate >= 1 {
		return 1
	}
	return rate
}

func (s *dynamicSampler) SetAdaptiveScale(scale float64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if scale <= 0 {
		s.scale = 0
	} else if scale >= 1 {
		s.scale = 1
	} else {
		s.scale = scale
	}
}

func (s *dynamicSampler) currentScale() float64 {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.scale <= 0 {
		return 0
	}
	if s.scale > 1 {
		return 1
	}
	return s.scale
}

func matchesMetadata(match map[string][]string, metadata map[string]string) bool {
	if len(match) == 0 {
		return true
	}
	if metadata == nil {
		return false
	}
	for key, vals := range match {
		actual := metadata[key]
		found := false
		for _, val := range vals {
			if strings.EqualFold(actual, val) {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}
