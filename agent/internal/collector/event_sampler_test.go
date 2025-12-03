package collector

import (
	"testing"
	"time"
)

func TestEventSamplerRate(t *testing.T) {
	s := newEventSampler(Sampling{Rate: 0.5})
	if s == nil {
		t.Fatalf("expected sampler for rate sampling")
	}
	s.randFn = func() float64 { return 0.6 }
	if s.allow(time.Now()) {
		t.Fatalf("expected drop when rand>rate")
	}
	s.randFn = func() float64 { return 0.4 }
	if !s.allow(time.Now()) {
		t.Fatalf("expected allow when rand<rate")
	}
}

func TestEventSamplerIntervalBurst(t *testing.T) {
	interval := 5 * time.Millisecond
	s := newEventSampler(Sampling{Interval: interval, Burst: 2})
	if s == nil {
		t.Fatalf("expected sampler for interval control")
	}
	now := time.Now()
	if !s.allow(now) || !s.allow(now) {
		t.Fatalf("expected first two events to pass")
	}
	if s.allow(now) {
		t.Fatalf("expected third event to be throttled")
	}
	if !s.allow(now.Add(2 * interval)) {
		t.Fatalf("expected allowance reset after interval")
	}
}

func TestEventSamplerNilAndCombinedModes(t *testing.T) {
	var nilSampler *eventSampler
	if !nilSampler.allow(time.Now()) {
		t.Fatalf("nil sampler should allow events")
	}
	s := newEventSampler(Sampling{})
	if s != nil {
		t.Fatalf("expected nil sampler when config disables sampling")
	}
	interval := 2 * time.Millisecond
	s = newEventSampler(Sampling{Rate: 0.5, Interval: interval})
	if s == nil {
		t.Fatalf("expected sampler when rate and interval are configured")
	}
	s.randFn = func() float64 { return 0.4 }
	now := time.Now()
	if !s.allow(now) {
		t.Fatalf("expected first event to pass when rand<rate")
	}
	s.randFn = func() float64 { return 0.9 }
	if s.allow(now) {
		t.Fatalf("expected event to be dropped when rand>rate")
	}
	s.randFn = func() float64 { return 0.4 }
	if s.allow(now) {
		t.Fatalf("expected interval limiter to hold when tokens exhausted")
	}
	if !s.allow(now.Add(2 * interval)) {
		t.Fatalf("expected limiter to reset after interval elapses")
	}
}
