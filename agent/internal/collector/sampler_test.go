package collector

import "testing"

func TestDynamicSamplerRate(t *testing.T) {
	sampler := newDynamicSampler(Sampling{Rate: 0.0})
	if !sampler.ShouldSample("event", nil) {
		t.Fatalf("sampler should default to rate=1 when unspecified")
	}
	_ = sampler.UpdateConfig(Sampling{Rate: 0.5})
	hits := 0
	for i := 0; i < 1000; i++ {
		if sampler.ShouldSample("event", nil) {
			hits++
		}
	}
	if hits == 0 || hits == 1000 {
		t.Fatalf("expected probabilistic sampling, got %d hits", hits)
	}
}

func TestDynamicSamplerRules(t *testing.T) {
	sampler := newDynamicSampler(Sampling{
		Rules: []SamplingRule{
			{
				Name:       "process",
				EventTypes: []string{"process.exec"},
				Match: map[string][]string{
					"level": {"5"},
				},
				Rate:    0.0,
				Enabled: true,
			},
		},
	})
	meta := map[string]string{"level": "5"}
	if len(sampler.rules) == 0 {
		t.Fatalf("expected rules to be copied")
	}
	if rate := sampler.determineRate("process.exec", meta); rate != 0 {
		t.Fatalf("expected rate 0, got %f", rate)
	}
	for i := 0; i < 10; i++ {
		if sampler.ShouldSample("process.exec", meta) {
			t.Fatalf("expected rule to drop events")
		}
	}
	if !sampler.ShouldSample("process.exit", meta) {
		t.Fatalf("expected unrelated events to pass")
	}
}

func TestDynamicSamplerAdaptiveScale(t *testing.T) {
	sampler := newDynamicSampler(Sampling{Rate: 1.0})
	hits := 0
	for i := 0; i < 1000; i++ {
		if sampler.ShouldSample("event", nil) {
			hits++
		}
	}
	if hits < 900 {
		t.Fatalf("expected near full sampling before scaling, got %d", hits)
	}
	sampler.SetAdaptiveScale(0.0)
	for i := 0; i < 50; i++ {
		if sampler.ShouldSample("event", nil) {
			t.Fatalf("expected sampler to drop events after scaling")
		}
	}
	stats := sampler.Stats()
	if stats.Scale != 0 {
		t.Fatalf("expected stats scale to reflect adaptive scaling, got %f", stats.Scale)
	}
	sampler.SetAdaptiveScale(0.5)
	stats = sampler.Stats()
	if stats.Scale != 0.5 {
		t.Fatalf("expected sampler scale 0.5, got %f", stats.Scale)
	}
}
