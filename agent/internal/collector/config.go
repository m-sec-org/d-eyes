package collector

import (
	"github.com/m-sec-org/d-eyes/agent/pkg/config"
)

// FromAppConfig converts CLI/Probe collector definitions to runtime configs.
func FromAppConfig(cfg config.Config) []Config {
	result := make([]Config, 0, len(cfg.Collectors))
	for _, src := range cfg.Collectors {
		if src.Name == "" || src.Kind == "" {
			continue
		}
		rc := Config{
			Name:      src.Name,
			Kind:      Kind(src.Kind),
			Disabled:  src.Disabled,
			Providers: append([]string(nil), src.Providers...),
			Probes:    append([]string(nil), src.Probes...),
			Filters: Filters{
				Include: cloneStringSliceMap(src.Filters.Include),
				Exclude: cloneStringSliceMap(src.Filters.Exclude),
			},
			Sampling: Sampling{
				Rate:              src.Sampling.Rate,
				Interval:          src.Sampling.Interval,
				Burst:             src.Sampling.Burst,
				MaxEventsPerBatch: src.Sampling.MaxEventsPerBatch,
			},
			Output: Output{
				Mode:       src.Output.Mode,
				Path:       src.Output.Path,
				BufferSize: src.Output.BufferSize,
				BatchSize:  src.Output.BatchSize,
				Stream: CollectorStreamConfig{
					URL:           src.Output.Stream.URL,
					APIKey:        src.Output.Stream.APIKey,
					AgentID:       src.Output.Stream.AgentID,
					AgentName:     src.Output.Stream.AgentName,
					MaxBatch:      src.Output.Stream.MaxBatch,
					FlushInterval: src.Output.Stream.FlushInterval,
				},
			},
			Settings: cloneAnyMap(src.Settings),
		}
		result = append(result, rc)
	}
	return result
}

func cloneStringSliceMap(input map[string][]string) map[string][]string {
	if len(input) == 0 {
		return nil
	}
	out := make(map[string][]string, len(input))
	for key, vals := range input {
		out[key] = append([]string(nil), vals...)
	}
	return out
}

func cloneAnyMap(input map[string]any) map[string]any {
	if len(input) == 0 {
		return nil
	}
	out := make(map[string]any, len(input))
	for k, v := range input {
		out[k] = v
	}
	return out
}
