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
			Parser: ParserConfig{
				Enabled:  append([]string(nil), src.Parser.Enabled...),
				Disabled: append([]string(nil), src.Parser.Disabled...),
				Plugins:  convertParserPlugins(src.Parser.Plugins),
				Settings: cloneAnyMap(src.Parser.Settings),
			},
			Filters: Filters{
				Include: cloneStringSliceMap(src.Filters.Include),
				Exclude: cloneStringSliceMap(src.Filters.Exclude),
				Rules:   convertFilterRules(src.Filters.Rules),
			},
			Sampling: Sampling{
				Rate:              src.Sampling.Rate,
				Interval:          src.Sampling.Interval,
				Burst:             src.Sampling.Burst,
				MaxEventsPerBatch: src.Sampling.MaxEventsPerBatch,
				Rules:             convertSamplingRules(src.Sampling.Strategies),
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

func convertParserPlugins(items []config.CollectorParserPluginConfig) []ParserPluginConfig {
	if len(items) == 0 {
		return nil
	}
	out := make([]ParserPluginConfig, 0, len(items))
	for _, item := range items {
		out = append(out, ParserPluginConfig{
			Name:     item.Name,
			Path:     item.Path,
			Type:     item.Type,
			Checksum: item.Checksum,
			Config:   cloneAnyMap(item.Config),
			Enabled:  item.Enabled,
			Metadata: cloneStringMap(item.Metadata),
		})
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func convertFilterRules(items []config.CollectorFilterRuleConfig) []FilterRule {
	if len(items) == 0 {
		return nil
	}
	out := make([]FilterRule, 0, len(items))
	for _, item := range items {
		rule := FilterRule{
			Name:       item.Name,
			Action:     item.Action,
			Conditions: convertFilterConditions(item.Conditions),
			Tags:       cloneStringMap(item.Tags),
			Threshold: FilterThreshold{
				Count:  item.Threshold.Count,
				Window: item.Threshold.Window,
			},
			Enabled: item.Enabled,
		}
		out = append(out, rule)
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func convertFilterConditions(items []config.CollectorFilterConditionConfig) []FilterCondition {
	if len(items) == 0 {
		return nil
	}
	out := make([]FilterCondition, 0, len(items))
	for _, item := range items {
		out = append(out, FilterCondition{
			Field:    item.Field,
			Operator: item.Operator,
			Value:    item.Value,
			Values:   append([]string(nil), item.Values...),
			Regex:    item.Regex,
		})
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func convertSamplingRules(items []config.CollectorSamplingStrategyConfig) []SamplingRule {
	if len(items) == 0 {
		return nil
	}
	out := make([]SamplingRule, 0, len(items))
	for _, item := range items {
		out = append(out, SamplingRule{
			Name:       item.Name,
			EventTypes: append([]string(nil), item.EventTypes...),
			Match:      cloneStringSliceMap(item.Match),
			Rate:       item.Rate,
			Burst:      item.Burst,
			Window:     item.Window,
			Enabled:    item.Enabled,
		})
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func cloneStringMap(input map[string]string) map[string]string {
	if len(input) == 0 {
		return nil
	}
	out := make(map[string]string, len(input))
	for k, v := range input {
		out[k] = v
	}
	return out
}
