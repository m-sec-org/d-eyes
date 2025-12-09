package eventing

import (
	"encoding/json"
	"io"
	"log/slog"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
	"github.com/stretchr/testify/require"

	"github.com/m-sec-org/d-eyes/server/internal/config"
	"github.com/m-sec-org/d-eyes/server/internal/metrics"
	"github.com/m-sec-org/d-eyes/server/internal/model"
)

func TestSchemaParserValidatePayloadAndMetadata(t *testing.T) {
	parserCfg := config.EventParserConfig{
		Name:             "process-schema",
		Enabled:          true,
		EventTypes:       []string{"process.exec"},
		Sources:          []string{"ebpf"},
		RequiredMetadata: []string{"collector"},
		RequiredPayload:  []string{"pid", "image.path"},
	}
	parser, err := newSchemaParser(parserCfg)
	if err != nil {
		t.Fatalf("newSchemaParser: %v", err)
	}
	payload := map[string]any{
		"pid": 1234,
		"image": map[string]any{
			"path": "/bin/bash",
		},
	}
	raw, _ := json.Marshal(payload)
	event := &model.SystemEventRecord{
		EventType: "process.exec",
		Source:    "ebpf",
		Metadata:  map[string]string{"collector": "diag-ebpf"},
		Payload:   raw,
	}
	if !parser.Matches(event) {
		t.Fatalf("parser should match event")
	}
	if err := parser.Normalize(event); err != nil {
		t.Fatalf("Normalize should succeed, got %v", err)
	}
}

func TestSchemaParserFailsOnMissingFields(t *testing.T) {
	parserCfg := config.EventParserConfig{
		Name:             "fs-schema",
		Enabled:          true,
		EventTypes:       []string{"fs.open"},
		RequiredMetadata: []string{"collector"},
		RequiredPayload:  []string{"path"},
	}
	parser, err := newSchemaParser(parserCfg)
	if err != nil {
		t.Fatalf("newSchemaParser: %v", err)
	}
	event := &model.SystemEventRecord{
		EventType: "fs.open",
		Metadata:  map[string]string{},
		Payload:   json.RawMessage(`{"pid": 1}`),
	}
	if err := parser.Normalize(event); err == nil {
		t.Fatalf("expected error for missing fields")
	}
}

func TestParserRegistryMetrics(t *testing.T) {
	cfg := config.EventsConfig{
		Parsers: []config.EventParserConfig{
			{
				Name:             "process-schema",
				Enabled:          true,
				EventTypes:       []string{"process.exec"},
				RequiredMetadata: []string{"collector"},
			},
		},
	}
	promReg := prometheus.NewRegistry()
	metricsCollector := metrics.New(promReg)
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	registry, err := NewParserRegistry(cfg, metricsCollector, log)
	require.NoError(t, err)

	require.Equal(t, 1.0, readGaugeValue(t, metricsCollector.SystemEventParsersConfigured.WithLabelValues("process-schema")))

	event := &model.SystemEventRecord{
		EventType: "process.exec",
	}
	err = registry.Normalize(event)
	require.Error(t, err)
	require.Equal(t, 1.0, readCounterValue(t, metricsCollector.SystemEventParserFailures.WithLabelValues("process-schema", "metadata_missing")))
}

func readGaugeValue(t *testing.T, gauge prometheus.Gauge) float64 {
	t.Helper()
	var metric dto.Metric
	require.NoError(t, gauge.Write(&metric))
	return metric.GetGauge().GetValue()
}

func readCounterValue(t *testing.T, counter prometheus.Counter) float64 {
	t.Helper()
	var metric dto.Metric
	require.NoError(t, counter.Write(&metric))
	return metric.GetCounter().GetValue()
}
