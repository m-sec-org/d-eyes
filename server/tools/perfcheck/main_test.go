package main

import (
	"testing"

	dto "github.com/prometheus/client_model/go"
	"google.golang.org/protobuf/proto"
)

func TestHistogramQuantile(t *testing.T) {
	fam := newHistogramMetricFamily(map[float64]uint64{
		10: 1,
		20: 2,
		30: 1,
	}, 4)
	got, err := histogramQuantile("test_metric", fam, 0.95)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != 30 {
		t.Fatalf("expected 30, got %.2f", got)
	}
}

func TestTaskFailureRate(t *testing.T) {
	fam := &dto.MetricFamily{
		Metric: []*dto.Metric{
			{
				Label: []*dto.LabelPair{
					{Name: proto.String("status"), Value: proto.String("succeeded")},
				},
				Counter: &dto.Counter{Value: proto.Float64(99)},
			},
			{
				Label: []*dto.LabelPair{
					{Name: proto.String("status"), Value: proto.String("failed")},
				},
				Counter: &dto.Counter{Value: proto.Float64(1)},
			},
		},
	}
	got, err := taskFailureRate(fam)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got < 0.0099 || got > 0.0101 {
		t.Fatalf("expected ~0.01, got %.5f", got)
	}
}

func TestHistogramQuantileMissing(t *testing.T) {
	if _, err := histogramQuantile("missing_metric", nil, 0.95); err == nil {
		t.Fatalf("expected error for missing histogram")
	}
}
