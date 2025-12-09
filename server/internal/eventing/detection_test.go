package eventing

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"sync"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/require"

	"github.com/m-sec-org/d-eyes/server/internal/config"
	"github.com/m-sec-org/d-eyes/server/internal/metrics"
	"github.com/m-sec-org/d-eyes/server/internal/model"
	"github.com/m-sec-org/d-eyes/server/internal/queue/memory"
	"github.com/m-sec-org/d-eyes/server/internal/scheduler"
	"github.com/m-sec-org/d-eyes/server/internal/store"
	"github.com/m-sec-org/d-eyes/server/internal/streams"
	"github.com/m-sec-org/d-eyes/server/internal/threatintel"
)

func TestDetectionEngineRuleCreatesRespondTaskAndAlert(t *testing.T) {
	gin.SetMode(gin.TestMode)
	st := store.NewInMemoryStore()
	queue := memory.New()
	sched := scheduler.New(st, queue, config.SchedulerConfig{
		LeaseTTL:             time.Second,
		MaxRetries:           1,
		HeartbeatTimeout:     time.Second,
		QueueCapacity:        16,
		LeasePollInterval:    time.Millisecond,
		MaxAgentConcurrency:  2,
		GlobalMaxConcurrency: 0,
	})
	threat := &fakeThreatIntel{}
	metricsCollector := metrics.New(prometheus.NewRegistry())
	stream := streams.NewTaskHub()
	t.Cleanup(stream.Close)

	cfg := config.EventsConfig{
		Detection: config.DetectionConfig{
			Enabled:    true,
			MaxWorkers: 1,
			QueueSize:  16,
			AutoRespond: config.DetectionAutoRespondConfig{
				Enabled:         true,
				DefaultProfile:  "respond_profile_v1",
				DefaultPriority: 2,
				CreatedBy:       "detector",
			},
			Rules: []config.DetectionRuleConfig{
				{
					Name:                "suspicious-process",
					Enabled:             true,
					Severity:            "high",
					EventTypes:          []string{"process.exec"},
					Metadata:            map[string]string{"collector": "diag-ebpf"},
					PayloadContains:     []string{"powershell"},
					Indicators:          []string{"metadata.sha256"},
					SubmitToThreatIntel: true,
				},
			},
		},
		Retention: config.EventRetentionConfig{
			Hot:  time.Hour,
			Warm: 2 * time.Hour,
			Cold: 3 * time.Hour,
		},
	}

	engine := NewDetectionEngine(cfg, st, sched, threat, slog.New(slog.NewTextHandler(io.Discard, nil)), metricsCollector, stream)
	require.NotNil(t, engine)
	t.Cleanup(engine.Close)

	ctx := context.Background()
	rawPayload, _ := json.Marshal(map[string]any{"command": "powershell.exe"})
	event := model.SystemEventRecord{
		ID:            uuid.New(),
		AgentID:       uuid.New(),
		AgentName:     "agent-1",
		EventType:     "process.exec",
		Source:        "ebpf",
		Priority:      "normal",
		StorageTier:   "hot",
		Metadata:      map[string]string{"collector": "diag-ebpf", "sha256": "abc123"},
		Timestamp:     time.Now().UTC(),
		ReceivedAt:    time.Now().UTC(),
		Payload:       rawPayload,
		CollectorKind: "ebpf",
	}

	sub, cancel := stream.Subscribe(ctx)
	defer cancel()

	engine.Consume(ctx, []model.SystemEventRecord{event})

	require.Eventually(t, func() bool {
		records, err := st.QuerySystemEvents(context.Background(), store.SystemEventQuery{
			EventType: "detection.alert",
			Limit:     1,
		})
		require.NoError(t, err)
		return len(records) == 1
	}, 2*time.Second, 20*time.Millisecond)

	require.Eventually(t, func() bool {
		select {
		case evt := <-sub:
			return evt.Event == "detection.triggered"
		default:
			return false
		}
	}, 2*time.Second, 20*time.Millisecond)

	pending, err := st.ListPendingTasks(context.Background(), 10)
	require.NoError(t, err)
	require.Len(t, pending, 1)
	require.Equal(t, model.TaskType("respond"), pending[0].Type)
	require.Contains(t, string(pending[0].Payload), `"detection_id"`)

	require.Eventually(t, func() bool {
		return len(threat.requests()) == 1
	}, time.Second, 20*time.Millisecond)
	require.Equal(t, "abc123", threat.requests()[0].Indicator)
}

func TestDetectionEngineMLModel(t *testing.T) {
	st := store.NewInMemoryStore()
	queue := memory.New()
	sched := scheduler.New(st, queue, config.SchedulerConfig{
		LeaseTTL:          time.Second,
		MaxRetries:        1,
		HeartbeatTimeout:  time.Second,
		QueueCapacity:     16,
		LeasePollInterval: time.Millisecond,
	})
	stream := streams.NewTaskHub()
	t.Cleanup(stream.Close)
	metricsCollector := metrics.New(prometheus.NewRegistry())

	cfg := config.EventsConfig{
		Detection: config.DetectionConfig{
			Enabled:    true,
			MaxWorkers: 1,
			QueueSize:  8,
			Rules:      nil,
			MLModels: []config.DetectionMLModelConfig{
				{
					Name:      "risk-score",
					Enabled:   true,
					Threshold: 0.5,
					Severity:  "medium",
					FeatureWeights: map[string]float64{
						"metadata.risk_score": 1.0,
					},
				},
			},
		},
		Retention: config.EventRetentionConfig{
			Hot:  time.Hour,
			Warm: 2 * time.Hour,
			Cold: 3 * time.Hour,
		},
	}

	engine := NewDetectionEngine(cfg, st, sched, nil, slog.New(slog.NewTextHandler(io.Discard, nil)), metricsCollector, stream)
	require.NotNil(t, engine)
	t.Cleanup(engine.Close)

	event := model.SystemEventRecord{
		ID:          uuid.New(),
		EventType:   "fs.open",
		Source:      "ebpf",
		Metadata:    map[string]string{"risk_score": "0.8"},
		ReceivedAt:  time.Now().UTC(),
		StorageTier: "hot",
	}
	engine.Consume(context.Background(), []model.SystemEventRecord{event})

	require.Eventually(t, func() bool {
		records, err := st.QuerySystemEvents(context.Background(), store.SystemEventQuery{
			EventType: "detection.alert",
			Limit:     1,
		})
		require.NoError(t, err)
		return len(records) == 1
	}, 2*time.Second, 20*time.Millisecond)
}

type fakeThreatIntel struct {
	mu         sync.Mutex
	executions []threatintel.LookupRequest
}

func (f *fakeThreatIntel) SubmitLookup(ctx context.Context, req threatintel.LookupRequest) ([]uuid.UUID, []*model.ThreatIntelVerdict, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.executions = append(f.executions, req)
	return []uuid.UUID{uuid.New()}, nil, nil
}

func (f *fakeThreatIntel) requests() []threatintel.LookupRequest {
	f.mu.Lock()
	defer f.mu.Unlock()
	copied := make([]threatintel.LookupRequest, len(f.executions))
	copy(copied, f.executions)
	return copied
}
