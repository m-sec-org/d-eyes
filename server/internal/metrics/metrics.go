package metrics

import (
	"github.com/gin-gonic/gin"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

type Metrics struct {
	Heartbeats                   prometheus.Counter
	TasksLeased                  prometheus.Counter
	TasksCompleted               *prometheus.CounterVec
	TaskQueueDepth               prometheus.Gauge
	TaskTimeToLease              prometheus.Histogram
	TaskRunDuration              prometheus.Histogram
	TasksInFlight                prometheus.Gauge
	TaskStatus                   *prometheus.GaugeVec
	AgentCPUPercent              prometheus.Histogram
	AgentMemoryPercent           prometheus.Histogram
	AgentIOUtilPercent           prometheus.Histogram
	BASRuns                      *prometheus.CounterVec
	BASSandboxFallbacks          *prometheus.CounterVec
	BASApprovals                 *prometheus.CounterVec
	BASBacklog                   prometheus.Gauge
	BASInFlight                  prometheus.Gauge
	BASQueueWait                 prometheus.Histogram
	ThreatIntelJobs              *prometheus.CounterVec
	ThreatIntelQueue             prometheus.Gauge
	ThreatIntelLatency           *prometheus.HistogramVec
	SystemEventsIngested         prometheus.Counter
	SystemEventsDropped          prometheus.Counter
	SystemEventsQueue            prometheus.Gauge
	SystemEventsQueueByPriority  *prometheus.GaugeVec
	SystemEventsLatency          prometheus.Histogram
	SystemEventsIngestedByTier   *prometheus.CounterVec
	SystemEventsBackpressure     *prometheus.CounterVec
	SystemEventParsersConfigured *prometheus.GaugeVec
	SystemEventParserFailures    *prometheus.CounterVec
	DetectionsTriggered          *prometheus.CounterVec
	DetectionsAutoResponded      *prometheus.CounterVec
	CollectorConfigUpdates       prometheus.Counter
	CollectorStatusAlerts        *prometheus.CounterVec
	CollectorRolloutTargets      *prometheus.GaugeVec
	CollectorRolloutActions      *prometheus.CounterVec
}

func New(reg prometheus.Registerer) *Metrics {
	m := &Metrics{
		Heartbeats: prometheus.NewCounter(prometheus.CounterOpts{
			Namespace: "d_eyes",
			Subsystem: "server",
			Name:      "agent_heartbeats_total",
			Help:      "Total number of heartbeats processed.",
		}),
		TasksLeased: prometheus.NewCounter(prometheus.CounterOpts{
			Namespace: "d_eyes",
			Subsystem: "server",
			Name:      "tasks_leased_total",
			Help:      "Total number of task leases granted.",
		}),
		TasksCompleted: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: "d_eyes",
			Subsystem: "server",
			Name:      "tasks_completed_total",
			Help:      "Count of tasks completed by status.",
		}, []string{"status"}),
		TaskQueueDepth: prometheus.NewGauge(prometheus.GaugeOpts{
			Namespace: "d_eyes",
			Subsystem: "server",
			Name:      "task_queue_depth",
			Help:      "Approximate number of pending tasks in the dispatch queue.",
		}),
		TaskTimeToLease: prometheus.NewHistogram(prometheus.HistogramOpts{
			Namespace: "d_eyes",
			Subsystem: "server",
			Name:      "task_time_to_lease_seconds",
			Help:      "Distribution of time spent waiting in queue before being leased to an agent.",
			Buckets:   []float64{0.01, 0.05, 0.1, 0.25, 0.5, 1, 2, 5, 10, 30},
		}),
		TaskRunDuration: prometheus.NewHistogram(prometheus.HistogramOpts{
			Namespace: "d_eyes",
			Subsystem: "server",
			Name:      "task_run_duration_seconds",
			Help:      "Distribution of task execution durations as reported by agents.",
			Buckets:   []float64{0.05, 0.1, 0.25, 0.5, 1, 2, 5, 15, 30, 60, 120},
		}),
		TasksInFlight: prometheus.NewGauge(prometheus.GaugeOpts{
			Namespace: "d_eyes",
			Subsystem: "server",
			Name:      "tasks_in_flight",
			Help:      "Number of task leases currently assigned to agents.",
		}),
		TaskStatus: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Namespace: "d_eyes",
			Subsystem: "server",
			Name:      "tasks_status_count",
			Help:      "Number of tasks in each status as observed by the scheduler.",
		}, []string{"status"}),
		AgentCPUPercent: prometheus.NewHistogram(prometheus.HistogramOpts{
			Namespace: "d_eyes",
			Subsystem: "server",
			Name:      "agent_cpu_percent",
			Help:      "Distribution of agent-reported CPU percent from heartbeats.",
			Buckets:   []float64{1, 5, 10, 20, 30, 40, 50, 60, 70, 80, 90, 100},
		}),
		AgentMemoryPercent: prometheus.NewHistogram(prometheus.HistogramOpts{
			Namespace: "d_eyes",
			Subsystem: "server",
			Name:      "agent_memory_percent",
			Help:      "Distribution of agent-reported memory percent from heartbeats.",
			Buckets:   []float64{10, 20, 30, 40, 50, 60, 70, 80, 90, 100},
		}),
		AgentIOUtilPercent: prometheus.NewHistogram(prometheus.HistogramOpts{
			Namespace: "d_eyes",
			Subsystem: "server",
			Name:      "agent_io_util_percent",
			Help:      "Distribution of agent-reported IO utilization percent from heartbeats.",
			Buckets:   []float64{1, 5, 10, 20, 30, 40, 50, 60, 70, 80, 90, 100},
		}),
		BASRuns: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: "d_eyes",
			Subsystem: "bas",
			Name:      "scenarios_total",
			Help:      "Total BAS scenarios executed grouped by scenario and status.",
		}, []string{"scenario_id", "status", "sandbox_used"}),
		BASSandboxFallbacks: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: "d_eyes",
			Subsystem: "bas",
			Name:      "sandbox_fallback_total",
			Help:      "Count of BAS runs that fell back to host execution.",
		}, []string{"scenario_id"}),
		BASApprovals: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: "d_eyes",
			Subsystem: "bas",
			Name:      "sandbox_approvals_total",
			Help:      "Count of BAS runs requiring sandbox approval grouped by approval outcome.",
		}, []string{"approved"}),
		BASBacklog: prometheus.NewGauge(prometheus.GaugeOpts{
			Namespace: "d_eyes",
			Subsystem: "bas",
			Name:      "queue_backlog",
			Help:      "Number of BAS tasks waiting in the scheduler queue.",
		}),
		BASInFlight: prometheus.NewGauge(prometheus.GaugeOpts{
			Namespace: "d_eyes",
			Subsystem: "bas",
			Name:      "tasks_in_flight",
			Help:      "Number of BAS tasks currently leased to agents.",
		}),
		BASQueueWait: prometheus.NewHistogram(prometheus.HistogramOpts{
			Namespace: "d_eyes",
			Subsystem: "bas",
			Name:      "queue_wait_seconds",
			Help:      "Time BAS tasks spend waiting in queue before being leased.",
			Buckets:   []float64{0.1, 0.5, 1, 2, 5, 10, 30, 60, 120, 300},
		}),
		ThreatIntelJobs: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: "d_eyes",
			Subsystem: "threat_intel",
			Name:      "jobs_total",
			Help:      "Count of threat intelligence jobs grouped by source and result.",
		}, []string{"source", "result"}),
		ThreatIntelQueue: prometheus.NewGauge(prometheus.GaugeOpts{
			Namespace: "d_eyes",
			Subsystem: "threat_intel",
			Name:      "queue_depth",
			Help:      "Approximate number of pending threat intelligence jobs.",
		}),
		ThreatIntelLatency: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Namespace: "d_eyes",
			Subsystem: "threat_intel",
			Name:      "external_latency_seconds",
			Help:      "Latency of external threat intelligence API calls.",
			Buckets:   []float64{0.25, 0.5, 1, 2, 5, 10, 30},
		}, []string{"source", "action"}),
		SystemEventsIngested: prometheus.NewCounter(prometheus.CounterOpts{
			Namespace: "d_eyes",
			Subsystem: "events",
			Name:      "ingested_total",
			Help:      "Total number of system events accepted into persistent storage.",
		}),
		SystemEventsDropped: prometheus.NewCounter(prometheus.CounterOpts{
			Namespace: "d_eyes",
			Subsystem: "events",
			Name:      "dropped_total",
			Help:      "Total number of system events dropped due to validation or backpressure.",
		}),
		SystemEventsQueue: prometheus.NewGauge(prometheus.GaugeOpts{
			Namespace: "d_eyes",
			Subsystem: "events",
			Name:      "queue_depth",
			Help:      "Current buffered system events waiting to be flushed to storage.",
		}),
		SystemEventsQueueByPriority: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Namespace: "d_eyes",
			Subsystem: "events",
			Name:      "queue_depth_priority",
			Help:      "Buffered system events per priority lane.",
		}, []string{"priority"}),
		SystemEventsLatency: prometheus.NewHistogram(prometheus.HistogramOpts{
			Namespace: "d_eyes",
			Subsystem: "events",
			Name:      "ingest_latency_seconds",
			Help:      "Time from event receipt to durable storage.",
			Buckets:   []float64{0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1},
		}),
		SystemEventsIngestedByTier: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: "d_eyes",
			Subsystem: "events",
			Name:      "ingested_by_tier_total",
			Help:      "Count of system events ingested by priority/tier.",
		}, []string{"priority", "tier"}),
		SystemEventsBackpressure: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: "d_eyes",
			Subsystem: "events",
			Name:      "backpressure_total",
			Help:      "Count of backpressure signals grouped by priority and reason.",
		}, []string{"priority", "reason"}),
		SystemEventParsersConfigured: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Namespace: "d_eyes",
			Subsystem: "events",
			Name:      "parsers_configured",
			Help:      "Configured parser plugins registered at runtime.",
		}, []string{"parser"}),
		SystemEventParserFailures: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: "d_eyes",
			Subsystem: "events",
			Name:      "parser_failures_total",
			Help:      "Count of parser validation failures grouped by parser and reason.",
		}, []string{"parser", "reason"}),
		DetectionsTriggered: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: "d_eyes",
			Subsystem: "events",
			Name:      "detections_triggered_total",
			Help:      "Count of detection alerts grouped by rule and severity.",
		}, []string{"rule", "severity"}),
		DetectionsAutoResponded: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: "d_eyes",
			Subsystem: "events",
			Name:      "detections_auto_respond_total",
			Help:      "Count of auto respond tasks created from detections grouped by rule.",
		}, []string{"rule"}),
		CollectorConfigUpdates: prometheus.NewCounter(prometheus.CounterOpts{
			Namespace: "d_eyes",
			Subsystem: "collector",
			Name:      "config_updates_total",
			Help:      "Total collector configuration updates applied via the control plane.",
		}),
		CollectorStatusAlerts: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: "d_eyes",
			Subsystem: "collector",
			Name:      "status_alerts_total",
			Help:      "Collector status reports grouped by tenant and alert level.",
		}, []string{"tenant", "level"}),
		CollectorRolloutTargets: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Namespace: "d_eyes",
			Subsystem: "collector",
			Name:      "rollout_targets",
			Help:      "Number of rollout targets grouped by rollout and state.",
		}, []string{"rollout", "state"}),
		CollectorRolloutActions: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: "d_eyes",
			Subsystem: "collector",
			Name:      "rollout_actions_total",
			Help:      "Count of rollout actions grouped by action and result.",
		}, []string{"action", "result"}),
	}
	reg.MustRegister(
		m.Heartbeats,
		m.TasksLeased,
		m.TasksCompleted,
		m.TaskQueueDepth,
		m.TaskTimeToLease,
		m.TaskRunDuration,
		m.TasksInFlight,
		m.TaskStatus,
		m.AgentCPUPercent,
		m.AgentMemoryPercent,
		m.AgentIOUtilPercent,
		m.BASRuns,
		m.BASSandboxFallbacks,
		m.BASApprovals,
		m.BASBacklog,
		m.BASInFlight,
		m.BASQueueWait,
		m.ThreatIntelJobs,
		m.ThreatIntelQueue,
		m.ThreatIntelLatency,
		m.SystemEventsIngested,
		m.SystemEventsDropped,
		m.SystemEventsQueue,
		m.SystemEventsQueueByPriority,
		m.SystemEventsLatency,
		m.SystemEventsIngestedByTier,
		m.SystemEventsBackpressure,
		m.SystemEventParsersConfigured,
		m.SystemEventParserFailures,
		m.DetectionsTriggered,
		m.DetectionsAutoResponded,
		m.CollectorConfigUpdates,
		m.CollectorStatusAlerts,
		m.CollectorRolloutTargets,
		m.CollectorRolloutActions,
	)
	return m
}

func Handler(gatherer prometheus.Gatherer) gin.HandlerFunc {
	h := promhttp.HandlerFor(gatherer, promhttp.HandlerOpts{})
	return func(c *gin.Context) {
		h.ServeHTTP(c.Writer, c.Request)
	}
}
