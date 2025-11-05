package metrics

import (
	"github.com/gin-gonic/gin"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

type Metrics struct {
	Heartbeats      prometheus.Counter
	TasksLeased     prometheus.Counter
	TasksCompleted  *prometheus.CounterVec
	TaskQueueDepth  prometheus.Gauge
	TaskTimeToLease prometheus.Histogram
	TaskRunDuration prometheus.Histogram
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
	}
	reg.MustRegister(m.Heartbeats, m.TasksLeased, m.TasksCompleted, m.TaskQueueDepth, m.TaskTimeToLease, m.TaskRunDuration)
	return m
}

func Handler(gatherer prometheus.Gatherer) gin.HandlerFunc {
	h := promhttp.HandlerFor(gatherer, promhttp.HandlerOpts{})
	return func(c *gin.Context) {
		h.ServeHTTP(c.Writer, c.Request)
	}
}
