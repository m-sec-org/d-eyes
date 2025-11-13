package behavior

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"math"
	"math/rand"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	redis "github.com/redis/go-redis/v9"

	"github.com/m-sec-org/d-eyes/server/internal/config"
	"github.com/m-sec-org/d-eyes/server/internal/model"
	"github.com/m-sec-org/d-eyes/server/internal/store"
	telemetrykeys "github.com/m-sec-org/d-eyes/server/pkg/telemetry"
)

// GraphService provides ingestion + anomaly graph correlation.
type GraphService struct {
	log             *slog.Logger
	store           store.Store
	cfg             config.BehaviorConfig
	hub             *Hub
	redis           *redis.Client
	heartbeatStream string
	eventStream     string
	window          time.Duration
	flushInterval   time.Duration
	sampleRate      float64
	maxBatch        int
	group           string
	consumer        string
	cooldown        time.Duration

	mu        sync.Mutex
	metrics   map[uuid.UUID][]HeartbeatMetric
	telemetry map[uuid.UUID][]TaskTelemetry
	recent    map[uuid.UUID]time.Time
	randSrc   *rand.Rand
	randMu    sync.Mutex
	startCtx  context.Context
	cancel    context.CancelFunc
	wg        sync.WaitGroup
}

// NewGraphService constructs a graph service when enabled.
func NewGraphService(cfg config.BehaviorConfig, redisCfg config.RedisConfig, st store.Store, hub *Hub, logger *slog.Logger) (*GraphService, error) {
	if !cfg.Enabled || !cfg.Graph.Enabled || st == nil {
		return nil, nil
	}
	if logger == nil {
		logger = slog.Default()
	}
	window := cfg.Graph.Window
	if window <= 0 {
		window = 5 * time.Minute
	}
	flush := cfg.Graph.FlushInterval
	if flush <= 0 {
		flush = 5 * time.Second
	}
	sampleRate := cfg.Graph.SampleRate
	if sampleRate <= 0 || sampleRate > 1 {
		sampleRate = 1
	}
	maxBatch := cfg.Graph.MaxBatch
	if maxBatch <= 0 {
		maxBatch = 256
	}
	group := cfg.Graph.RedisGroup
	if group == "" {
		group = "behavior-graph"
	}
	consumer := cfg.Graph.RedisConsumer
	if consumer == "" {
		consumer = fmt.Sprintf("behavior-graph-%d", time.Now().UnixNano())
	}
	heartbeatStream := cfg.HeartbeatStream
	if heartbeatStream == "" {
		heartbeatStream = "behavior.heartbeats"
	}
	eventStream := cfg.EventStream
	if eventStream == "" {
		eventStream = "behavior.events"
	}
	var client *redis.Client
	if redisCfg.Enabled {
		client = redis.NewClient(&redis.Options{
			Addr:         redisCfg.Addr,
			Password:     redisCfg.Password,
			DB:           redisCfg.DB,
			DialTimeout:  redisCfg.DialTimeout,
			ReadTimeout:  redisCfg.ReadTimeout,
			WriteTimeout: redisCfg.WriteTimeout,
		})
		if err := client.Ping(context.Background()).Err(); err != nil {
			return nil, fmt.Errorf("graph redis ping: %w", err)
		}
	}
	service := &GraphService{
		log:             logger,
		store:           st,
		cfg:             cfg,
		hub:             hub,
		redis:           client,
		heartbeatStream: heartbeatStream,
		eventStream:     eventStream,
		window:          window,
		flushInterval:   flush,
		sampleRate:      sampleRate,
		maxBatch:        maxBatch,
		group:           group,
		consumer:        consumer,
		cooldown:        time.Duration(float64(window) * 0.6),
		metrics:         make(map[uuid.UUID][]HeartbeatMetric),
		telemetry:       make(map[uuid.UUID][]TaskTelemetry),
		recent:          make(map[uuid.UUID]time.Time),
		randSrc:         rand.New(rand.NewSource(time.Now().UnixNano())),
	}
	if service.cooldown <= 0 {
		service.cooldown = 30 * time.Second
	}
	return service, nil
}

// Enabled returns true when the graph service is ready.
func (g *GraphService) Enabled() bool {
	return g != nil && g.store != nil
}

// Start launches the Redis ingestion worker if configured.
func (g *GraphService) Start(ctx context.Context) {
	if !g.Enabled() || g.redis == nil {
		return
	}
	g.startCtx, g.cancel = context.WithCancel(ctx)
	g.wg.Add(1)
	go g.run(g.startCtx)
}

// Stop terminates the background worker.
func (g *GraphService) Stop() {
	if g.cancel != nil {
		g.cancel()
	}
	g.wg.Wait()
	if g.redis != nil {
		_ = g.redis.Close()
	}
}

// HandleHeartbeat ingests metrics directly from gRPC service.
func (g *GraphService) HandleHeartbeat(ctx context.Context, metric HeartbeatMetric) {
	if !g.Enabled() || !g.shouldSample() {
		return
	}
	if metric.Timestamp.IsZero() {
		metric.Timestamp = time.Now().UTC()
	}
	metric.RunningTasks = append([]string(nil), metric.RunningTasks...)
	metric.BlockedActions = append([]string(nil), metric.BlockedActions...)
	g.appendMetric(metric)
	g.evaluateAgent(ctx, metric.AgentID)
}

// HandleTaskTelemetry ingests task telemetry metadata.
func (g *GraphService) HandleTaskTelemetry(ctx context.Context, payload TaskTelemetry) {
	if !g.Enabled() || len(payload.Metadata) == 0 || !g.shouldSample() {
		return
	}
	if payload.ReceivedAt.IsZero() {
		payload.ReceivedAt = time.Now().UTC()
	}
	if len(payload.Metadata) > 0 {
		cp := make(map[string]string, len(payload.Metadata))
		for k, v := range payload.Metadata {
			cp[k] = v
		}
		payload.Metadata = cp
	}
	g.appendTelemetry(payload)
	g.evaluateAgent(ctx, payload.AgentID)
}

func (g *GraphService) run(ctx context.Context) {
	defer g.wg.Done()
	g.ensureGroups(ctx)
	ticker := time.NewTicker(g.flushInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}
		g.consumeStreams(ctx)
		select {
		case <-ticker.C:
			g.gc(time.Now().Add(-g.window))
		default:
		}
	}
}

func (g *GraphService) ensureGroups(ctx context.Context) {
	if g.redis == nil {
		return
	}
	for _, stream := range []string{g.heartbeatStream, g.eventStream} {
		if stream == "" {
			continue
		}
		if err := g.redis.XGroupCreateMkStream(ctx, stream, g.group, "0").Err(); err != nil && !strings.Contains(err.Error(), "BUSYGROUP") {
			g.log.Warn("graph create group", "stream", stream, "error", err)
		}
	}
}

func (g *GraphService) consumeStreams(ctx context.Context) {
	if g.redis == nil {
		time.Sleep(g.flushInterval)
		return
	}
	args := &redis.XReadGroupArgs{
		Group:    g.group,
		Consumer: g.consumer,
		Streams:  []string{g.heartbeatStream, g.eventStream, ">", ">"},
		Count:    int64(g.maxBatch),
		Block:    g.flushInterval,
	}
	streams, err := g.redis.XReadGroup(ctx, args).Result()
	if err != nil {
		if err != redis.Nil && !errorsIsCancelled(err, ctx) {
			g.log.Debug("graph read group", "error", err)
		}
		return
	}
	for _, stream := range streams {
		for _, msg := range stream.Messages {
			var processed bool
			switch stream.Stream {
			case g.heartbeatStream:
				processed = g.ingestHeartbeatMessage(ctx, msg)
			case g.eventStream:
				processed = g.ingestTelemetryMessage(ctx, msg)
			default:
			}
			if processed {
				_ = g.redis.XAck(ctx, stream.Stream, g.group, msg.ID).Err()
			}
		}
	}
}

func (g *GraphService) ingestHeartbeatMessage(ctx context.Context, msg redis.XMessage) bool {
	metric, err := decodeHeartbeatMessage(msg.Values)
	if err != nil {
		g.log.Debug("graph decode heartbeat", "error", err)
		return false
	}
	g.HandleHeartbeat(ctx, metric)
	return true
}

func (g *GraphService) ingestTelemetryMessage(ctx context.Context, msg redis.XMessage) bool {
	payload, err := decodeTelemetryMessage(msg.Values)
	if err != nil {
		g.log.Debug("graph decode telemetry", "error", err)
		return false
	}
	g.HandleTaskTelemetry(ctx, payload)
	return true
}

func decodeHeartbeatMessage(values map[string]interface{}) (HeartbeatMetric, error) {
	var metric HeartbeatMetric
	var err error
	if metric.AgentID, err = parseUUID(values["agent_id"]); err != nil {
		return metric, err
	}
	if ts, ok := values["timestamp"]; ok {
		metric.Timestamp = time.Unix(parseInt(ts), 0)
	}
	metric.Load = parseFloat(values["load"])
	metric.LatencyMs = parseFloat(values["latency_ms"])
	metric.CPUPercent = parseFloat(values["cpu_percent"])
	metric.RunningTasks = parseStringList(values["tasks"])
	metric.BlockedActions = parseStringList(values["blocked_actions"])
	return metric, nil
}

func decodeTelemetryMessage(values map[string]interface{}) (TaskTelemetry, error) {
	var payload TaskTelemetry
	var err error
	if payload.AgentID, err = parseUUID(values["agent_id"]); err != nil {
		return payload, err
	}
	if payload.TaskID, err = parseUUID(values["task_id"]); err != nil {
		return payload, err
	}
	payload.ReceivedAt = time.Unix(parseInt(values["timestamp"]), 0)
	if raw := values["metadata"]; raw != nil {
		payload.Metadata = parseMetadataMap(raw)
	}
	return payload, nil
}

func parseMetadataMap(value interface{}) map[string]string {
	switch typed := value.(type) {
	case map[string]string:
		copyMap := make(map[string]string, len(typed))
		for k, v := range typed {
			copyMap[k] = v
		}
		return copyMap
	case map[string]interface{}:
		result := make(map[string]string, len(typed))
		for k, v := range typed {
			result[k] = fmt.Sprint(v)
		}
		return result
	case string:
		var parsed map[string]string
		if err := json.Unmarshal([]byte(typed), &parsed); err == nil && len(parsed) > 0 {
			return parsed
		}
	}
	return nil
}

func parseUUID(value interface{}) (uuid.UUID, error) {
	switch v := value.(type) {
	case uuid.UUID:
		return v, nil
	case string:
		return uuid.Parse(strings.TrimSpace(v))
	default:
		return uuid.Nil, fmt.Errorf("invalid uuid value: %v", value)
	}
}

func parseFloat(value interface{}) float64 {
	switch v := value.(type) {
	case float64:
		return v
	case float32:
		return float64(v)
	case int64:
		return float64(v)
	case int:
		return float64(v)
	case json.Number:
		f, _ := v.Float64()
		return f
	case string:
		f, _ := strconv.ParseFloat(v, 64)
		return f
	default:
		return 0
	}
}

func parseInt(value interface{}) int64 {
	switch v := value.(type) {
	case int64:
		return v
	case int:
		return int64(v)
	case float64:
		return int64(v)
	case json.Number:
		i, _ := v.Int64()
		return i
	case string:
		i, _ := strconv.ParseInt(v, 10, 64)
		return i
	default:
		return time.Now().Unix()
	}
}

func parseStringList(value interface{}) []string {
	switch v := value.(type) {
	case []string:
		return append([]string(nil), v...)
	case []interface{}:
		result := make([]string, 0, len(v))
		for _, entry := range v {
			result = append(result, fmt.Sprint(entry))
		}
		return result
	case string:
		if v == "" {
			return nil
		}
		var arr []string
		if err := json.Unmarshal([]byte(v), &arr); err == nil {
			return arr
		}
		parts := strings.Split(v, ",")
		result := make([]string, 0, len(parts))
		for _, part := range parts {
			if trimmed := strings.TrimSpace(part); trimmed != "" {
				result = append(result, trimmed)
			}
		}
		return result
	default:
		return nil
	}
}

func (g *GraphService) appendMetric(metric HeartbeatMetric) {
	g.mu.Lock()
	defer g.mu.Unlock()
	cutoff := time.Now().Add(-g.window)
	series := append(g.metrics[metric.AgentID], metric)
	g.metrics[metric.AgentID] = filterMetrics(series, cutoff)
}

func (g *GraphService) appendTelemetry(payload TaskTelemetry) {
	g.mu.Lock()
	defer g.mu.Unlock()
	cutoff := time.Now().Add(-g.window)
	series := append(g.telemetry[payload.AgentID], payload)
	g.telemetry[payload.AgentID] = filterTelemetry(series, cutoff)
}

func filterMetrics(series []HeartbeatMetric, cutoff time.Time) []HeartbeatMetric {
	result := series[:0]
	for _, metric := range series {
		if metric.Timestamp.After(cutoff) || metric.Timestamp.Equal(cutoff) {
			result = append(result, metric)
		}
	}
	return append([]HeartbeatMetric(nil), result...)
}

func filterTelemetry(series []TaskTelemetry, cutoff time.Time) []TaskTelemetry {
	result := series[:0]
	for _, payload := range series {
		if payload.ReceivedAt.After(cutoff) || payload.ReceivedAt.Equal(cutoff) {
			result = append(result, payload)
		}
	}
	return append([]TaskTelemetry(nil), result...)
}

func (g *GraphService) evaluateAgent(ctx context.Context, agentID uuid.UUID) {
	if agentID == uuid.Nil {
		return
	}
	metrics, telemetry := g.snapshot(agentID)
	if len(metrics) == 0 && len(telemetry) == 0 {
		return
	}
	result := g.detect(agentID, metrics, telemetry)
	if result == nil {
		return
	}
	if err := g.store.CreateAnomaly(ctx, result.anomaly); err != nil {
		g.log.Debug("graph create anomaly", "error", err)
		return
	}
	if err := g.store.SaveAnomalyGraph(ctx, result.anomaly.ID, result.nodes, result.edges); err != nil {
		g.log.Debug("graph save nodes", "error", err)
	}
	g.emitDetection(result)
}

func (g *GraphService) snapshot(agentID uuid.UUID) ([]HeartbeatMetric, []TaskTelemetry) {
	g.mu.Lock()
	defer g.mu.Unlock()
	cutoff := time.Now().Add(-g.window)
	metrics := filterMetrics(g.metrics[agentID], cutoff)
	telemetry := filterTelemetry(g.telemetry[agentID], cutoff)
	if len(metrics) == 0 {
		delete(g.metrics, agentID)
	} else {
		g.metrics[agentID] = metrics
	}
	if len(telemetry) == 0 {
		delete(g.telemetry, agentID)
	} else {
		g.telemetry[agentID] = telemetry
	}
	return metrics, telemetry
}

func (g *GraphService) detect(agentID uuid.UUID, metrics []HeartbeatMetric, telemetry []TaskTelemetry) *detectionResult {
	stats := computeWindowStats(metrics, telemetry)
	score := g.computeScore(stats)
	if score < 35 {
		return nil
	}
	if !g.shouldEmit(agentID) {
		return nil
	}
	if stats.ioc == "" && len(stats.suspiciousRemotes) > 0 {
		stats.ioc = stats.suspiciousRemotes[0]
	}
	anomaly := &model.Anomaly{
		ID:        uuid.New(),
		AgentID:   agentID,
		TaskID:    stats.taskID,
		IOC:       stats.ioc,
		Entities:  dedupeStrings(stats.entities),
		Severity:  severityFromScore(score),
		Score:     score,
		Status:    "open",
		CreatedAt: time.Now().UTC(),
		UpdatedAt: time.Now().UTC(),
		Summary: map[string]interface{}{
			"window_seconds":         int(g.window.Seconds()),
			"avg_cpu_percent":        stats.avgCPU,
			"max_cpu_percent":        stats.maxCPU,
			"blocked_actions":        stats.blockedActions,
			"connection_count":       stats.connectionCount,
			"unique_remote_count":    len(stats.uniqueRemotes),
			"suspicious_remotes":     stats.suspiciousRemotes,
			"top_processes":          stats.topProcesses,
			"user_sessions":          stats.sessionUsers,
			"max_memory_percent":     stats.maxMemory,
			"max_load":               stats.maxLoad,
			"score_breakdown":        g.scoreBreakdown(stats),
			"telemetry_sample_count": len(telemetry),
		},
	}
	nodes, edges := g.buildGraph(agentID, stats)
	return &detectionResult{anomaly: anomaly, nodes: nodes, edges: edges}
}

func (g *GraphService) emitDetection(result *detectionResult) {
	if g == nil || g.hub == nil || result == nil || result.anomaly == nil {
		return
	}
	graph := buildGraphPayload(result.anomaly.ID, result.nodes, result.edges)
	g.hub.Emit("created", result.anomaly, graph)
}

func (g *GraphService) computeScore(stats windowStats) float64 {
	cpuComponent := math.Min(stats.maxCPU/100.0, 1.0) * g.cfg.Graph.CPUScoreWeight
	blockedComponent := math.Min(float64(len(stats.blockedActions))/5.0, 1.0) * g.cfg.Graph.BlockedActionWeight
	connectionComponent := 0.0
	if stats.connectionCount >= g.cfg.Graph.ConnectionBurstThreshold && g.cfg.Graph.ConnectionBurstThreshold > 0 {
		connectionComponent = math.Min(float64(stats.connectionCount)/float64(g.cfg.Graph.ConnectionBurstThreshold*2), 1.0) * g.cfg.Graph.ConnectionAnomalyWeight
	}
	resourceComponent := 0.0
	if stats.maxMemory >= 85 || stats.maxLoad >= 4 {
		resourceComponent = g.cfg.Graph.ResourceAnomalyWeight
	}
	sessionComponent := 0.0
	if len(stats.sessionUsers) >= 3 {
		sessionComponent = g.cfg.Graph.UserSessionAnomalyWeight
	}
	score := (cpuComponent + blockedComponent + connectionComponent + resourceComponent + sessionComponent) * 100
	return math.Min(score, 100)
}

func (g *GraphService) scoreBreakdown(stats windowStats) map[string]float64 {
	return map[string]float64{
		"cpu":         math.Min(stats.maxCPU/100.0, 1.0) * g.cfg.Graph.CPUScoreWeight * 100,
		"blocked":     math.Min(float64(len(stats.blockedActions))/5.0, 1.0) * g.cfg.Graph.BlockedActionWeight * 100,
		"connections": math.Min(float64(stats.connectionCount)/math.Max(1.0, float64(g.cfg.Graph.ConnectionBurstThreshold*2)), 1.0) * g.cfg.Graph.ConnectionAnomalyWeight * 100,
		"resource": func() float64 {
			if stats.maxMemory >= 85 || stats.maxLoad >= 4 {
				return g.cfg.Graph.ResourceAnomalyWeight * 100
			}
			return 0
		}(),
		"sessions": func() float64 {
			if len(stats.sessionUsers) >= 3 {
				return g.cfg.Graph.UserSessionAnomalyWeight * 100
			}
			return 0
		}(),
	}
}

func (g *GraphService) buildGraph(agentID uuid.UUID, stats windowStats) ([]*model.BehaviorGraphNode, []*model.BehaviorGraphEdge) {
	nodes := make([]*model.BehaviorGraphNode, 0, 4)
	edges := make([]*model.BehaviorGraphEdge, 0, 4)
	agentNode := &model.BehaviorGraphNode{
		ID:    uuid.New(),
		Type:  "agent",
		Label: agentID.String(),
		Properties: map[string]interface{}{
			"max_cpu":        stats.maxCPU,
			"avg_cpu":        stats.avgCPU,
			"blocked":        stats.blockedActions,
			"window_seconds": int(g.window.Seconds()),
		},
	}
	nodes = append(nodes, agentNode)
	if stats.connectionCount > 0 {
		connNode := &model.BehaviorGraphNode{
			ID:    uuid.New(),
			Type:  "connection_cluster",
			Label: fmt.Sprintf("%d connections", stats.connectionCount),
			Properties: map[string]interface{}{
				"unique_remotes": len(stats.uniqueRemotes),
				"samples":        stats.remoteSamples,
				"suspicious":     stats.suspiciousRemotes,
			},
		}
		nodes = append(nodes, connNode)
		edges = append(edges, &model.BehaviorGraphEdge{
			ID:         uuid.New(),
			SourceNode: agentNode.ID,
			TargetNode: connNode.ID,
			Type:       "observed",
		})
	}
	if len(stats.topProcesses) > 0 {
		processNode := &model.BehaviorGraphNode{
			ID:    uuid.New(),
			Type:  "process_summary",
			Label: "Top Processes",
			Properties: map[string]interface{}{
				"top": stats.topProcesses,
			},
		}
		nodes = append(nodes, processNode)
		edges = append(edges, &model.BehaviorGraphEdge{
			ID:         uuid.New(),
			SourceNode: agentNode.ID,
			TargetNode: processNode.ID,
			Type:       "runs",
		})
	}
	if stats.maxMemory > 0 {
		resourceNode := &model.BehaviorGraphNode{
			ID:    uuid.New(),
			Type:  "resource_usage",
			Label: "Resource",
			Properties: map[string]interface{}{
				"max_memory_percent": stats.maxMemory,
				"max_load":           stats.maxLoad,
			},
		}
		nodes = append(nodes, resourceNode)
		edges = append(edges, &model.BehaviorGraphEdge{
			ID:         uuid.New(),
			SourceNode: agentNode.ID,
			TargetNode: resourceNode.ID,
			Type:       "resource_profile",
		})
	}
	if len(stats.sessionUsers) > 0 {
		sessionNode := &model.BehaviorGraphNode{
			ID:    uuid.New(),
			Type:  "session_cluster",
			Label: "User Sessions",
			Properties: map[string]interface{}{
				"users": stats.sessionUsers,
			},
		}
		nodes = append(nodes, sessionNode)
		edges = append(edges, &model.BehaviorGraphEdge{
			ID:         uuid.New(),
			SourceNode: agentNode.ID,
			TargetNode: sessionNode.ID,
			Type:       "logged_in",
		})
	}
	return nodes, edges
}

type detectionResult struct {
	anomaly *model.Anomaly
	nodes   []*model.BehaviorGraphNode
	edges   []*model.BehaviorGraphEdge
}

type windowStats struct {
	avgCPU            float64
	maxCPU            float64
	blockedActions    []string
	connectionCount   int
	uniqueRemotes     map[string]int
	remoteSamples     []string
	suspiciousRemotes []string
	sessionUsers      []string
	topProcesses      []map[string]interface{}
	maxMemory         float64
	maxLoad           float64
	taskID            uuid.UUID
	ioc               string
	entities          []string
}

func computeWindowStats(metrics []HeartbeatMetric, telemetry []TaskTelemetry) windowStats {
	stats := windowStats{
		uniqueRemotes: make(map[string]int),
	}
	if len(metrics) > 0 {
		var totalCPU float64
		for _, metric := range metrics {
			totalCPU += metric.CPUPercent
			if metric.CPUPercent > stats.maxCPU {
				stats.maxCPU = metric.CPUPercent
			}
			stats.blockedActions = append(stats.blockedActions, metric.BlockedActions...)
		}
		stats.avgCPU = totalCPU / float64(len(metrics))
	}
	processCounts := make(map[string]int)
	userSet := make(map[string]struct{})
	entitySet := make(map[string]struct{})
	for _, payload := range telemetry {
		if payload.TaskID != uuid.Nil && stats.taskID == uuid.Nil {
			stats.taskID = payload.TaskID
		}
		for key, value := range payload.Metadata {
			switch key {
			case telemetrykeys.MetadataNetConnections:
				conns, err := decodeConnections(value)
				if err != nil {
					continue
				}
				for _, conn := range conns {
					if conn.Remote == "" || conn.Remote == ":0" {
						continue
					}
					stats.connectionCount++
					stats.uniqueRemotes[conn.Remote]++
					if len(stats.remoteSamples) < 5 {
						stats.remoteSamples = append(stats.remoteSamples, conn.Remote)
					}
					if stats.uniqueRemotes[conn.Remote] >= 3 {
						stats.suspiciousRemotes = appendUnique(stats.suspiciousRemotes, conn.Remote)
					}
					entitySet[conn.Remote] = struct{}{}
				}
			case telemetrykeys.MetadataProcessTree:
				nodes, err := decodeProcessTree(value)
				if err != nil {
					continue
				}
				for _, node := range nodes {
					if node.Name == "" {
						continue
					}
					processCounts[node.Name]++
					entitySet[node.Name] = struct{}{}
				}
			case telemetrykeys.MetadataResourceUsage:
				if usage, err := decodeResource(value); err == nil {
					if usage.MemoryPercent > stats.maxMemory {
						stats.maxMemory = usage.MemoryPercent
					}
					load := math.Max(math.Max(usage.Load1, usage.Load5), usage.Load15)
					if load > stats.maxLoad {
						stats.maxLoad = load
					}
				}
			case telemetrykeys.MetadataUserSessions:
				sessions, err := decodeSessions(value)
				if err != nil {
					continue
				}
				for _, session := range sessions {
					if session.User == "" {
						continue
					}
					label := fmt.Sprintf("%s@%s", session.User, session.Host)
					if _, ok := userSet[label]; !ok {
						stats.sessionUsers = append(stats.sessionUsers, label)
						userSet[label] = struct{}{}
					}
					entitySet[label] = struct{}{}
				}
			default:
				if strings.HasPrefix(strings.ToLower(key), "threatintel.") && strings.TrimSpace(value) != "" && stats.ioc == "" {
					stats.ioc = value
					entitySet[value] = struct{}{}
				}
			}
		}
	}
	stats.topProcesses = summarizeProcesses(processCounts)
	for entity := range entitySet {
		stats.entities = append(stats.entities, entity)
	}
	return stats
}

func summarizeProcesses(counts map[string]int) []map[string]interface{} {
	type kv struct {
		Key   string
		Value int
	}
	pairs := make([]kv, 0, len(counts))
	for k, v := range counts {
		pairs = append(pairs, kv{Key: k, Value: v})
	}
	sort.Slice(pairs, func(i, j int) bool {
		return pairs[i].Value > pairs[j].Value
	})
	limit := 5
	if len(pairs) < limit {
		limit = len(pairs)
	}
	results := make([]map[string]interface{}, 0, limit)
	for i := 0; i < limit; i++ {
		results = append(results, map[string]interface{}{
			"name":  pairs[i].Key,
			"count": pairs[i].Value,
		})
	}
	return results
}

func buildGraphPayload(anomalyID uuid.UUID, nodes []*model.BehaviorGraphNode, edges []*model.BehaviorGraphEdge) *model.AnomalyGraph {
	if len(nodes) == 0 && len(edges) == 0 {
		return nil
	}
	graph := &model.AnomalyGraph{
		Nodes: make([]*model.BehaviorGraphNode, 0, len(nodes)),
		Edges: make([]*model.BehaviorGraphEdge, 0, len(edges)),
	}
	for _, node := range nodes {
		if node == nil {
			continue
		}
		cp := *node
		if cp.AnomalyID == uuid.Nil {
			cp.AnomalyID = anomalyID
		}
		if node.Properties != nil {
			cp.Properties = make(map[string]interface{}, len(node.Properties))
			for k, v := range node.Properties {
				cp.Properties[k] = v
			}
		}
		graph.Nodes = append(graph.Nodes, &cp)
	}
	for _, edge := range edges {
		if edge == nil {
			continue
		}
		cp := *edge
		if cp.AnomalyID == uuid.Nil {
			cp.AnomalyID = anomalyID
		}
		if edge.Properties != nil {
			cp.Properties = make(map[string]interface{}, len(edge.Properties))
			for k, v := range edge.Properties {
				cp.Properties[k] = v
			}
		}
		graph.Edges = append(graph.Edges, &cp)
	}
	return graph
}

func appendUnique(list []string, value string) []string {
	for _, existing := range list {
		if existing == value {
			return list
		}
	}
	return append(list, value)
}

func dedupeStrings(list []string) []string {
	if len(list) == 0 {
		return nil
	}
	set := make(map[string]struct{}, len(list))
	for _, entry := range list {
		trimmed := strings.TrimSpace(entry)
		if trimmed == "" {
			continue
		}
		set[trimmed] = struct{}{}
	}
	result := make([]string, 0, len(set))
	for entry := range set {
		result = append(result, entry)
	}
	sort.Strings(result)
	return result
}

func (g *GraphService) shouldEmit(agentID uuid.UUID) bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	now := time.Now()
	if last, ok := g.recent[agentID]; ok {
		if now.Sub(last) < g.cooldown {
			return false
		}
	}
	g.recent[agentID] = now
	return true
}

func (g *GraphService) gc(deadline time.Time) {
	g.mu.Lock()
	defer g.mu.Unlock()
	for id, t := range g.recent {
		if t.Before(deadline) {
			delete(g.recent, id)
		}
	}
}

func errorsIsCancelled(err error, ctx context.Context) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return true
	}
	select {
	case <-ctx.Done():
		return true
	default:
		return false
	}
}

func (g *GraphService) shouldSample() bool {
	if g.sampleRate >= 1 {
		return true
	}
	g.randMu.Lock()
	defer g.randMu.Unlock()
	return g.randSrc.Float64() <= g.sampleRate
}
