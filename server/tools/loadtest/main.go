package main

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"math/rand"
	"net/http"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	pb "github.com/m-sec-org/d-eyes/server/proto/agentservicepb"
)

type createTaskResponse struct {
	ID string `json:"id"`
}

func main() {
	api := flag.String("api", "http://127.0.0.1:8080", "Server HTTP base URL")
	grpcAddr := flag.String("grpc", "127.0.0.1:9090", "Server gRPC address")
	apiKey := flag.String("api-key", "changeme", "API key for authentication")
	agentToken := flag.String("agent-token", "changeme", "Agent token used by simulated agents")
	duration := flag.Duration("duration", time.Minute, "Load test duration")
	concurrency := flag.Int("concurrency", 16, "Concurrent task creators")
	payloadSize := flag.Int("payload-bytes", 256, "Approximate payload size per task payload blob")
	agents := flag.Int("agents", 8, "Number of simulated Agent workers (0 to disable)")
	pullBatch := flag.Int("pull-batch", 4, "Max tasks pulled per request by simulated Agents")
	flag.Parse()

	client := &http.Client{Timeout: 10 * time.Second}
	ctx, cancel := context.WithTimeout(context.Background(), *duration)
	defer cancel()

	var (
		totalRequests   int64
		requestFailures int64
		processedTasks  int64
		reportFailures  int64
	)
	latencies := make([]time.Duration, 0, *concurrency*64)
	latMu := sync.Mutex{}
	wg := sync.WaitGroup{}

	log.Printf("starting load test: api=%s grpc=%s concurrency=%d agents=%d duration=%s", *api, *grpcAddr, *concurrency, *agents, duration.String())

	// Task creation workers
	for i := 0; i < *concurrency; i++ {
		wg.Add(1)
		go func(worker int) {
			defer wg.Done()
			rnd := rand.New(rand.NewSource(time.Now().UnixNano() + int64(worker)))
			for {
				select {
				case <-ctx.Done():
					return
				default:
				}
				started := time.Now()
				if err := submitTask(ctx, client, *api, *apiKey, rnd, *payloadSize); err != nil {
					atomic.AddInt64(&requestFailures, 1)
				}
				latency := time.Since(started)
				latMu.Lock()
				latencies = append(latencies, latency)
				latMu.Unlock()
				atomic.AddInt64(&totalRequests, 1)
			}
		}(i)
	}

	// Agent simulators (optional)
	if *agents > 0 {
		conn, err := grpc.DialContext(ctx, *grpcAddr, grpc.WithTransportCredentials(insecure.NewCredentials()), grpc.WithBlock())
		if err != nil {
			log.Fatalf("dial gRPC: %v", err)
		}
		defer conn.Close()
		client := pb.NewAgentServiceClient(conn)

		for i := 0; i < *agents; i++ {
			wg.Add(1)
			go func(idx int) {
				defer wg.Done()
				simulateAgent(ctx, client, idx, *pullBatch, *agentToken, &processedTasks, &reportFailures)
			}(i)
		}
	}

	<-ctx.Done()
	wg.Wait()

	summary(totalRequests, requestFailures, processedTasks, reportFailures, latencies, duration)
}

func summary(total, failures, processed, reportFailures int64, latencies []time.Duration, duration *time.Duration) {
	success := total - failures
	if total == 0 {
		log.Println("no requests completed during load test")
		return
	}
	sort.Slice(latencies, func(i, j int) bool { return latencies[i] < latencies[j] })
	p50 := percentile(latencies, 0.50)
	p95 := percentile(latencies, 0.95)
	p99 := percentile(latencies, 0.99)

	fmt.Println("=== Load Test Summary ===")
	fmt.Printf("Duration: %s\n", duration.String())
	fmt.Printf("Task create requests: total=%d success=%d failures=%d\n", total, success, failures)
	fmt.Printf("Throughput (req/s): %.2f\n", float64(total)/duration.Seconds())
	fmt.Printf("Latency P50: %s\n", p50)
	fmt.Printf("Latency P95: %s\n", p95)
	fmt.Printf("Latency P99: %s\n", p99)
	fmt.Printf("Simulated agent completions: success=%d failures=%d\n", processed, reportFailures)
}

func percentile(values []time.Duration, p float64) time.Duration {
	if len(values) == 0 {
		return 0
	}
	idx := int(float64(len(values)-1) * p)
	if idx < 0 {
		idx = 0
	}
	if idx >= len(values) {
		idx = len(values) - 1
	}
	return values[idx]
}

func submitTask(ctx context.Context, client *http.Client, baseURL, apiKey string, rnd *rand.Rand, payloadSize int) error {
	payload := map[string]any{
		"targets": []string{"/tmp", "/var"},
		"nonce":   rnd.Int63(),
		"blob":    randomString(rnd, payloadSize),
	}

	body, err := json.Marshal(map[string]any{
		"type":       "respond",
		"priority":   rnd.Intn(5) + 1,
		"payload":    payload,
		"metadata":   map[string]string{"source": "loadtest"},
		"created_by": "loadtest",
	})
	if err != nil {
		return err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, fmt.Sprintf("%s/api/v1/tasks", baseURL), bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	if apiKey != "" {
		req.Header.Set("X-API-Key", apiKey)
	}

	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		return fmt.Errorf("unexpected status %d", resp.StatusCode)
	}
	var out createTaskResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return err
	}
	if out.ID == "" {
		return fmt.Errorf("missing task id in response")
	}
	return nil
}

func simulateAgent(ctx context.Context, client pb.AgentServiceClient, idx int, pullBatch int, token string, processed *int64, reportFailures *int64) {
	name := fmt.Sprintf("load-agent-%d", idx)
	registerResp, err := client.Register(ctx, &pb.RegisterRequest{
		Token: token,
		Metadata: &pb.AgentMetadata{
			Name:         name,
			Platform:     "linux",
			Version:      "loadtest",
			Capabilities: []string{"respond"},
			Labels:       map[string]string{"env": "loadtest"},
		},
	})
	if err != nil {
		log.Printf("agent %s register failed: %v", name, err)
		return
	}
	agentID := registerResp.GetAgentId()

	stream, err := client.Heartbeat(ctx)
	if err != nil {
		log.Printf("agent %s heartbeat stream error: %v", name, err)
		return
	}
	hbCtx, hbCancel := context.WithCancel(ctx)
	wg := sync.WaitGroup{}
	wg.Add(1)
	go func() {
		defer wg.Done()
		interval := time.Duration(registerResp.GetHeartbeatIntervalSeconds()) * time.Second
		if interval <= 0 {
			interval = 5 * time.Second
		}
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-hbCtx.Done():
				_ = stream.CloseSend()
				return
			case <-ticker.C:
				hb := &pb.HeartbeatRequest{
					AgentId:      agentID,
					Timestamp:    time.Now().Unix(),
					Load:         0.1,
					RunningTasks: nil,
				}
				if err := stream.Send(hb); err != nil {
					log.Printf("agent %s heartbeat send error: %v", name, err)
					hbCancel()
					return
				}
				if _, err := stream.Recv(); err != nil {
					log.Printf("agent %s heartbeat recv error: %v", name, err)
					hbCancel()
					return
				}
			}
		}
	}()

	rnd := rand.New(rand.NewSource(time.Now().UnixNano() + int64(idx)))
	pullTicker := time.NewTicker(200 * time.Millisecond)
	defer pullTicker.Stop()

	for {
		select {
		case <-ctx.Done():
			hbCancel()
			wg.Wait()
			return
		case <-pullTicker.C:
			resp, err := client.PullTasks(ctx, &pb.PullTaskRequest{
				AgentId:  agentID,
				MaxTasks: int32(pullBatch),
			})
			if err != nil {
				continue
			}
			for _, lease := range resp.GetLeases() {
				// Simulate processing latency
				time.Sleep(time.Duration(rnd.Intn(200)+50) * time.Millisecond)
				report := &pb.ReportResultRequest{
					AgentId:     agentID,
					TaskId:      lease.GetTaskId(),
					LeaseId:     lease.GetLeaseId(),
					Status:      "succeeded",
					SummaryJson: []byte(`{"result":"ok"}`),
				}
				if _, err := client.ReportResult(ctx, report); err != nil {
					atomic.AddInt64(reportFailures, 1)
				} else {
					atomic.AddInt64(processed, 1)
				}
			}
		}
	}
}

func randomString(rnd *rand.Rand, size int) string {
	const letters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	if size <= 0 {
		return ""
	}
	buf := make([]byte, size)
	for i := range buf {
		buf[i] = letters[rnd.Intn(len(letters))]
	}
	return string(buf)
}
