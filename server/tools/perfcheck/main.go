package main

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"math"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	dto "github.com/prometheus/client_model/go"
	"github.com/prometheus/common/expfmt"
	"google.golang.org/protobuf/proto"
)

type summary struct {
	CPUP95      float64
	MemP95      float64
	IOP95       float64
	FailureRate float64
}

func main() {
	metricsURL := flag.String("metrics-url", "http://127.0.0.1:8080/metrics", "Prometheus metrics endpoint or exporter URL")
	promURL := flag.String("prom-url", "", "Optional Prometheus base URL; if set, use PromQL rate() windows to compute P95/failure rate")
	window := flag.String("window", "5m", "PromQL range window for rate/quantile queries (e.g. 5m)")
	bearerToken := flag.String("bearer-token", "", "Optional bearer token for Authorization header when scraping or querying Prometheus")
	caFile := flag.String("ca-file", "", "Optional CA certificate file for TLS endpoints")
	jsonOut := flag.String("json", "", "Optional path to write JSON summary (use '-' for stdout)")
	cpuP95Limit := flag.Float64("cpu-p95-threshold", 80.0, "Allowed P95 agent CPU percent before failing")
	memP95Limit := flag.Float64("mem-p95-threshold", 85.0, "Allowed P95 agent memory percent before failing")
	ioP95Limit := flag.Float64("io-p95-threshold", 80.0, "Allowed P95 agent IO util percent before failing")
	failureLimit := flag.Float64("failure-rate-threshold", 0.01, "Allowed task failure rate (0-1) before failing")
	flag.Parse()

	client, err := newHTTPClient(*caFile)
	if err != nil {
		log.Fatalf("perfcheck: %v", err)
	}

	result, usedWindow, err := evaluate(*metricsURL, *promURL, *window, *bearerToken, client)
	if err != nil {
		log.Fatalf("perfcheck: %v", err)
	}

	mode := "scrape"
	if *promURL != "" {
		mode = "promql"
	}

	fmt.Printf("Agent CPU P95: %.2f%% (limit %.2f%%)\n", result.CPUP95, *cpuP95Limit)
	fmt.Printf("Agent Memory P95: %.2f%% (limit %.2f%%)\n", result.MemP95, *memP95Limit)
	fmt.Printf("Agent IO Util P95: %.2f%% (limit %.2f%%)\n", result.IOP95, *ioP95Limit)
	fmt.Printf("Task failure rate: %.4f (limit %.4f)\n", result.FailureRate, *failureLimit)

	var violations []string
	if result.CPUP95 > *cpuP95Limit {
		violations = append(violations, fmt.Sprintf("CPU P95 %.2f%% exceeds %.2f%%", result.CPUP95, *cpuP95Limit))
	}
	if result.MemP95 > *memP95Limit {
		violations = append(violations, fmt.Sprintf("memory P95 %.2f%% exceeds %.2f%%", result.MemP95, *memP95Limit))
	}
	if result.IOP95 > *ioP95Limit {
		violations = append(violations, fmt.Sprintf("io util P95 %.2f%% exceeds %.2f%%", result.IOP95, *ioP95Limit))
	}
	if result.FailureRate > *failureLimit {
		violations = append(violations, fmt.Sprintf("failure rate %.4f exceeds %.4f", result.FailureRate, *failureLimit))
	}
	if len(violations) > 0 {
		for _, v := range violations {
			fmt.Println("FAIL:", v)
		}
		writeJSONReport(*jsonOut, mode, usedWindow, result, thresholds{*cpuP95Limit, *memP95Limit, *ioP95Limit, *failureLimit}, violations)
		os.Exit(1)
	}

	fmt.Println("PASS: thresholds satisfied")
	writeJSONReport(*jsonOut, mode, usedWindow, result, thresholds{*cpuP95Limit, *memP95Limit, *ioP95Limit, *failureLimit}, violations)
}

func evaluate(metricsURL, promURL, window, bearerToken string, client *http.Client) (summary, string, error) {
	if promURL != "" {
		if window == "" {
			window = "5m"
		}
		s, err := evaluatePromQL(promURL, window, bearerToken, client)
		return s, window, err
	}
	s, err := evaluateScrape(metricsURL, bearerToken, client)
	return s, window, err
}

func evaluatePromQL(promURL, window, bearerToken string, client *http.Client) (summary, error) {
	cpuP95, err := queryHistogramQuantile(promURL, "d_eyes_server_agent_cpu_percent", window, bearerToken, client)
	if err != nil {
		return summary{}, err
	}
	memP95, err := queryHistogramQuantile(promURL, "d_eyes_server_agent_memory_percent", window, bearerToken, client)
	if err != nil {
		return summary{}, err
	}
	ioP95, err := queryHistogramQuantile(promURL, "d_eyes_server_agent_io_util_percent", window, bearerToken, client)
	if err != nil {
		return summary{}, err
	}
	failRate, err := queryFailureRate(promURL, window, bearerToken, client)
	if err != nil {
		return summary{}, err
	}
	return summary{CPUP95: cpuP95, MemP95: memP95, IOP95: ioP95, FailureRate: failRate}, nil
}

func queryHistogramQuantile(promURL, metric, window, bearerToken string, client *http.Client) (float64, error) {
	query := fmt.Sprintf("histogram_quantile(0.95, rate(%s_bucket[%s]))", metric, window)
	return runPromQuery(promURL, query, bearerToken, client)
}

func queryFailureRate(promURL, window, bearerToken string, client *http.Client) (float64, error) {
	query := fmt.Sprintf("sum(rate(d_eyes_server_tasks_completed_total{status=\"failed\"}[%s])) / sum(rate(d_eyes_server_tasks_completed_total[%s]))", window, window)
	return runPromQuery(promURL, query, bearerToken, client)
}

type promAPIResponse struct {
	Status string `json:"status"`
	Data   struct {
		ResultType string `json:"resultType"`
		Result     []struct {
			Value []interface{} `json:"value"`
		} `json:"result"`
	} `json:"data"`
	ErrorType string `json:"errorType"`
	Error     string `json:"error"`
}

func runPromQuery(promURL, query, bearerToken string, client *http.Client) (float64, error) {
	endpoint := strings.TrimRight(promURL, "/") + "/api/v1/query"
	values := url.Values{}
	values.Set("query", query)

	req, err := http.NewRequest(http.MethodGet, endpoint+"?"+values.Encode(), nil)
	if err != nil {
		return 0, fmt.Errorf("build promql request: %w", err)
	}
	setAuth(req, bearerToken)

	resp, err := client.Do(req)
	if err != nil {
		return 0, fmt.Errorf("query promql: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return 0, fmt.Errorf("unexpected status from prometheus: %s", resp.Status)
	}

	var payload promAPIResponse
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		return 0, fmt.Errorf("decode promql response: %w", err)
	}
	if payload.Status != "success" {
		return 0, fmt.Errorf("promql error (%s): %s", payload.ErrorType, payload.Error)
	}
	if len(payload.Data.Result) == 0 || len(payload.Data.Result[0].Value) < 2 {
		return 0, fmt.Errorf("promql returned no data")
	}
	rawVal, ok := payload.Data.Result[0].Value[1].(string)
	if !ok {
		return 0, fmt.Errorf("promql value is not a string")
	}
	val, err := strconv.ParseFloat(rawVal, 64)
	if err != nil {
		return 0, fmt.Errorf("parse promql value: %w", err)
	}
	if math.IsNaN(val) || math.IsInf(val, 0) {
		return 0, nil
	}
	return val, nil
}

func evaluateScrape(metricsURL, bearerToken string, client *http.Client) (summary, error) {
	req, err := http.NewRequest(http.MethodGet, metricsURL, nil)
	if err != nil {
		return summary{}, fmt.Errorf("build scrape request: %w", err)
	}
	setAuth(req, bearerToken)

	resp, err := client.Do(req)
	if err != nil {
		return summary{}, fmt.Errorf("fetch metrics: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return summary{}, fmt.Errorf("unexpected status from metrics endpoint: %s", resp.Status)
	}

	parser := expfmt.TextParser{}
	families, err := parser.TextToMetricFamilies(resp.Body)
	if err != nil {
		return summary{}, fmt.Errorf("parse metrics: %w", err)
	}

	cpuP95, err := histogramQuantile("d_eyes_server_agent_cpu_percent", families["d_eyes_server_agent_cpu_percent"], 0.95)
	if err != nil {
		return summary{}, err
	}
	memP95, err := histogramQuantile("d_eyes_server_agent_memory_percent", families["d_eyes_server_agent_memory_percent"], 0.95)
	if err != nil {
		return summary{}, err
	}
	ioP95, err := histogramQuantile("d_eyes_server_agent_io_util_percent", families["d_eyes_server_agent_io_util_percent"], 0.95)
	if err != nil {
		return summary{}, err
	}
	failRate, err := taskFailureRate(families["d_eyes_server_tasks_completed_total"])
	if err != nil {
		return summary{}, err
	}
	return summary{CPUP95: cpuP95, MemP95: memP95, IOP95: ioP95, FailureRate: failRate}, nil
}

func histogramQuantile(name string, fam *dto.MetricFamily, quantile float64) (float64, error) {
	if fam == nil || len(fam.Metric) == 0 {
		return 0, fmt.Errorf("metric %s is missing", name)
	}
	h := fam.Metric[0].GetHistogram()
	if h == nil {
		return 0, fmt.Errorf("metric %s is not a histogram", name)
	}
	total := h.GetSampleCount()
	if total == 0 {
		return 0, nil
	}
	target := uint64(math.Ceil(float64(total) * quantile))
	var lastUpper float64
	for _, b := range h.GetBucket() {
		lastUpper = b.GetUpperBound()
		if b.GetCumulativeCount() >= target {
			if math.IsInf(lastUpper, 1) {
				return 100, nil
			}
			return lastUpper, nil
		}
	}
	if math.IsInf(lastUpper, 1) {
		return 100, nil
	}
	return lastUpper, nil
}

func taskFailureRate(fam *dto.MetricFamily) (float64, error) {
	if fam == nil || len(fam.Metric) == 0 {
		return 0, fmt.Errorf("metric d_eyes_server_tasks_completed_total is missing")
	}
	var failed, total float64
	for _, m := range fam.Metric {
		counter := m.GetCounter()
		if counter == nil {
			continue
		}
		val := counter.GetValue()
		status := labelValue(m.Label, "status")
		if status == "failed" {
			failed += val
		}
		total += val
	}
	if total == 0 {
		return 0, nil
	}
	return failed / total, nil
}

func labelValue(labels []*dto.LabelPair, name string) string {
	for _, lp := range labels {
		if lp.GetName() == name {
			return lp.GetValue()
		}
	}
	return ""
}

type thresholds struct {
	CPUP95Limit      float64 `json:"cpu_p95_limit"`
	MemP95Limit      float64 `json:"mem_p95_limit"`
	IOP95Limit       float64 `json:"io_p95_limit"`
	FailureRateLimit float64 `json:"failure_rate_limit"`
}

type report struct {
	Mode       string     `json:"mode"`
	Window     string     `json:"window"`
	Summary    summary    `json:"summary"`
	Thresholds thresholds `json:"thresholds"`
	Pass       bool       `json:"pass"`
	Violations []string   `json:"violations,omitempty"`
}

func writeJSONReport(path, mode, window string, sum summary, th thresholds, violations []string) {
	if path == "" {
		return
	}
	data, err := json.MarshalIndent(report{
		Mode:       mode,
		Window:     window,
		Summary:    sum,
		Thresholds: th,
		Pass:       len(violations) == 0,
		Violations: violations,
	}, "", "  ")
	if err != nil {
		fmt.Fprintf(os.Stderr, "perfcheck: marshal json: %v\n", err)
		return
	}
	if path == "-" {
		fmt.Println(string(data))
		return
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		fmt.Fprintf(os.Stderr, "perfcheck: write json report: %v\n", err)
	}
}

func newHTTPClient(caFile string) (*http.Client, error) {
	rootCAs, err := x509.SystemCertPool()
	if err != nil {
		rootCAs = x509.NewCertPool()
	}
	if rootCAs == nil {
		rootCAs = x509.NewCertPool()
	}
	if caFile != "" {
		pemData, err := os.ReadFile(caFile)
		if err != nil {
			return nil, fmt.Errorf("read ca file: %w", err)
		}
		if ok := rootCAs.AppendCertsFromPEM(pemData); !ok {
			return nil, fmt.Errorf("append ca certs failed")
		}
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.TLSClientConfig = &tls.Config{RootCAs: rootCAs}
	return &http.Client{
		Timeout:   10 * time.Second,
		Transport: transport,
	}, nil
}

func setAuth(req *http.Request, bearerToken string) {
	if bearerToken != "" {
		req.Header.Set("Authorization", "Bearer "+bearerToken)
	}
}

// helpers for tests
func newHistogramMetricFamily(buckets map[float64]uint64, count uint64) *dto.MetricFamily {
	hist := &dto.Histogram{
		SampleCount: proto.Uint64(count),
	}
	var cumulative uint64
	ordered := make([]float64, 0, len(buckets))
	for upper := range buckets {
		ordered = append(ordered, upper)
	}
	// naive sort by upper bound
	for i := 0; i < len(ordered); i++ {
		for j := i + 1; j < len(ordered); j++ {
			if ordered[j] < ordered[i] {
				ordered[i], ordered[j] = ordered[j], ordered[i]
			}
		}
	}
	for _, upper := range ordered {
		cumulative += buckets[upper]
		hist.Bucket = append(hist.Bucket, &dto.Bucket{
			UpperBound:      proto.Float64(upper),
			CumulativeCount: proto.Uint64(cumulative),
		})
	}
	return &dto.MetricFamily{
		Metric: []*dto.Metric{{Histogram: hist}},
	}
}
