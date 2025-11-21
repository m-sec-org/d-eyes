package threatintel

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
)

// ErrNoActiveConnector 在未配置任何可用数据源时返回。
var ErrNoActiveConnector = errors.New("threatintel: no active connector configured")

// IndicatorKind 表示指标类型。
type IndicatorKind string

// 支持的指标类型枚举。
const (
	IndicatorIP     IndicatorKind = "ip"
	IndicatorDomain IndicatorKind = "domain"
	IndicatorURL    IndicatorKind = "url"
	IndicatorHash   IndicatorKind = "hash"
	IndicatorFile   IndicatorKind = "file"
)

// Finding 描述一次情报查询的结果。
type Finding struct {
	Indicator      string            `json:"indicator"`
	Kind           IndicatorKind     `json:"kind"`
	Classification string            `json:"classification"`
	Confidence     string            `json:"confidence"`
	Source         string            `json:"source"`
	Details        map[string]string `json:"details,omitempty"`
	Context        map[string]string `json:"context,omitempty"`
	ObservedAt     time.Time         `json:"observed_at"`
}

type cacheEntry struct {
	findings []Finding
	expires  time.Time
}

// Manager 负责协调情报查询、缓存与启发式。
type Manager struct {
	cfg   Config
	cache map[string]cacheEntry
	mu    sync.RWMutex
	clock func() time.Time
}

// NewManager 根据配置创建情报管理器。
func NewManager(cfg Config) (*Manager, error) {
	mode := cfg.Mode
	if mode == "" {
		mode = ModeHybrid
	}
	cfg.Mode = mode

	// server 模式下直接交由服务端处理，此处不初始化。
	if mode == ModeServer {
		return nil, ErrNoActiveConnector
	}

	if cfg.CacheTTL <= 0 {
		cfg.CacheTTL = 6 * time.Hour
	}
	if cfg.CacheSize <= 0 {
		cfg.CacheSize = 512
	}
	if cfg.HTTPTimeout <= 0 {
		cfg.HTTPTimeout = 15 * time.Second
	}
	if cfg.MaxParallelPerSource <= 0 {
		cfg.MaxParallelPerSource = 4
	}
	if cfg.OpenTIPBaseURL == "" {
		cfg.OpenTIPBaseURL = DefaultOpenTIPBaseURL
	}
	if cfg.MetaDefenderBaseURL == "" {
		cfg.MetaDefenderBaseURL = DefaultMetaDefenderBaseURL
	}

	hasRemoteSource := strings.TrimSpace(cfg.OpenTIPAPIKey) != "" || strings.TrimSpace(cfg.MetaDefenderAPIKey) != ""
	if mode != ModeLocal && !hasRemoteSource {
		return nil, ErrNoActiveConnector
	}

	return &Manager{
		cfg:   cfg,
		cache: make(map[string]cacheEntry),
		clock: time.Now,
	}, nil
}

// LookupFile 对文件执行情报查询（启发式 + 缓存）。
func (m *Manager) LookupFile(ctx context.Context, path string, metadata map[string]string) ([]Finding, error) {
	if m == nil {
		return nil, fmt.Errorf("threatintel manager is nil")
	}
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
	}
	info, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	hash, err := hashFile(ctx, path)
	if err != nil {
		return nil, err
	}
	key := fmt.Sprintf("file:%s", hash)
	if cached, ok := m.getCached(key); ok {
		return cloneFindings(cached), nil
	}

	details := map[string]string{
		"sha256":     hash,
		"size_bytes": fmt.Sprintf("%d", info.Size()),
		"modified":   info.ModTime().UTC().Format(time.RFC3339),
		"filename":   filepath.Base(path),
	}
	classification, confidence, reason := classifyFile(path, info.Size())
	if reason != "" {
		details["heuristic"] = reason
	}

	finding := Finding{
		Indicator:      hash,
		Kind:           IndicatorHash,
		Classification: classification,
		Confidence:     confidence,
		Source:         "local-heuristic",
		Details:        details,
		Context:        cloneMap(metadata),
		ObservedAt:     m.clock(),
	}
	m.storeCache(key, []Finding{finding})
	return []Finding{finding}, nil
}

// LookupIndicator 对 IP/Domain/URL/Hash 等指标执行本地判定。
func (m *Manager) LookupIndicator(ctx context.Context, kind IndicatorKind, value string, metadata map[string]string) ([]Finding, error) {
	if m == nil {
		return nil, fmt.Errorf("threatintel manager is nil")
	}
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
	}
	value = strings.TrimSpace(value)
	if value == "" {
		return nil, fmt.Errorf("empty indicator value")
	}
	key := fmt.Sprintf("indicator:%s:%s", kind, strings.ToLower(value))
	if cached, ok := m.getCached(key); ok {
		return cloneFindings(cached), nil
	}
	classification, confidence, source, details := classifyIndicator(kind, value)
	finding := Finding{
		Indicator:      value,
		Kind:           kind,
		Classification: classification,
		Confidence:     confidence,
		Source:         source,
		Details:        details,
		Context:        cloneMap(metadata),
		ObservedAt:     m.clock(),
	}
	m.storeCache(key, []Finding{finding})
	return []Finding{finding}, nil
}

func (m *Manager) storeCache(key string, findings []Finding) {
	if m.cfg.CacheSize <= 0 {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(m.cache) >= m.cfg.CacheSize {
		m.evictLocked()
	}
	m.cache[key] = cacheEntry{
		findings: cloneFindings(findings),
		expires:  m.clock().Add(m.cfg.CacheTTL),
	}
}

func (m *Manager) getCached(key string) ([]Finding, bool) {
	m.mu.RLock()
	entry, ok := m.cache[key]
	m.mu.RUnlock()
	if !ok {
		return nil, false
	}
	if m.clock().After(entry.expires) {
		m.mu.Lock()
		delete(m.cache, key)
		m.mu.Unlock()
		return nil, false
	}
	return cloneFindings(entry.findings), true
}

func (m *Manager) evictLocked() {
	if len(m.cache) == 0 {
		return
	}
	// 优先清理过期项
	now := m.clock()
	for k, v := range m.cache {
		if now.After(v.expires) {
			delete(m.cache, k)
		}
	}
	if len(m.cache) < m.cfg.CacheSize {
		return
	}
	// 简单按键排序淘汰最旧项
	keys := make([]string, 0, len(m.cache))
	for k := range m.cache {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for i := len(keys) - 1; i >= 0 && len(m.cache) >= m.cfg.CacheSize; i-- {
		delete(m.cache, keys[i])
	}
}

func hashFile(ctx context.Context, path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	hasher := sha256.New()
	buf := make([]byte, 64*1024)
	for {
		select {
		case <-ctx.Done():
			return "", ctx.Err()
		default:
		}
		n, err := f.Read(buf)
		if n > 0 {
			if _, wErr := hasher.Write(buf[:n]); wErr != nil {
				return "", wErr
			}
		}
		if err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			return "", err
		}
	}
	return hex.EncodeToString(hasher.Sum(nil)), nil
}

func classifyFile(path string, size int64) (classification, confidence, reason string) {
	lower := strings.ToLower(filepath.Base(path))
	suspiciousExt := []string{".exe", ".dll", ".ps1", ".bat", ".vbs", ".scr", ".jar"}
	for _, ext := range suspiciousExt {
		if strings.HasSuffix(lower, ext) {
			reason = fmt.Sprintf("extension %s", ext)
			return "suspicious", "medium", reason
		}
	}
	if size == 0 {
		return "benign", "low", "empty file"
	}
	if strings.Contains(lower, "temp") || strings.Contains(lower, "tmp") {
		return "suspicious", "low", "temporary path heuristic"
	}
	return "unknown", "low", ""
}

func classifyIndicator(kind IndicatorKind, value string) (string, string, string, map[string]string) {
	details := make(map[string]string)
	source := "local-heuristic"
	switch kind {
	case IndicatorIP:
		ip := net.ParseIP(value)
		if ip == nil {
			return "invalid", "high", source, details
		}
		if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
			return "internal", "medium", source, details
		}
		if isSuspiciousIP(ip) {
			return "suspicious", "medium", source, details
		}
		return "unknown", "low", source, details
	case IndicatorDomain:
		domain := strings.ToLower(value)
		if strings.HasSuffix(domain, ".gov") || strings.HasSuffix(domain, ".edu") {
			return "trusted", "medium", source, details
		}
		if strings.Contains(domain, "update") && strings.Contains(domain, "microsoft") {
			return "trusted", "low", source, details
		}
		if maliciousDomainPattern.MatchString(domain) {
			return "suspicious", "medium", source, details
		}
		return "unknown", "low", source, details
	case IndicatorURL:
		url := strings.ToLower(value)
		if strings.HasPrefix(url, "https://") {
			return "unknown", "low", source, details
		}
		if strings.HasPrefix(url, "http://") && strings.Contains(url, "login") {
			return "suspicious", "medium", source, details
		}
		return "unknown", "low", source, details
	case IndicatorHash:
		if len(value) == 64 {
			if strings.HasPrefix(strings.ToLower(value), "dead") {
				return "suspicious", "medium", source, details
			}
			return "unknown", "low", source, details
		}
		return "invalid", "high", source, details
	default:
		return "unknown", "low", source, details
	}
}

func cloneFindings(src []Finding) []Finding {
	if len(src) == 0 {
		return nil
	}
	out := make([]Finding, 0, len(src))
	for _, item := range src {
		out = append(out, Finding{
			Indicator:      item.Indicator,
			Kind:           item.Kind,
			Classification: item.Classification,
			Confidence:     item.Confidence,
			Source:         item.Source,
			Details:        cloneMap(item.Details),
			Context:        cloneMap(item.Context),
			ObservedAt:     item.ObservedAt,
		})
	}
	return out
}

func cloneMap(src map[string]string) map[string]string {
	if len(src) == 0 {
		return nil
	}
	out := make(map[string]string, len(src))
	for k, v := range src {
		out[k] = v
	}
	return out
}

func isSuspiciousIP(ip net.IP) bool {
	// RFC1918 已通过 Private 检测，这里仅做简单黑名单。
	suspiciousRanges := []struct {
		subnet string
		mask   string
	}{
		{"45.134.0.0", "255.254.0.0"}, // 随机示例
		{"103.0.0.0", "255.0.0.0"},
	}
	for _, item := range suspiciousRanges {
		_, network, err := net.ParseCIDR(fmt.Sprintf("%s/%s", item.subnet, maskToCIDR(item.mask)))
		if err != nil {
			continue
		}
		if network.Contains(ip) {
			return true
		}
	}
	return false
}

func maskToCIDR(mask string) string {
	ip := net.ParseIP(mask)
	if ip == nil {
		return "24"
	}
	ip = ip.To4()
	if ip == nil {
		return "24"
	}
	ones, _ := net.IPMask(ip).Size()
	return fmt.Sprintf("%d", ones)
}

var maliciousDomainPattern = regexp.MustCompile(`(?i)(update|secure|login|verify)[\-\._]?((account|wallet|bank|paypal)|(microsoft|office|onedrive))`)
