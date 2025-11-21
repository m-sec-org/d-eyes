package tasks

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

func embedRiskMetadata(meta map[string]string, risks map[string]int) {
	if meta == nil {
		return
	}
	for level, count := range risks {
		meta["risk."+strings.ToLower(level)] = strconv.Itoa(count)
	}
}

func metadataToRisk(meta map[string]string) map[string]int {
	if len(meta) == 0 {
		return nil
	}
	risks := make(map[string]int)
	for key, val := range meta {
		if strings.HasPrefix(key, "risk.") {
			level := strings.TrimPrefix(key, "risk.")
			if n, err := strconv.Atoi(val); err == nil && n > 0 {
				risks[level] = n
			}
		}
	}
	if len(risks) == 0 {
		return nil
	}
	return risks
}

func setCacheMetadata(meta map[string]string, namespace, key, strategy string, ttl time.Duration) {
	if meta == nil {
		return
	}
	if namespace != "" {
		meta["cache.namespace"] = namespace
	}
	if key != "" {
		meta["cache.key"] = key
	}
	if strategy != "" {
		meta["cache.strategy"] = strategy
	}
	meta["cache.hit"] = "false"
	if ttl > 0 {
		ttlSeconds := int64(ttl / time.Second)
		if ttlSeconds < 1 {
			ttlSeconds = 1
		}
		meta["cache.ttl_seconds"] = strconv.FormatInt(ttlSeconds, 10)
		now := time.Now().UTC()
		meta["cache.generated_at"] = now.Format(time.RFC3339)
		meta["cache.expires_at"] = now.Add(ttl).Format(time.RFC3339)
	}
}

func markCacheHit(meta map[string]string, ttl time.Duration) {
	if meta == nil {
		return
	}
	meta["cache.hit"] = "true"
	if ttl <= 0 {
		return
	}
	var cachedAt time.Time
	if ts := meta["cached_at"]; ts != "" {
		if t, err := time.Parse(time.RFC3339, ts); err == nil {
			cachedAt = t
		}
	}
	if cachedAt.IsZero() {
		cachedAt = time.Now().UTC()
	}
	age := time.Since(cachedAt)
	if age < 0 {
		age = 0
	}
	meta["cache.age_seconds"] = strconv.FormatInt(int64(age/time.Second), 10)
	meta["cache.expires_at"] = cachedAt.Add(ttl).Format(time.RFC3339)
}

func fileFingerprint(path string) (string, error) {
	info, err := os.Stat(path)
	if err != nil {
		return "", err
	}
	payload := fmt.Sprintf("%s:%d:%d", path, info.ModTime().UnixNano(), info.Size())
	sum := sha256.Sum256([]byte(payload))
	return hex.EncodeToString(sum[:]), nil
}
