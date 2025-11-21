package tasks

import (
	"encoding/json"
	"os"
	"time"

	"github.com/m-sec-org/d-eyes/agent/internal/tasks/taskcache"
)

type manifestCache struct {
	Key     string                        `json:"-"`
	Entries map[string]manifestCacheEntry `json:"entries"`
	SavedAt time.Time                     `json:"saved_at"`
}

type manifestCacheEntry struct {
	Fingerprint string            `json:"fingerprint"`
	Components  []componentRecord `json:"components"`
	CachedAt    time.Time         `json:"cached_at"`
}

func loadManifestCache(cacheKey string, ttl time.Duration) (*manifestCache, error) {
	path, _, ok, err := taskcache.RestoreFile(supplyChainCacheNamespace+".manifests", cacheKey, ttl)
	if err != nil {
		return nil, err
	}
	cache := &manifestCache{Key: cacheKey, Entries: make(map[string]manifestCacheEntry)}
	if !ok {
		return cache, nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return cache, err
	}
	if err := json.Unmarshal(data, cache); err != nil {
		return cache, err
	}
	cache.Key = cacheKey
	if cache.Entries == nil {
		cache.Entries = make(map[string]manifestCacheEntry)
	}
	return cache, nil
}

func (m *manifestCache) Lookup(path, fingerprint string) ([]componentRecord, bool) {
	if m == nil || len(m.Entries) == 0 {
		return nil, false
	}
	entry, ok := m.Entries[path]
	if !ok || entry.Fingerprint != fingerprint {
		return nil, false
	}
	comps := make([]componentRecord, len(entry.Components))
	copy(comps, entry.Components)
	return comps, true
}

func (m *manifestCache) Update(path, fingerprint string, comps []componentRecord) {
	if m == nil {
		return
	}
	if m.Entries == nil {
		m.Entries = make(map[string]manifestCacheEntry)
	}
	cloned := make([]componentRecord, len(comps))
	copy(cloned, comps)
	m.Entries[path] = manifestCacheEntry{Fingerprint: fingerprint, Components: cloned, CachedAt: time.Now().UTC()}
}

func (m *manifestCache) Save() error {
	if m == nil || m.Key == "" {
		return nil
	}
	m.SavedAt = time.Now().UTC()
	data, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp("", "supplychain-manifest-*.json")
	if err != nil {
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		os.Remove(tmp.Name())
		return err
	}
	tmp.Close()
	defer os.Remove(tmp.Name())
	return taskcache.SaveFile(supplyChainCacheNamespace+".manifests", m.Key, tmp.Name(), nil)
}
