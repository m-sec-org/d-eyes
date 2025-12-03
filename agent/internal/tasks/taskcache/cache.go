package taskcache

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

type fileMetadata struct {
	FilePath  string            `json:"file_path"`
	Metadata  map[string]string `json:"metadata"`
	CreatedAt time.Time         `json:"created_at"`
}

var (
	cacheRoot string
	rootOnce  sync.Once
)

func ensureRoot() string {
	if strings.TrimSpace(cacheRoot) != "" {
		return cacheRoot
	}
	rootOnce.Do(func() {
		if strings.TrimSpace(cacheRoot) != "" {
			return
		}
		home, err := os.UserHomeDir()
		if err != nil || strings.TrimSpace(home) == "" {
			cacheRoot = filepath.Join(os.TempDir(), "d-eyes", "cache", "tasks")
		} else {
			cacheRoot = filepath.Join(home, ".d-eyes", "cache", "tasks")
		}
	})
	return cacheRoot
}

func namespaceDir(namespace string) string {
	return filepath.Join(ensureRoot(), namespace)
}

// SaveFile copies srcPath into cache namespace/key with metadata.
func SaveFile(namespace, key, srcPath string, metadata map[string]string) error {
	if namespace == "" || key == "" || srcPath == "" {
		return errors.New("taskcache: namespace/key/srcPath must be set")
	}
	dir := namespaceDir(namespace)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	hash := hashKey(key)
	dataPath := filepath.Join(dir, hash+".bin")
	metaPath := filepath.Join(dir, hash+".json")
	if err := copyFile(srcPath, dataPath); err != nil {
		return err
	}
	metaCopy := cloneMetadata(metadata)
	if metaCopy == nil {
		metaCopy = make(map[string]string)
	}
	metaCopy["cached_at"] = time.Now().UTC().Format(time.RFC3339)
	meta := fileMetadata{
		FilePath:  dataPath,
		Metadata:  metaCopy,
		CreatedAt: time.Now().UTC(),
	}
	data, err := json.Marshal(meta)
	if err != nil {
		return err
	}
	return os.WriteFile(metaPath, data, 0o644)
}

// RestoreFile returns cached file path and metadata if entry exists and TTL not expired.
func RestoreFile(namespace, key string, ttl time.Duration) (string, map[string]string, bool, error) {
	if namespace == "" || key == "" {
		return "", nil, false, errors.New("taskcache: namespace/key required")
	}
	dir := namespaceDir(namespace)
	hash := hashKey(key)
	metaPath := filepath.Join(dir, hash+".json")
	data, err := os.ReadFile(metaPath)
	if err != nil {
		if os.IsNotExist(err) {
			return "", nil, false, nil
		}
		return "", nil, false, err
	}
	var meta fileMetadata
	if err := json.Unmarshal(data, &meta); err != nil {
		_ = os.Remove(metaPath)
		return "", nil, false, err
	}
	if ttl > 0 && time.Since(meta.CreatedAt) > ttl {
		_ = os.Remove(metaPath)
		_ = os.Remove(meta.FilePath)
		return "", nil, false, nil
	}
	if _, err := os.Stat(meta.FilePath); err != nil {
		_ = os.Remove(metaPath)
		return "", nil, false, nil
	}
	meta.Metadata["cached_at"] = meta.CreatedAt.Format(time.RFC3339)
	return meta.FilePath, cloneMetadata(meta.Metadata), true, nil
}

// RestoreTo copies cached file to dstPath if cache hit.
func RestoreTo(namespace, key string, ttl time.Duration, dstPath string) (map[string]string, bool, error) {
	if dstPath == "" {
		return nil, false, errors.New("taskcache: dstPath required")
	}
	src, meta, ok, err := RestoreFile(namespace, key, ttl)
	if err != nil || !ok {
		return meta, ok, err
	}
	if err := copyFile(src, dstPath); err != nil {
		return meta, false, err
	}
	return meta, true, nil
}

// PurgeExpired removes entries older than ttl from namespace.
func PurgeExpired(namespace string, ttl time.Duration) {
	if namespace == "" || ttl <= 0 {
		return
	}
	dir := namespaceDir(namespace)
	entries, err := filepath.Glob(filepath.Join(dir, "*.json"))
	if err != nil {
		return
	}
	for _, metaPath := range entries {
		data, err := os.ReadFile(metaPath)
		if err != nil {
			_ = os.Remove(metaPath)
			continue
		}
		var meta fileMetadata
		if err := json.Unmarshal(data, &meta); err != nil {
			_ = os.Remove(metaPath)
			continue
		}
		if time.Since(meta.CreatedAt) > ttl {
			_ = os.Remove(metaPath)
			_ = os.Remove(meta.FilePath)
		}
	}
}

func hashKey(key string) string {
	sum := sha256.Sum256([]byte(key))
	return hex.EncodeToString(sum[:])
}

func copyFile(src, dst string) error {
	srcFile, err := os.Open(src)
	if err != nil {
		return err
	}
	defer srcFile.Close()
	dstFile, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer dstFile.Close()
	if _, err := io.Copy(dstFile, srcFile); err != nil {
		return err
	}
	return nil
}

func cloneMetadata(src map[string]string) map[string]string {
	if len(src) == 0 {
		return nil
	}
	dst := make(map[string]string, len(src))
	for k, v := range src {
		dst[k] = v
	}
	return dst
}
