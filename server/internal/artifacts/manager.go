package artifacts

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/m-sec-org/d-eyes/server/internal/config"
)

// Metadata describes the client-provided info for an upload.
type Metadata struct {
	Filename    string
	ContentType string
	Hash        string
	Encryption  string
	Size        int64
}

// StoredArtifact represents a completed upload that can be persisted.
type StoredArtifact struct {
	ID          uuid.UUID
	Filename    string
	ContentType string
	Hash        string
	Encryption  string
	Data        []byte
}

type uploadToken struct {
	id        uuid.UUID
	meta      Metadata
	path      string
	expiresAt time.Time
	completed bool
}

// Manager coordinates artifact uploads prior to ingestion.
type Manager struct {
	cfg     config.ArtifactConfig
	mu      sync.RWMutex
	uploads map[uuid.UUID]*uploadToken
}

// NewManager instantiates a Manager backed by the given config.
func NewManager(cfg config.ArtifactConfig) (*Manager, error) {
	if strings.TrimSpace(cfg.StorageDir) == "" {
		return nil, errors.New("artifact storage_dir must be set")
	}
	if cfg.UploadTTL <= 0 {
		cfg.UploadTTL = 15 * time.Minute
	}
	if cfg.MaxSize <= 0 {
		cfg.MaxSize = 25 * 1024 * 1024 // 25 MB
	}
	if err := os.MkdirAll(cfg.StorageDir, 0o750); err != nil {
		return nil, fmt.Errorf("create artifact storage dir: %w", err)
	}
	return &Manager{
		cfg:     cfg,
		uploads: make(map[uuid.UUID]*uploadToken),
	}, nil
}

// CreateUpload reserves a token for a future upload.
func (m *Manager) CreateUpload(meta Metadata) (uuid.UUID, time.Time, error) {
	meta = sanitizeMetadata(meta)
	if err := validateMetadata(meta, m.cfg.MaxSize); err != nil {
		return uuid.Nil, time.Time{}, err
	}
	id := uuid.New()
	expiry := time.Now().Add(m.cfg.UploadTTL)
	token := &uploadToken{
		id:        id,
		meta:      meta,
		path:      filepath.Join(m.cfg.StorageDir, id.String()+".bin"),
		expiresAt: expiry,
	}
	m.mu.Lock()
	m.uploads[id] = token
	m.mu.Unlock()
	return id, expiry, nil
}

// WriteUpload streams the request body into storage and finalizes the token.
func (m *Manager) WriteUpload(id uuid.UUID, reader io.Reader) error {
	m.mu.Lock()
	token, ok := m.uploads[id]
	if !ok {
		m.mu.Unlock()
		return fmt.Errorf("upload %s not found", id)
	}
	if time.Now().After(token.expiresAt) {
		delete(m.uploads, id)
		m.mu.Unlock()
		return fmt.Errorf("upload %s expired", id)
	}
	if token.completed {
		m.mu.Unlock()
		return fmt.Errorf("upload %s already completed", id)
	}
	path := token.path
	m.mu.Unlock()

	tmpPath := path + ".part"
	file, err := os.Create(tmpPath)
	if err != nil {
		return fmt.Errorf("create temp artifact file: %w", err)
	}
	defer file.Close()

	limited := io.LimitReader(reader, m.cfg.MaxSize+1)
	written, err := io.Copy(file, limited)
	if err != nil {
		return fmt.Errorf("write artifact: %w", err)
	}
	if written > m.cfg.MaxSize {
		_ = os.Remove(tmpPath)
		return fmt.Errorf("upload exceeds max size (%d bytes)", m.cfg.MaxSize)
	}
	if token.meta.Size > 0 && written != token.meta.Size {
		_ = os.Remove(tmpPath)
		return fmt.Errorf("size mismatch: declared %d bytes, uploaded %d bytes", token.meta.Size, written)
	}
	if err := file.Close(); err != nil {
		return fmt.Errorf("close temp artifact: %w", err)
	}
	if err := os.Rename(tmpPath, path); err != nil {
		return fmt.Errorf("finalize artifact: %w", err)
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	if token, ok := m.uploads[id]; ok {
		token.completed = true
	}
	return nil
}

// Consume retrieves the artifact data and removes it from the manager.
func (m *Manager) Consume(id uuid.UUID) (StoredArtifact, error) {
	m.mu.Lock()
	token, ok := m.uploads[id]
	if !ok {
		m.mu.Unlock()
		return StoredArtifact{}, fmt.Errorf("artifact %s not found", id)
	}
	if !token.completed {
		m.mu.Unlock()
		return StoredArtifact{}, fmt.Errorf("artifact %s not uploaded yet", id)
	}
	delete(m.uploads, id)
	m.mu.Unlock()

	data, err := os.ReadFile(token.path)
	if err != nil {
		return StoredArtifact{}, fmt.Errorf("read artifact: %w", err)
	}
	_ = os.Remove(token.path)

	checksum := sha256.Sum256(data)
	if token.meta.Hash != "" {
		expected := strings.ToLower(strings.TrimSpace(token.meta.Hash))
		if expected != hex.EncodeToString(checksum[:]) {
			_ = os.Remove(token.path)
			return StoredArtifact{}, fmt.Errorf("artifact %s hash mismatch", id)
		}
	}

	return StoredArtifact{
		ID:          token.id,
		Filename:    token.meta.Filename,
		ContentType: token.meta.ContentType,
		Hash:        token.meta.Hash,
		Encryption:  token.meta.Encryption,
		Data:        data,
	}, nil
}

// Config exposes the underlying artifact config.
func (m *Manager) Config() config.ArtifactConfig {
	return m.cfg
}

func sanitizeMetadata(meta Metadata) Metadata {
	meta.Filename = strings.TrimSpace(meta.Filename)
	meta.ContentType = strings.TrimSpace(meta.ContentType)
	meta.Hash = strings.ToLower(strings.TrimSpace(meta.Hash))
	meta.Encryption = strings.ToLower(strings.TrimSpace(meta.Encryption))
	if meta.Encryption == "" {
		meta.Encryption = "none"
	}
	return meta
}

func validateMetadata(meta Metadata, maxSize int64) error {
	if meta.Filename == "" {
		return errors.New("filename required")
	}
	if meta.Size <= 0 {
		return errors.New("size must be positive")
	}
	if meta.Size > maxSize {
		return fmt.Errorf("file exceeds max size (%d bytes)", maxSize)
	}
	if meta.Hash == "" {
		return errors.New("hash required")
	}
	if len(meta.Hash) != 64 {
		return errors.New("hash must be 64 hex characters")
	}
	if _, err := hex.DecodeString(meta.Hash); err != nil {
		return errors.New("hash must be hexadecimal")
	}
	if meta.Encryption == "" {
		meta.Encryption = "none"
	}
	if meta.Encryption != "none" && meta.Encryption != "aes256-gcm" {
		return fmt.Errorf("unsupported encryption %q", meta.Encryption)
	}
	return nil
}
