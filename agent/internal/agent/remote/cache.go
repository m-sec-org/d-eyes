package remote

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	serverpb "github.com/m-sec-org/d-eyes/server/proto/agentservicepb"
)

// FileStore 使用本地文件缓存待上报的任务结果，支持断线重试。
type FileStore struct {
	dir string
	mu  sync.Mutex
}

// NewFileStore 创建文件缓存目录。
func NewFileStore(dir string) (*FileStore, error) {
	if dir == "" {
		return nil, fmt.Errorf("cache dir cannot be empty")
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, fmt.Errorf("create cache dir: %w", err)
	}
	return &FileStore{dir: dir}, nil
}

// Save 将待上报结果持久化到本地。
func (s *FileStore) Save(req *serverpb.ReportResultRequest) error {
	if req == nil {
		return fmt.Errorf("nil result request")
	}
	record := serializedResult{
		AgentID:      req.GetAgentId(),
		LeaseID:      req.GetLeaseId(),
		TaskID:       req.GetTaskId(),
		Status:       req.GetStatus(),
		ErrorMessage: req.GetErrorMessage(),
		Summary:      req.GetSummaryJson(),
		Metadata:     cloneStringMap(req.GetMetadata()),
		ExitCode:     req.GetExitCode(),
		ErrorCode:    req.GetErrorCode(),
		SavedAt:      time.Now().UTC(),
	}
	data, err := json.Marshal(record)
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return os.WriteFile(s.path(record.LeaseID), data, 0o644)
}

// Delete 删除指定租约的缓存。
func (s *FileStore) Delete(leaseID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if leaseID == "" {
		return nil
	}
	if err := os.Remove(s.path(leaseID)); err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}

// Pending 返回当前所有待上报的结果请求。
func (s *FileStore) Pending() ([]*serverpb.ReportResultRequest, error) {
	entries, err := os.ReadDir(s.dir)
	if err != nil {
		return nil, err
	}
	results := make([]*serverpb.ReportResultRequest, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		data, err := os.ReadFile(filepath.Join(s.dir, entry.Name()))
		if err != nil {
			continue
		}
		var rec serializedResult
		if err := json.Unmarshal(data, &rec); err != nil {
			continue
		}
		results = append(results, rec.ToProto())
	}
	return results, nil
}

func (s *FileStore) path(leaseID string) string {
	return filepath.Join(s.dir, leaseID+".json")
}

type serializedResult struct {
	AgentID      string            `json:"agent_id"`
	LeaseID      string            `json:"lease_id"`
	TaskID       string            `json:"task_id"`
	Status       string            `json:"status"`
	ErrorMessage string            `json:"error_message,omitempty"`
	Summary      []byte            `json:"summary"`
	Metadata     map[string]string `json:"metadata,omitempty"`
	ExitCode     int32             `json:"exit_code,omitempty"`
	ErrorCode    string            `json:"error_code,omitempty"`
	SavedAt      time.Time         `json:"saved_at"`
}

func (s serializedResult) ToProto() *serverpb.ReportResultRequest {
	return &serverpb.ReportResultRequest{
		AgentId:      s.AgentID,
		TaskId:       s.TaskID,
		LeaseId:      s.LeaseID,
		Status:       s.Status,
		ErrorMessage: s.ErrorMessage,
		SummaryJson:  s.Summary,
		Metadata:     cloneStringMap(s.Metadata),
		ExitCode:     s.ExitCode,
		ErrorCode:    s.ErrorCode,
	}
}

func cloneStringMap(src map[string]string) map[string]string {
	if len(src) == 0 {
		return nil
	}
	dst := make(map[string]string, len(src))
	for k, v := range src {
		dst[k] = v
	}
	return dst
}
