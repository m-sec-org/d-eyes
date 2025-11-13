package behavior

import (
	"bytes"
	"compress/gzip"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
)

type processNode struct {
	PID        int32  `json:"pid"`
	PPID       int32  `json:"ppid"`
	Name       string `json:"name"`
	Cmdline    string `json:"cmdline,omitempty"`
	Username   string `json:"user,omitempty"`
	CreateTime int64  `json:"create_time,omitempty"`
}

type netConn struct {
	Local  string `json:"local"`
	Remote string `json:"remote"`
	Status string `json:"status"`
	PID    int32  `json:"pid"`
}

type resourceUsage struct {
	Timestamp     string  `json:"timestamp"`
	MemoryPercent float64 `json:"memory_percent"`
	MemoryUsed    uint64  `json:"memory_used"`
	MemoryTotal   uint64  `json:"memory_total"`
	GoRoutines    int     `json:"goroutines"`
	Load1         float64 `json:"load1"`
	Load5         float64 `json:"load5"`
	Load15        float64 `json:"load15"`
}

type userSession struct {
	User     string `json:"user"`
	Terminal string `json:"terminal"`
	Host     string `json:"host"`
	Started  int64  `json:"started"`
}

func decodeProcessTree(encoded string) ([]processNode, error) {
	var nodes []processNode
	if err := decodeCompressed(encoded, &nodes); err != nil {
		return nil, err
	}
	return nodes, nil
}

func decodeConnections(encoded string) ([]netConn, error) {
	var conns []netConn
	if err := decodeCompressed(encoded, &conns); err != nil {
		return nil, err
	}
	return conns, nil
}

func decodeResource(encoded string) (*resourceUsage, error) {
	var usage resourceUsage
	if err := decodeCompressed(encoded, &usage); err != nil {
		return nil, err
	}
	return &usage, nil
}

func decodeSessions(encoded string) ([]userSession, error) {
	var sessions []userSession
	if err := decodeCompressed(encoded, &sessions); err != nil {
		return nil, err
	}
	return sessions, nil
}

func decodeCompressed(encoded string, target interface{}) error {
	if encoded == "" {
		return fmt.Errorf("empty payload")
	}
	raw, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return fmt.Errorf("base64 decode: %w", err)
	}
	reader, err := gzip.NewReader(bytes.NewReader(raw))
	if err != nil {
		return fmt.Errorf("gzip reader: %w", err)
	}
	defer reader.Close()
	data, err := io.ReadAll(reader)
	if err != nil {
		return fmt.Errorf("gzip read: %w", err)
	}
	if err := json.Unmarshal(data, target); err != nil {
		return fmt.Errorf("json decode: %w", err)
	}
	return nil
}
