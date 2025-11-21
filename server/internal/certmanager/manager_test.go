package certmanager

import (
	"log/slog"
	"os"
	"testing"
	"time"

	"github.com/m-sec-org/d-eyes/server/internal/config"
)

func TestManagerRotateAndIssue(t *testing.T) {
	dir := t.TempDir()
	cfg := config.PKIConfig{
		Enabled:           true,
		StorageDir:        dir,
		CommonName:        "test.local",
		Organization:      "d-eyes",
		ServerDNSNames:    []string{"localhost"},
		ServerCertTTL:     24 * time.Hour,
		AgentCertTTL:      12 * time.Hour,
		RequireClientCert: true,
	}
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))
	mgr, err := New(cfg, logger)
	if err != nil {
		t.Fatalf("new manager: %v", err)
	}

	caPEM, caExpiry := mgr.CACertificate()
	if len(caPEM) == 0 || caExpiry.Before(time.Now()) {
		t.Fatalf("invalid ca info")
	}
	serverPEM, serverExpiry := mgr.ServerCertificate()
	if len(serverPEM) == 0 || serverExpiry.Before(time.Now()) {
		t.Fatalf("invalid server info")
	}

	bundle, err := mgr.IssueAgentCertificate("agent-1", 2*time.Hour)
	if err != nil {
		t.Fatalf("issue agent cert: %v", err)
	}
	if len(bundle.CertPEM) == 0 || len(bundle.KeyPEM) == 0 || len(bundle.CAPEM) == 0 {
		t.Fatalf("agent bundle missing fields")
	}
	if bundle.ExpiresAt.Sub(time.Now()) < time.Hour {
		t.Fatalf("agent cert ttl unexpected")
	}

	res, err := mgr.Rotate()
	if err != nil {
		t.Fatalf("rotate: %v", err)
	}
	if len(res.CAPEM) == 0 || len(res.ServerPEM) == 0 {
		t.Fatalf("rotation missing pem data")
	}
	newServerPEM, _ := mgr.ServerCertificate()
	if string(serverPEM) == string(newServerPEM) {
		t.Fatalf("server cert did not change after rotation")
	}
}
