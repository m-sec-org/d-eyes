package remote

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/test/bufconn"

	"github.com/m-sec-org/d-eyes/agent/internal/telemetry"
	serverpb "github.com/m-sec-org/d-eyes/server/proto/agentservicepb"
)

func TestClientWorkflowWithBufconn(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	mockSvc := newMockAgentService()
	server, lis := startBufconnServer(t, mockSvc)
	defer server.Stop()

	restoreCPU := telemetry.OverrideCPUPercentProvider(func() float64 { return 37.5 })
	defer restoreCPU()
	restoreMem := telemetry.OverrideMemoryPercentProvider(func() float64 { return 55.5 })
	defer restoreMem()
	restoreIO := telemetry.OverrideIOUtilizationProvider(func() float64 { return 12.5 })
	defer restoreIO()
	restoreBlocked := telemetry.OverrideBlockedActionsProvider(func() []string { return []string{"kill-process"} })
	defer restoreBlocked()

	client := NewClient(RemoteConfig{ServerGRPCAddr: "bufconn", AgentToken: "token", HeartbeatInterval: 10 * time.Millisecond})
	client.SetDialer(func(ctx context.Context, _ string) (net.Conn, error) {
		return lis.DialContext(ctx)
	})

	require.NoError(t, client.Connect(ctx))

	meta := Metadata{
		Name:         "test-agent",
		Platform:     "linux",
		Version:      "go1.x",
		Capabilities: []string{"respond"},
	}
	_, err := client.Register(ctx, meta)
	require.NoError(t, err)

	hbPayload := make(chan HeartbeatPayload, 1)
	hbErrCh, err := client.StartHeartbeat(ctx, hbPayload)
	require.NoError(t, err)

	hbPayload <- HeartbeatPayload{
		Load:         2.5,
		RunningTasks: []string{"task-1"},
		Metadata: map[string]string{
			"telemetry.cpu_percent": "37.50",
			"cache.respond_hits":    "3",
		},
	}

	select {
	case req := <-mockSvc.heartbeatCh:
		require.Equal(t, client.AgentID(), req.GetAgentId())
		require.InEpsilon(t, 2.5, req.GetLoad(), 0.001)
		require.Equal(t, []string{"task-1"}, req.GetRunningTasks())
		require.Equal(t, 37.5, req.GetTelemetry().GetCpuPercent())
		require.Equal(t, 55.5, req.GetTelemetry().GetMemoryPercent())
		require.Equal(t, 12.5, req.GetTelemetry().GetIoUtilPercent())
		require.Equal(t, []string{"kill-process"}, req.GetTelemetry().GetBlockedActions())
		require.Equal(t, "37.50", req.GetMetadata()["telemetry.cpu_percent"])
		require.Equal(t, "3", req.GetMetadata()["cache.respond_hits"])
	case <-time.After(2 * time.Second):
		t.Fatal("heartbeat not received")
	}

	mockSvc.setPullResponse(&serverpb.PullTaskResponse{
		Leases: []*serverpb.TaskLease{
			{TaskId: "task-1"},
		},
	})
	resp, err := client.PullTasks(ctx, 1)
	require.NoError(t, err)
	require.Len(t, resp.GetLeases(), 1)
	require.Equal(t, "task-1", resp.GetLeases()[0].GetTaskId())

	reportReq := &serverpb.ReportResultRequest{
		AgentId: client.AgentID(),
		TaskId:  "task-1",
		Status:  "succeeded",
	}
	_, err = client.ReportResult(ctx, reportReq)
	require.NoError(t, err)

	select {
	case req := <-mockSvc.reportCh:
		require.Equal(t, "task-1", req.GetTaskId())
	case <-time.After(time.Second):
		t.Fatal("report result not received")
	}

	cancel()
	select {
	case err := <-hbErrCh:
		require.Error(t, err)
	case <-time.After(time.Second):
		t.Fatal("heartbeat loop did not stop")
	}
}

func TestBuildTLSCredentials(t *testing.T) {
	dir := t.TempDir()
	caPath, certPath, keyPath := writeTLSFixtures(t, dir)
	creds, err := buildTLSCredentials(TLSConfig{
		Enabled:  true,
		CAFile:   caPath,
		CertFile: certPath,
		KeyFile:  keyPath,
	})
	require.NoError(t, err)
	require.NotNil(t, creds)
}

func TestBuildTLSCredentialsInvalidCA(t *testing.T) {
	_, err := buildTLSCredentials(TLSConfig{
		Enabled: true,
		CAFile:  "missing.pem",
	})
	require.Error(t, err)
}

func TestClientConnectMissingAddress(t *testing.T) {
	client := NewClient(RemoteConfig{})
	err := client.Connect(context.Background())
	require.Error(t, err)
	require.Contains(t, err.Error(), "empty gRPC address")
}

func TestClientRegisterWithoutConnect(t *testing.T) {
	client := NewClient(RemoteConfig{ServerGRPCAddr: "bufconn"})
	_, err := client.Register(context.Background(), Metadata{})
	require.Error(t, err)
	require.Contains(t, err.Error(), "not connected")
}

type mockAgentService struct {
	serverpb.UnimplementedAgentServiceServer

	registerCh  chan *serverpb.RegisterRequest
	heartbeatCh chan *serverpb.HeartbeatRequest
	pullReqCh   chan *serverpb.PullTaskRequest
	reportCh    chan *serverpb.ReportResultRequest

	mu       sync.Mutex
	pullResp *serverpb.PullTaskResponse
}

func newMockAgentService() *mockAgentService {
	return &mockAgentService{
		registerCh:  make(chan *serverpb.RegisterRequest, 1),
		heartbeatCh: make(chan *serverpb.HeartbeatRequest, 1),
		pullReqCh:   make(chan *serverpb.PullTaskRequest, 1),
		reportCh:    make(chan *serverpb.ReportResultRequest, 1),
		pullResp:    &serverpb.PullTaskResponse{},
	}
}

func (m *mockAgentService) Register(ctx context.Context, req *serverpb.RegisterRequest) (*serverpb.RegisterResponse, error) {
	m.registerCh <- req
	return &serverpb.RegisterResponse{
		AgentId:                  "agent-xyz",
		HeartbeatIntervalSeconds: 1,
	}, nil
}

func (m *mockAgentService) Heartbeat(stream serverpb.AgentService_HeartbeatServer) error {
	for {
		req, err := stream.Recv()
		if err != nil {
			return err
		}
		select {
		case m.heartbeatCh <- req:
		default:
		}
		if err := stream.Send(&serverpb.HeartbeatResponse{}); err != nil {
			return err
		}
	}
}

func (m *mockAgentService) PullTasks(ctx context.Context, req *serverpb.PullTaskRequest) (*serverpb.PullTaskResponse, error) {
	m.pullReqCh <- req
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.pullResp, nil
}

func (m *mockAgentService) ReportResult(ctx context.Context, req *serverpb.ReportResultRequest) (*serverpb.ReportResultResponse, error) {
	m.reportCh <- req
	return &serverpb.ReportResultResponse{Accepted: true}, nil
}

func (m *mockAgentService) setPullResponse(resp *serverpb.PullTaskResponse) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.pullResp = resp
}

func startBufconnServer(t *testing.T, svc serverpb.AgentServiceServer) (*grpc.Server, *bufconn.Listener) {
	t.Helper()
	lis := bufconn.Listen(1024 * 1024)
	server := grpc.NewServer()
	serverpb.RegisterAgentServiceServer(server, svc)

	go func() {
		if err := server.Serve(lis); err != nil {
			t.Logf("grpc server stopped: %v", err)
		}
	}()
	return server, lis
}

func writeTLSFixtures(t *testing.T, dir string) (caPath, certPath, keyPath string) {
	t.Helper()
	caKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	caTemplate := &x509.Certificate{
		SerialNumber:          bigInt(1),
		Subject:               pkix.Name{CommonName: "Test CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	require.NoError(t, err)
	caPath = filepath.Join(dir, "ca.pem")
	require.NoError(t, os.WriteFile(caPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER}), 0o600))

	clientKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	clientTemplate := &x509.Certificate{
		SerialNumber: bigInt(2),
		Subject:      pkix.Name{CommonName: "client"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	clientDER, err := x509.CreateCertificate(rand.Reader, clientTemplate, caTemplate, &clientKey.PublicKey, caKey)
	require.NoError(t, err)
	certPath = filepath.Join(dir, "client.pem")
	require.NoError(t, os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: clientDER}), 0o600))
	keyPath = filepath.Join(dir, "client-key.pem")
	require.NoError(t, os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(clientKey)}), 0o600))
	return caPath, certPath, keyPath
}

func bigInt(val int64) *big.Int {
	return big.NewInt(val)
}
