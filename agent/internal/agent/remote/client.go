package remote

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"os"
	"sync"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"

	serverpb "github.com/m-sec-org/d-eyes/server/proto/agentservicepb"
)

// Metadata 描述 Agent 的基础信息，用于注册与心跳上报。
type Metadata struct {
	Name         string
	Platform     string
	Version      string
	Capabilities []string
	Labels       map[string]string
}

// HeartbeatPayload 表示一次心跳需要携带的状态。
type HeartbeatPayload struct {
	Load         float64
	RunningTasks []string
}

// Client 负责维护与 Server 的 gRPC 链接以及会话。
type Client struct {
	cfg      RemoteConfig
	conn     *grpc.ClientConn
	agentSvc serverpb.AgentServiceClient

	mu      sync.RWMutex
	agentID string
}

// NewClient 根据配置构造 Client 实例。
func NewClient(cfg RemoteConfig) *Client {
	if cfg.HeartbeatInterval <= 0 {
		cfg.HeartbeatInterval = 10 * time.Second
	}
	return &Client{cfg: cfg}
}

// Connect 建立 gRPC 连接。
func (c *Client) Connect(ctx context.Context) error {
	if c.cfg.ServerGRPCAddr == "" {
		return errors.New("remote client: empty gRPC address")
	}
	opts, err := dialOptions(c.cfg.TLS)
	if err != nil {
		return err
	}
	conn, err := grpc.DialContext(ctx, c.cfg.ServerGRPCAddr, opts...)
	if err != nil {
		return fmt.Errorf("remote client: dial failed: %w", err)
	}
	c.conn = conn
	c.agentSvc = serverpb.NewAgentServiceClient(conn)
	return nil
}

// Close 关闭底层连接。
func (c *Client) Close() error {
	if c.conn != nil {
		return c.conn.Close()
	}
	return nil
}

// Register 调用远程 Register 接口，保存返回的 agentID。
func (c *Client) Register(ctx context.Context, meta Metadata) (*serverpb.RegisterResponse, error) {
	if c.agentSvc == nil {
		return nil, errors.New("remote client: not connected")
	}
	req := &serverpb.RegisterRequest{
		Token: c.cfg.AgentToken,
		Metadata: &serverpb.AgentMetadata{
			Name:         meta.Name,
			Platform:     meta.Platform,
			Version:      meta.Version,
			Capabilities: append([]string(nil), meta.Capabilities...),
			Labels:       meta.Labels,
		},
	}
	resp, err := c.agentSvc.Register(ctx, req)
	if err != nil {
		return nil, err
	}
	c.mu.Lock()
	c.agentID = resp.GetAgentId()
	c.mu.Unlock()
	return resp, nil
}

// AgentID 返回最近一次注册成功的 Agent ID。
func (c *Client) AgentID() string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.agentID
}

// StartHeartbeat 启动心跳协程，消费数据并发送至 Server。
func (c *Client) StartHeartbeat(ctx context.Context, payloadCh <-chan HeartbeatPayload) (<-chan error, error) {
	if c.agentSvc == nil {
		return nil, errors.New("remote client: not connected")
	}
	agentID := c.AgentID()
	if agentID == "" {
		return nil, errors.New("remote client: agent not registered")
	}
	stream, err := c.agentSvc.Heartbeat(ctx)
	if err != nil {
		return nil, err
	}
	errCh := make(chan error, 1)

	go func() {
		defer close(errCh)
		ticker := time.NewTicker(c.cfg.HeartbeatInterval)
		defer ticker.Stop()
		var last HeartbeatPayload
		for {
			select {
			case <-ctx.Done():
				errCh <- ctx.Err()
				return
			case payload, ok := <-payloadCh:
				if ok {
					last = payload
				}
			case <-ticker.C:
				req := &serverpb.HeartbeatRequest{
					AgentId:      agentID,
					Timestamp:    time.Now().Unix(),
					Load:         last.Load,
					RunningTasks: append([]string(nil), last.RunningTasks...),
				}
				if err := stream.Send(req); err != nil {
					errCh <- err
					return
				}
				if _, err := stream.Recv(); err != nil {
					errCh <- err
					return
				}
			}
		}
	}()

	return errCh, nil
}

// PullTasks 调用远程 PullTasks 接口。
func (c *Client) PullTasks(ctx context.Context, maxTasks int32) (*serverpb.PullTaskResponse, error) {
	if c.agentSvc == nil {
		return nil, errors.New("remote client: not connected")
	}
	agentID := c.AgentID()
	if agentID == "" {
		return nil, errors.New("remote client: agent not registered")
	}
	if maxTasks <= 0 {
		maxTasks = 1
	}
	return c.agentSvc.PullTasks(ctx, &serverpb.PullTaskRequest{
		AgentId:  agentID,
		MaxTasks: maxTasks,
	})
}

// ReportResult 将执行结果回传给 Server。
func (c *Client) ReportResult(ctx context.Context, req *serverpb.ReportResultRequest) (*serverpb.ReportResultResponse, error) {
	if c.agentSvc == nil {
		return nil, errors.New("remote client: not connected")
	}
	return c.agentSvc.ReportResult(ctx, req)
}

func dialOptions(tlsCfg TLSConfig) ([]grpc.DialOption, error) {
	var opts []grpc.DialOption
	if tlsCfg.Enabled {
		creds, err := buildTLSCredentials(tlsCfg)
		if err != nil {
			return nil, err
		}
		opts = append(opts, grpc.WithTransportCredentials(creds))
	} else {
		opts = append(opts, grpc.WithTransportCredentials(insecure.NewCredentials()))
	}
	opts = append(opts, grpc.WithBlock())
	return opts, nil
}

func buildTLSCredentials(cfg TLSConfig) (credentials.TransportCredentials, error) {
	certPool := x509.NewCertPool()
	if cfg.CAFile != "" {
		data, err := os.ReadFile(cfg.CAFile)
		if err != nil {
			return nil, fmt.Errorf("load CA file: %w", err)
		}
		if ok := certPool.AppendCertsFromPEM(data); !ok {
			return nil, errors.New("append CA cert failed")
		}
	}
	var certs []tls.Certificate
	if cfg.CertFile != "" && cfg.KeyFile != "" {
		cert, err := tls.LoadX509KeyPair(cfg.CertFile, cfg.KeyFile)
		if err != nil {
			return nil, fmt.Errorf("load client cert: %w", err)
		}
		certs = append(certs, cert)
	}
	tlsCfg := &tls.Config{
		RootCAs:      certPool,
		Certificates: certs,
	}
	return credentials.NewTLS(tlsCfg), nil
}
