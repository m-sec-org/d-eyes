package app

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"

	"github.com/prometheus/client_golang/prometheus"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"

	"github.com/m-sec-org/d-eyes/server/internal/api"
	v1 "github.com/m-sec-org/d-eyes/server/internal/api/v1"
	"github.com/m-sec-org/d-eyes/server/internal/config"
	"github.com/m-sec-org/d-eyes/server/internal/grpcsvc"
	"github.com/m-sec-org/d-eyes/server/internal/logger"
	"github.com/m-sec-org/d-eyes/server/internal/metrics"
	"github.com/m-sec-org/d-eyes/server/internal/monitor"
	"github.com/m-sec-org/d-eyes/server/internal/queueprovider"
	"github.com/m-sec-org/d-eyes/server/internal/scheduler"
	"github.com/m-sec-org/d-eyes/server/internal/store"
	"github.com/m-sec-org/d-eyes/server/internal/storeprovider"
	pb "github.com/m-sec-org/d-eyes/server/proto/agentservicepb"
)

// Run bootstraps and starts the server components.
func Run(ctx context.Context, cfg config.Config) error {
	if err := cfg.Validate(); err != nil {
		return err
	}
	log := logger.New()

	st, err := storeprovider.New(ctx, cfg.Database)
	if err != nil {
		return fmt.Errorf("init store: %w", err)
	}
	queue, err := queueprovider.New(ctx, cfg)
	if err != nil {
		return fmt.Errorf("init queue: %w", err)
	}
	sched := scheduler.New(st, queue, cfg.Scheduler)
	if err := sched.PrimeFromStore(ctx); err != nil {
		return fmt.Errorf("prime queue: %w", err)
	}
	log.Info("queue primed from persistent tasks")
	heartbeatStop := monitor.StartHeartbeat(ctx, st, cfg.Scheduler, log)
	defer heartbeatStop()

	reg := prometheus.NewRegistry()
	metricsCollector := metrics.New(reg)
	sched.SetMetrics(metricsCollector)
	metricsHandler := metrics.Handler(reg)

	taskHandler := &v1.TaskHandler{Store: st, Sched: sched}
	router := api.NewRouter(cfg, taskHandler, metricsHandler)

	grpcServer, err := newGRPCServer(cfg, st, sched, log, metricsCollector)
	if err != nil {
		return err
	}

	httpSrv := &http.Server{Addr: cfg.Server.HTTPAddr, Handler: router}

	go func() {
		log.Info("http server listening", "addr", cfg.Server.HTTPAddr)
		if err := httpSrv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Error("http server error", "error", err)
		}
	}()

	go func() {
		if err := serveGRPC(cfg, grpcServer, log); err != nil {
			log.Error("grpc server stopped", "error", err)
		}
	}()

	log.Info("d-eyes server started")

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)

	select {
	case <-ctx.Done():
		log.Info("context canceled, shutting down")
	case sig := <-stop:
		log.Info("received signal, shutting down", "signal", sig.String())
	}

	_ = httpSrv.Shutdown(context.Background())
	grpcServer.GracefulStop()
	return nil
}

func newGRPCServer(cfg config.Config, st store.Store, sched *scheduler.Scheduler, log *slog.Logger, metricsCollector *metrics.Metrics) (*grpc.Server, error) {
	var serverOpts []grpc.ServerOption
	if cfg.Server.TLS.Enabled {
		creds, err := credentials.NewServerTLSFromFile(cfg.Server.TLS.CertFile, cfg.Server.TLS.KeyFile)
		if err != nil {
			return nil, fmt.Errorf("load tls cert: %w", err)
		}
		serverOpts = append(serverOpts, grpc.Creds(creds))
	}
	grpcServer := grpc.NewServer(serverOpts...)
	svc := grpcsvc.NewService(cfg, st, sched, log, metricsCollector)
	pb.RegisterAgentServiceServer(grpcServer, svc)
	return grpcServer, nil
}

func serveGRPC(cfg config.Config, grpcServer *grpc.Server, log *slog.Logger) error {
	lis, err := net.Listen("tcp", cfg.Server.GRPCAddr)
	if err != nil {
		return fmt.Errorf("listen grpc: %w", err)
	}
	log.Info("grpc server listening", "addr", cfg.Server.GRPCAddr)
	return grpcServer.Serve(lis)
}
