package app

import (
	"context"
	"crypto/tls"
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

	"github.com/m-sec-org/d-eyes/server/internal/alerts"
	"github.com/m-sec-org/d-eyes/server/internal/api"
	v1 "github.com/m-sec-org/d-eyes/server/internal/api/v1"
	"github.com/m-sec-org/d-eyes/server/internal/artifacts"
	"github.com/m-sec-org/d-eyes/server/internal/audit"
	"github.com/m-sec-org/d-eyes/server/internal/auditlog"
	"github.com/m-sec-org/d-eyes/server/internal/basscenarios"
	"github.com/m-sec-org/d-eyes/server/internal/behavior"
	"github.com/m-sec-org/d-eyes/server/internal/certmanager"
	"github.com/m-sec-org/d-eyes/server/internal/collectorctrl"
	"github.com/m-sec-org/d-eyes/server/internal/config"
	"github.com/m-sec-org/d-eyes/server/internal/eventing"
	"github.com/m-sec-org/d-eyes/server/internal/grpcsvc"
	"github.com/m-sec-org/d-eyes/server/internal/logger"
	"github.com/m-sec-org/d-eyes/server/internal/metrics"
	"github.com/m-sec-org/d-eyes/server/internal/monitor"
	"github.com/m-sec-org/d-eyes/server/internal/playbook"
	"github.com/m-sec-org/d-eyes/server/internal/plugins"
	"github.com/m-sec-org/d-eyes/server/internal/queueprovider"
	"github.com/m-sec-org/d-eyes/server/internal/rbac"
	"github.com/m-sec-org/d-eyes/server/internal/reporttemplates"
	"github.com/m-sec-org/d-eyes/server/internal/scheduler"
	"github.com/m-sec-org/d-eyes/server/internal/security"
	"github.com/m-sec-org/d-eyes/server/internal/store"
	"github.com/m-sec-org/d-eyes/server/internal/storeprovider"
	"github.com/m-sec-org/d-eyes/server/internal/streams"
	"github.com/m-sec-org/d-eyes/server/internal/taskcatalog"
	"github.com/m-sec-org/d-eyes/server/internal/templates"
	"github.com/m-sec-org/d-eyes/server/internal/threatintel"
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
	selfHealStop := sched.StartSelfHeal(ctx, log)
	defer selfHealStop()

	reg := prometheus.NewRegistry()
	metricsCollector := metrics.New(reg)
	sched.SetMetrics(metricsCollector)
	metricsHandler := metrics.Handler(reg)

	eventService := eventing.NewService(cfg.Events, st, metricsCollector, log)
	if eventService != nil {
		defer eventService.Close()
	}
	parserRegistry, err := eventing.NewParserRegistry(cfg.Events, metricsCollector, log)
	if err != nil {
		return fmt.Errorf("init parser registry: %w", err)
	}
	collectorHub := collectorctrl.NewHub()
	defer collectorHub.Close()

	auditLogManager, err := auditlog.New(cfg.Audit.StorePath, 2000)
	if err != nil {
		return fmt.Errorf("init audit log manager: %w", err)
	}

	tiOrchestrator := threatintel.New(st, cfg.ThreatIntel, log, metricsCollector, auditLogManager)
	if tiOrchestrator.Enabled() {
		tiOrchestrator.Start(ctx)
		defer tiOrchestrator.Stop()
	}

	behaviorHub := behavior.NewHub()
	defer behaviorHub.Close()
	behaviorRecorder, err := behavior.NewRecorder(cfg.Behavior, cfg.Redis, log)
	if err != nil {
		return fmt.Errorf("init behavior recorder: %w", err)
	}
	behaviorAnalyzer := behavior.NewAnalyzer(cfg.Behavior, st, log, behaviorHub)
	behaviorGraph, err := behavior.NewGraphService(cfg.Behavior, cfg.Redis, st, behaviorHub, log)
	if err != nil {
		return fmt.Errorf("init behavior graph: %w", err)
	}
	if behaviorGraph != nil {
		behaviorGraph.Start(ctx)
		defer behaviorGraph.Stop()
	}

	if cfg.Audit.Enabled && cfg.Audit.LogPath != "" {
		auditLogger, err := audit.NewLogger(cfg.Audit.LogPath)
		if err != nil {
			return fmt.Errorf("init audit logger: %w", err)
		}
		sched.SetAudit(auditLogger)
	}
	var notifier alerts.Notifier = alerts.NopNotifier{}
	if cfg.Alerts.Enabled {
		notifier = alerts.NewLoggerNotifier(log, true, cfg.Alerts.NotifyBASFailure, cfg.Alerts.NotifyFallback)
	}
	sched.SetAlerts(notifier)

	templateManager, err := templates.NewManager(templates.Config{PersistPath: cfg.Templates.PersistPath}, st, sched, log)
	if err != nil {
		return fmt.Errorf("init template manager: %w", err)
	}
	defer templateManager.Close()

	reportTemplateManager, err := reporttemplates.New(cfg.Reports.TemplatePath, log)
	if err != nil {
		return fmt.Errorf("init report templates: %w", err)
	}

	basScenarioManager, err := basscenarios.NewManager(basscenarios.Config{
		Store:             st,
		DefaultBoundaries: cfg.BAS.DefaultNetworkBoundaries,
		DefaultResourceLimits: basscenarios.ResourceLimits{
			MaxTargets:        cfg.BAS.DefaultResourceLimits.MaxTargets,
			MaxParallelSteps:  cfg.BAS.DefaultResourceLimits.MaxParallelSteps,
			MaxDurationMinute: cfg.BAS.DefaultResourceLimits.MaxDurationMinutes,
			MaxCPUPercent:     cfg.BAS.DefaultResourceLimits.MaxCPUPercent,
		},
		DefaultExecutionPlan: basscenarios.ExecutionPlan{
			Mode:               cfg.BAS.DefaultExecutionPlan.Mode,
			MaxParallel:        cfg.BAS.DefaultExecutionPlan.MaxParallel,
			RetryLimit:         cfg.BAS.DefaultExecutionPlan.RetryLimit,
			StepTimeoutSeconds: cfg.BAS.DefaultExecutionPlan.StepTimeoutSeconds,
			CrossAgent:         cfg.BAS.DefaultExecutionPlan.CrossAgent,
		},
		DefaultApprovalPolicy: basApprovalRulesFromConfig(cfg.BAS.DefaultApprovalPolicy),
		CacheTTL:              cfg.BAS.CacheTTL,
	}, log)
	if err != nil {
		return fmt.Errorf("init bas scenario manager: %w", err)
	}

	taskStream := streams.NewTaskHub()
	sched.SetTaskHub(taskStream)
	taskStreamHandler := streams.SSEHandler(taskStream)
	defer taskStream.Close()

	queueStream := streams.NewTaskHub()
	sched.SetQueueHub(queueStream)
	queueStreamHandler := streams.SSEHandler(queueStream)
	defer queueStream.Close()

	detectionStream := streams.NewTaskHub()
	detectionStreamHandler := streams.SSEHandler(detectionStream)
	defer detectionStream.Close()

	var detectionEngine *eventing.DetectionEngine
	if eventService != nil {
		detectionEngine = eventing.NewDetectionEngine(cfg.Events, st, sched, tiOrchestrator, log, metricsCollector, detectionStream)
		if detectionEngine != nil {
			eventService.RegisterConsumer(detectionEngine)
			defer detectionEngine.Close()
		}
	}

	taskCatalogManager, err := taskcatalog.NewManager(taskcatalog.Config{PersistPath: cfg.TaskCatalog.PersistPath}, log)
	if err != nil {
		return fmt.Errorf("init task catalog: %w", err)
	}
	if seeded, err := taskCatalogManager.ImportSeedIfEmpty(ctx, taskcatalog.BuiltInSeed()); err != nil {
		return fmt.Errorf("seed task catalog: %w", err)
	} else if seeded {
		log.Info("task catalog seeded", "persist_path", cfg.TaskCatalog.PersistPath)
	}

	rbacPolicies := make([]rbac.Policy, 0, len(cfg.RBAC.Policies))
	for _, p := range cfg.RBAC.Policies {
		rbacPolicies = append(rbacPolicies, rbac.Policy{Role: p.Role, Permissions: p.Permissions})
	}
	rbacEnforcer := rbac.New(rbacPolicies)

	taskHandler := &v1.TaskHandler{
		Store:        st,
		Sched:        sched,
		Catalog:      taskCatalogManager,
		BASScenarios: basScenarioManager,
		RBAC:         rbacEnforcer,
		Audit:        auditLogManager,
	}
	templateHandler := &v1.TemplateHandler{Manager: templateManager}
	taskViewHandler := &v1.TaskViewHandler{Store: st, RBAC: rbacEnforcer}
	reportHandler := &v1.ReportHandler{Store: st, Templates: reportTemplateManager, Audit: auditLogManager, RBAC: rbacEnforcer}
	catalogHandler := &v1.TaskCatalogHandler{Catalog: taskCatalogManager}
	pluginManager := plugins.NewManager()
	pluginStream := streams.NewTaskHub()
	defer pluginStream.Close()
	pluginManager.UseHook(func(evt plugins.Event) {
		if pluginStream == nil {
			return
		}
		meta := map[string]string{
			"version": evt.Manifest.Version,
		}
		if evt.Reason != "" {
			meta["reason"] = evt.Reason
		}
		pluginStream.Publish(streams.TaskEvent{
			Event:    "plugin." + evt.Type,
			TaskID:   evt.Manifest.Name,
			Message:  evt.Reason,
			Metadata: meta,
		})
	})
	basHandler := &v1.BASScenarioHandler{Manager: basScenarioManager, RBAC: rbacEnforcer, Audit: auditLogManager}
	agentHandler := &v1.AgentHandler{Store: st, RBAC: rbacEnforcer}
	auditHandler := &v1.AuditHandler{Logs: auditLogManager}
	rbacHandler := &v1.RBACHandler{Enforcer: rbacEnforcer}
	artifactManager, err := artifacts.NewManager(cfg.Artifact)
	if err != nil {
		return fmt.Errorf("init artifact manager: %w", err)
	}
	artifactHandler := &v1.ArtifactHandler{Manager: artifactManager}
	threatIntelHandler := &v1.ThreatIntelHandler{Store: st, Orchestrator: tiOrchestrator, Audit: auditLogManager}
	behaviorHandler := &v1.BehaviorHandler{Store: st}
	complianceHandler := &v1.ComplianceHandler{Store: st}
	threatStreamHandler := threatintel.SSEHandler(tiOrchestrator.Hub())
	anomalyStreamHandler := behavior.SSEHandler(behaviorHub)
	playbookManager := playbook.NewManager(st, log)
	playbookEngine := playbook.NewEngine(cfg.Playbook, playbookManager, st, sched, log, taskStream, behaviorHub, tiOrchestrator.Hub())
	if playbookEngine != nil {
		playbookEngine.Start(ctx)
		defer playbookEngine.Stop()
	}
	playbookHandler := &v1.PlaybookHandler{Manager: playbookManager, Engine: playbookEngine, RBAC: rbacEnforcer}
	pluginHandler := &v1.PluginHandler{Manager: pluginManager, Stream: pluginStream}
	mfaStore := security.NewMFAStore(cfg.Security.MFA)
	certManager, err := certmanager.New(cfg.Security.PKI, log)
	if err != nil {
		return fmt.Errorf("init cert manager: %w", err)
	}
	securityHandler := &v1.SecurityHandler{MFAStore: mfaStore}
	opsHandler := &v1.OpsHandler{Scheduler: sched}
	queueHandler := &v1.QueueHandler{Scheduler: sched, RBAC: rbacEnforcer}
	collectorHandler := &v1.CollectorHandler{
		Store:            st,
		Hub:              collectorHub,
		RBAC:             rbacEnforcer,
		Audit:            auditLogManager,
		Metrics:          metricsCollector,
		AllowedProviders: cfg.Collectors.AllowedProviders,
		AllowedProbes:    cfg.Collectors.AllowedProbes,
		Control:          cfg.Collectors,
	}
	eventsHandler := &v1.EventsHandler{
		Service: eventService,
		Store:   st,
		Config:  cfg.Events,
		RBAC:    rbacEnforcer,
		Parsers: parserRegistry,
		Metrics: metricsCollector,
	}

	router := api.NewRouter(
		cfg,
		taskHandler,
		taskViewHandler,
		templateHandler,
		reportHandler,
		catalogHandler,
		pluginHandler,
		basHandler,
		agentHandler,
		auditHandler,
		rbacHandler,
		artifactHandler,
		threatIntelHandler,
		behaviorHandler,
		complianceHandler,
		playbookHandler,
		&v1.CertHandler{Manager: certManager},
		securityHandler,
		opsHandler,
		queueHandler,
		collectorHandler,
		eventsHandler,
		mfaStore,
		metricsHandler,
		taskStreamHandler,
		queueStreamHandler,
		detectionStreamHandler,
		threatStreamHandler,
		anomalyStreamHandler,
	)

	var tlsConfig *tls.Config
	if certManager != nil {
		tlsConfig = certManager.TLSConfig()
	} else if cfg.Server.TLS.Enabled {
		cert, err := tls.LoadX509KeyPair(cfg.Server.TLS.CertFile, cfg.Server.TLS.KeyFile)
		if err != nil {
			return fmt.Errorf("load tls cert: %w", err)
		}
		tlsConfig = &tls.Config{Certificates: []tls.Certificate{cert}}
	}

	grpcServer, err := newGRPCServer(cfg, st, sched, log, metricsCollector, artifactManager, tiOrchestrator, behaviorRecorder, behaviorAnalyzer, behaviorGraph, tlsConfig)
	if err != nil {
		return err
	}

	httpSrv := &http.Server{Addr: cfg.Server.HTTPAddr, Handler: router, TLSConfig: tlsConfig}

	go func() {
		log.Info("http server listening", "addr", cfg.Server.HTTPAddr, "tls", tlsConfig != nil)
		var err error
		if tlsConfig != nil {
			err = httpSrv.ListenAndServeTLS("", "")
		} else {
			err = httpSrv.ListenAndServe()
		}
		if err != nil && err != http.ErrServerClosed {
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
	taskStream.Close()
	return nil
}

func newGRPCServer(cfg config.Config, st store.Store, sched *scheduler.Scheduler, log *slog.Logger, metricsCollector *metrics.Metrics, artifactManager *artifacts.Manager, ti *threatintel.Orchestrator, behaviorRecorder *behavior.Recorder, behaviorAnalyzer *behavior.Analyzer, behaviorGraph *behavior.GraphService, tlsConfig *tls.Config) (*grpc.Server, error) {
	var serverOpts []grpc.ServerOption
	if tlsConfig != nil {
		serverOpts = append(serverOpts, grpc.Creds(credentials.NewTLS(tlsConfig)))
	} else if cfg.Server.TLS.Enabled {
		creds, err := credentials.NewServerTLSFromFile(cfg.Server.TLS.CertFile, cfg.Server.TLS.KeyFile)
		if err != nil {
			return nil, fmt.Errorf("load tls cert: %w", err)
		}
		serverOpts = append(serverOpts, grpc.Creds(creds))
	}
	grpcServer := grpc.NewServer(serverOpts...)
	svc := grpcsvc.NewService(cfg, st, sched, log, metricsCollector, artifactManager, ti, behaviorRecorder, behaviorAnalyzer, behaviorGraph)
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

func basApprovalRulesFromConfig(rules []config.BASApprovalRule) []basscenarios.ApprovalRule {
	if len(rules) == 0 {
		return nil
	}
	result := make([]basscenarios.ApprovalRule, 0, len(rules))
	for _, rule := range rules {
		result = append(result, basscenarios.ApprovalRule{
			Role:           rule.Role,
			TimeoutSeconds: rule.TimeoutSeconds,
		})
	}
	return result
}
