package store

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"

	"github.com/m-sec-org/d-eyes/server/internal/model"
)

var ErrNotFound = errors.New("store: not found")

// Store defines the persistence contract required by scheduler and services.
type Store interface {
	UpsertAgent(ctx context.Context, agent *model.Agent) error
	GetAgentByName(ctx context.Context, name string) (*model.Agent, error)
	GetAgent(ctx context.Context, id uuid.UUID) (*model.Agent, error)
	UpdateAgentStatus(ctx context.Context, id uuid.UUID, status model.AgentStatus, heartbeat time.Time, load float64, running []string, metadata map[string]string) error
	UpdateAgentMetadata(ctx context.Context, id uuid.UUID, labels map[string]string) error

	CreateTask(ctx context.Context, task *model.Task) error
	UpdateTaskStatus(ctx context.Context, taskID uuid.UUID, status model.TaskStatus) error
	IncrementTaskRetry(ctx context.Context, taskID uuid.UUID) error
	GetTask(ctx context.Context, id uuid.UUID) (*model.Task, error)
	ListPendingTasks(ctx context.Context, limit int) ([]*model.Task, error)
	ListTasks(ctx context.Context, statuses []model.TaskStatus, limit int) ([]*model.Task, error)
	ListAgents(ctx context.Context) ([]*model.Agent, error)
	Ping(ctx context.Context) error

	CreateTaskRun(ctx context.Context, run *model.TaskRun) error
	UpdateTaskRunStatusByLease(ctx context.Context, leaseID uuid.UUID, status model.TaskStatus) error
	UpdateTaskRunCompletion(ctx context.Context, runID uuid.UUID, status model.TaskStatus, finished time.Time, summary []byte, errMsg string, metadata map[string]string, exitCode int32, errorCode string, expiresAt time.Time) error
	GetTaskRunByLease(ctx context.Context, leaseID uuid.UUID) (*model.TaskRun, error)
	GetLatestTaskRun(ctx context.Context, taskID uuid.UUID) (*model.TaskRun, error)
	ListTaskRunsByAgent(ctx context.Context, agentID uuid.UUID, statuses []model.TaskStatus, limit int) ([]*model.TaskRun, error)

	SaveArtifacts(ctx context.Context, artifacts []model.Artifact) error
	GetArtifacts(ctx context.Context, ids []uuid.UUID) ([]model.Artifact, error)

	InsertTaskResult(ctx context.Context, result *model.TaskResult) error
	ArchiveTaskResults(ctx context.Context, before time.Time) (int, error)
	ListTaskResults(ctx context.Context, taskType model.TaskType, limit int) ([]*model.TaskResult, error)

	// Threat intelligence orchestrator persistence.
	CreateThreatIntelSample(ctx context.Context, sample *model.ThreatIntelSample) error
	UpdateThreatIntelSampleStatus(ctx context.Context, sampleID uuid.UUID, status, lastError string, metadata map[string]string) error
	GetThreatIntelSample(ctx context.Context, sampleID uuid.UUID) (*model.ThreatIntelSample, error)
	ListThreatIntelJobsBySample(ctx context.Context, sampleID uuid.UUID) ([]*model.ThreatIntelJob, error)
	ListThreatIntelJobs(ctx context.Context, limit int) ([]*model.ThreatIntelJob, error)

	InsertThreatIntelJob(ctx context.Context, job *model.ThreatIntelJob) error
	LeaseThreatIntelJobs(ctx context.Context, limit int) ([]*model.ThreatIntelJob, error)
	UpdateThreatIntelJobStatus(ctx context.Context, jobID uuid.UUID, status string, nextRunAt time.Time, errMsg string, metadata map[string]string) error

	InsertThreatIntelVerdict(ctx context.Context, verdict *model.ThreatIntelVerdict) error
	ListThreatIntelVerdicts(ctx context.Context, indicator string, limit int) ([]*model.ThreatIntelVerdict, error)
	CountThreatIntelJobs(ctx context.Context, statuses []string) (int64, error)

	// Behavior telemetry & anomalies.
	SaveBehaviorMetric(ctx context.Context, metric *model.BehaviorMetric) error
	SaveBehaviorEvent(ctx context.Context, event *model.BehaviorEvent) error
	CreateAnomaly(ctx context.Context, anomaly *model.Anomaly) error
	ListAnomalies(ctx context.Context, limit int) ([]*model.Anomaly, error)
	ListAnomaliesByFilter(ctx context.Context, filter model.AnomalyFilter) ([]*model.Anomaly, error)
	GetAnomaly(ctx context.Context, id uuid.UUID) (*model.Anomaly, error)
	SaveAnomalyGraph(ctx context.Context, anomalyID uuid.UUID, nodes []*model.BehaviorGraphNode, edges []*model.BehaviorGraphEdge) error
	GetAnomalyGraph(ctx context.Context, anomalyID uuid.UUID) (*model.AnomalyGraph, error)

	// Playbook automation.
	CreatePlaybook(ctx context.Context, playbook *model.Playbook) error
	UpdatePlaybook(ctx context.Context, playbook *model.Playbook) error
	GetPlaybook(ctx context.Context, id uuid.UUID) (*model.Playbook, error)
	ListPlaybooks(ctx context.Context, limit int) ([]*model.Playbook, error)
	CreatePlaybookRun(ctx context.Context, run *model.PlaybookRun) error
	UpdatePlaybookRun(ctx context.Context, run *model.PlaybookRun) error
	ListPlaybookRuns(ctx context.Context, playbookID uuid.UUID, limit int) ([]*model.PlaybookRun, error)

	// BAS scenario repository.
	CreateBASScenario(ctx context.Context, scenario *model.BASScenario) error
	UpdateBASScenario(ctx context.Context, scenario *model.BASScenario) error
	GetBASScenario(ctx context.Context, id uuid.UUID) (*model.BASScenario, error)
	ListBASScenarios(ctx context.Context) ([]*model.BASScenario, error)
	DeleteBASScenario(ctx context.Context, id uuid.UUID) error

	// Compliance data.
	CreateComplianceFramework(ctx context.Context, framework *model.ComplianceFramework) error
	UpdateComplianceFramework(ctx context.Context, framework *model.ComplianceFramework) error
	ListComplianceFrameworks(ctx context.Context) ([]*model.ComplianceFramework, error)
	CreateComplianceControl(ctx context.Context, control *model.ComplianceControl) error
	UpdateComplianceControl(ctx context.Context, control *model.ComplianceControl) error
	ListComplianceControls(ctx context.Context, frameworkID uuid.UUID) ([]*model.ComplianceControl, error)
	CreateControlMapping(ctx context.Context, mapping *model.ControlMapping) error
	ListControlMappings(ctx context.Context, controlID uuid.UUID) ([]*model.ControlMapping, error)
	CreateComplianceFinding(ctx context.Context, finding *model.ComplianceFinding) error
	UpdateComplianceFinding(ctx context.Context, finding *model.ComplianceFinding) error
	GetComplianceFinding(ctx context.Context, id uuid.UUID) (*model.ComplianceFinding, error)
	ListComplianceFindings(ctx context.Context, frameworkID uuid.UUID, status string) ([]*model.ComplianceFinding, error)
}
