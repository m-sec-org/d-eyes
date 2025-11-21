package agent

import (
	"context"
	"sync"

	internal "github.com/m-sec-org/d-eyes/agent/internal"
	"github.com/m-sec-org/d-eyes/agent/internal/tasks"
)

type customRunnerFactory struct {
	base      internal.RunnerFactory
	respond   tasks.TaskRunner
	audit     tasks.TaskRunner
	inventory tasks.TaskRunner
	supply    tasks.TaskRunner
	baseline  tasks.TaskRunner
	bas       tasks.TaskRunner
	action    tasks.TaskRunner
}

func (f customRunnerFactory) fallback() internal.RunnerFactory {
	if f.base != nil {
		return f.base
	}
	return internal.DefaultRunnerFactory()
}

func (f customRunnerFactory) RespondRunner() tasks.TaskRunner {
	if f.respond != nil {
		return f.respond
	}
	return f.fallback().RespondRunner()
}

func (f customRunnerFactory) AuditRunner() tasks.TaskRunner {
	if f.audit != nil {
		return f.audit
	}
	return f.fallback().AuditRunner()
}

func (f customRunnerFactory) InventoryRunner() tasks.TaskRunner {
	if f.inventory != nil {
		return f.inventory
	}
	return f.fallback().InventoryRunner()
}

func (f customRunnerFactory) SupplyChainRunner() tasks.TaskRunner {
	if f.supply != nil {
		return f.supply
	}
	return f.fallback().SupplyChainRunner()
}

func (f customRunnerFactory) BaselineRunner() tasks.TaskRunner {
	if f.baseline != nil {
		return f.baseline
	}
	return f.fallback().BaselineRunner()
}

func (f customRunnerFactory) BASRunner() tasks.TaskRunner {
	if f.bas != nil {
		return f.bas
	}
	return f.fallback().BASRunner()
}

func (f customRunnerFactory) ActionRunner() tasks.TaskRunner {
	if f.action != nil {
		return f.action
	}
	return f.fallback().ActionRunner()
}

type countingRunner struct {
	mu    sync.Mutex
	calls int
}

func (c *countingRunner) Run(ctx context.Context, req tasks.TaskRequest) (tasks.TaskResult, error) {
	c.mu.Lock()
	c.calls++
	c.mu.Unlock()
	return tasks.TaskResult{}, nil
}

func (c *countingRunner) Calls() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.calls
}
