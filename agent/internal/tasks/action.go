package tasks

import "context"

type actionRunner struct{}

// ActionTaskRunner 返回 action 命令的占位实现。
func ActionTaskRunner() TaskRunner {
	return &actionRunner{}
}

func (a *actionRunner) Run(ctx context.Context, req TaskRequest) (TaskResult, error) {
	return newStubRunner("action").Run(ctx, req)
}
