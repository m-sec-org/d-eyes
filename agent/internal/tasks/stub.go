package tasks

import (
	"context"
	"fmt"
)

type stubRunner struct {
	task string
}

func (s *stubRunner) Run(ctx context.Context, req TaskRequest) (TaskResult, error) {
	note := fmt.Sprintf("任务 %s 暂未实现，敬请期待后续版本。", s.task)
	return TaskResult{
		Notes: []string{note},
	}, ErrNotImplemented
}

func newStubRunner(name string) TaskRunner {
	return &stubRunner{task: name}
}
