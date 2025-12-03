package agent

import (
	"context"
	"testing"

	"github.com/m-sec-org/d-eyes/agent/internal/collector"
)

func TestCollectorMetadataIncluded(t *testing.T) {
	ctrl := &fakeCollectorController{
		statuses: []collector.CollectorStatus{{
			Name:  "etw-test",
			Kind:  collector.KindETW,
			State: "running",
		}},
	}
	runner := &remoteRunner{
		collectorFactory: func(configs []collector.Config) collectorController {
			return ctrl
		},
		collectorHandler: collector.EventHandlerFunc(func(context.Context, *collector.SystemEvent) error { return nil }),
	}
	runner.updateCollectorConfigs([]collector.Config{{Name: "etw-test", Kind: collector.KindETW}})
	if err := runner.startCollectors(context.Background()); err != nil {
		t.Fatalf("start collectors: %v", err)
	}
	stats := runner.collectHeartbeatMetadata()
	if stats["collector.etw-test.state"] != "running" {
		t.Fatalf("expected collector state in metadata, got %v", stats["collector.etw-test.state"])
	}
	if stats["collectors.enabled"] != "1" {
		t.Fatalf("expected collectors.enabled=1, got %v", stats["collectors.enabled"])
	}
}

func TestCollectorReconfigureRestartsService(t *testing.T) {
	ctrl1 := &fakeCollectorController{}
	ctrl2 := &fakeCollectorController{}
	factory := &sequenceCollectorFactory{controllers: []collectorController{ctrl1, ctrl2}}
	runner := &remoteRunner{
		collectorFactory: factory.Next,
		collectorHandler: collector.EventHandlerFunc(func(context.Context, *collector.SystemEvent) error { return nil }),
	}
	cfg := []collector.Config{{Name: "etw-test", Kind: collector.KindETW}}
	runner.updateCollectorConfigs(cfg)
	if err := runner.startCollectors(context.Background()); err != nil {
		t.Fatalf("start collectors: %v", err)
	}
	if ctrl1.startCount != 1 {
		t.Fatalf("expected first controller to start once, got %d", ctrl1.startCount)
	}
	runner.updateCollectorConfigs(cfg)
	if ctrl1.stopCount == 0 {
		t.Fatalf("expected first controller to stop on reload")
	}
	if ctrl2.startCount != 1 {
		t.Fatalf("expected second controller to start after reload, got %d", ctrl2.startCount)
	}
}

type fakeCollectorController struct {
	startCount int
	stopCount  int
	statuses   []collector.CollectorStatus
	startErr   error
}

func (f *fakeCollectorController) Start(context.Context, collector.EventHandler) error {
	f.startCount++
	return f.startErr
}

func (f *fakeCollectorController) Stop(context.Context) error {
	f.stopCount++
	return nil
}

func (f *fakeCollectorController) Status() []collector.CollectorStatus {
	return f.statuses
}

type sequenceCollectorFactory struct {
	controllers []collectorController
	index       int
}

func (s *sequenceCollectorFactory) Next(configs []collector.Config) collectorController {
	if len(configs) == 0 {
		return nil
	}
	if s.index >= len(s.controllers) {
		return nil
	}
	ctrl := s.controllers[s.index]
	s.index++
	return ctrl
}
