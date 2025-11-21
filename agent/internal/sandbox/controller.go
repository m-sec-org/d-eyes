package sandbox

import (
	"context"
	"sync"
)

// Controller abstracts sandbox execution so callers can inject custom implementations.
type Controller interface {
	Run(ctx context.Context, req RunRequest) (RunResult, error)
}

// ControllerFactory builds sandbox controllers based on Config.
type ControllerFactory interface {
	New(Config) Controller
}

var (
	controllerFactory   ControllerFactory = defaultControllerFactory{}
	controllerFactoryMu sync.RWMutex
)

// SetControllerFactory overrides the global factory; passing nil restores default.
func SetControllerFactory(factory ControllerFactory) {
	controllerFactoryMu.Lock()
	defer controllerFactoryMu.Unlock()
	if factory == nil {
		controllerFactory = defaultControllerFactory{}
	} else {
		controllerFactory = factory
	}
}

func getControllerFactory() ControllerFactory {
	controllerFactoryMu.RLock()
	defer controllerFactoryMu.RUnlock()
	return controllerFactory
}

// NewController builds a controller using the current factory.
func NewController(cfg Config) Controller {
	return getControllerFactory().New(cfg)
}

type defaultControllerFactory struct{}

func (defaultControllerFactory) New(cfg Config) Controller {
	return NewManager(cfg)
}
