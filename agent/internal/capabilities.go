package internal

import (
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"
)

type CapabilityContext struct {
	Platform string
	Labels   map[string]string
}

type CapabilityDefinition struct {
	Name                       string
	Runner                     string
	Platforms                  []string
	RequiredLabels             map[string]string
	ReservedRequiredLabelsOnly bool
}

type CapabilityOption func(*CapabilityDefinition)

func NewCapabilityDefinition(name string, opts ...CapabilityOption) CapabilityDefinition {
	def := CapabilityDefinition{Name: name}
	for _, opt := range opts {
		if opt != nil {
			opt(&def)
		}
	}
	return def
}

func WithRunner(runner string) CapabilityOption {
	return func(def *CapabilityDefinition) {
		if def != nil {
			def.Runner = runner
		}
	}
}

func WithPlatforms(platforms ...string) CapabilityOption {
	return func(def *CapabilityDefinition) {
		if def != nil {
			def.Platforms = append([]string(nil), platforms...)
		}
	}
}

func WithRequiredLabel(key, value string) CapabilityOption {
	return func(def *CapabilityDefinition) {
		if def == nil {
			return
		}
		if def.RequiredLabels == nil {
			def.RequiredLabels = make(map[string]string)
		}
		def.RequiredLabels[key] = value
	}
}

func WithRequiredLabelsReservedKeysOnly() CapabilityOption {
	return func(def *CapabilityDefinition) {
		if def != nil {
			def.ReservedRequiredLabelsOnly = true
		}
	}
}

type CapabilityCatalog struct {
	mu   sync.RWMutex
	defs map[string]CapabilityDefinition
}

func NewCapabilityCatalog() *CapabilityCatalog {
	return &CapabilityCatalog{defs: make(map[string]CapabilityDefinition)}
}

func DefaultCapabilityCatalog() *CapabilityCatalog {
	return defaultCapabilityCatalog
}

func RegisterAdvertisedCapability(def CapabilityDefinition) error {
	return defaultCapabilityCatalog.Register(def)
}

func RegisterAdvertisedCapabilityForTesting(def CapabilityDefinition) func() {
	name := strings.TrimSpace(def.Name)
	if err := RegisterAdvertisedCapability(def); err != nil {
		panic(err)
	}
	return func() {
		defaultCapabilityCatalog.unregister(name)
	}
}

func AdvertisedCapabilities(ctx CapabilityContext) []string {
	return defaultCapabilityCatalog.Advertised(ctx)
}

func (c *CapabilityCatalog) Register(def CapabilityDefinition) error {
	if c == nil {
		return errors.New("capability catalog: nil catalog")
	}
	name := strings.TrimSpace(def.Name)
	if name == "" {
		return errors.New("capability catalog: empty capability name")
	}
	runner := strings.TrimSpace(def.Runner)
	if runner == "" {
		runner = name
	}
	platforms := make([]string, 0, len(def.Platforms))
	seenPlatforms := make(map[string]struct{}, len(def.Platforms))
	for _, platform := range def.Platforms {
		value := strings.ToLower(strings.TrimSpace(platform))
		if value == "" {
			continue
		}
		if _, ok := seenPlatforms[value]; ok {
			continue
		}
		seenPlatforms[value] = struct{}{}
		platforms = append(platforms, value)
	}
	required := make(map[string]string, len(def.RequiredLabels))
	for k, v := range def.RequiredLabels {
		key := strings.TrimSpace(k)
		val := strings.TrimSpace(v)
		if key == "" || val == "" {
			continue
		}
		if def.ReservedRequiredLabelsOnly && !IsReservedLabelKey(key) {
			return fmt.Errorf("capability catalog: required label key %q is not reserved", key)
		}
		required[key] = val
	}

	c.mu.Lock()
	defer c.mu.Unlock()
	if _, ok := c.defs[name]; ok {
		return errors.New("capability catalog: capability already registered")
	}
	c.defs[name] = CapabilityDefinition{
		Name:                       name,
		Runner:                     runner,
		Platforms:                  platforms,
		RequiredLabels:             required,
		ReservedRequiredLabelsOnly: def.ReservedRequiredLabelsOnly,
	}
	return nil
}

func (c *CapabilityCatalog) unregister(name string) {
	if c == nil {
		return
	}
	name = strings.TrimSpace(name)
	if name == "" {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.defs, name)
}

func (c *CapabilityCatalog) Advertised(ctx CapabilityContext) []string {
	if c == nil {
		return nil
	}
	c.mu.RLock()
	defs := make([]CapabilityDefinition, 0, len(c.defs))
	for _, def := range c.defs {
		defs = append(defs, def)
	}
	c.mu.RUnlock()

	platform := strings.ToLower(strings.TrimSpace(ctx.Platform))
	caps := make([]string, 0, len(defs))
	for _, def := range defs {
		if _, ok := TaskRunnerByName(def.Runner); !ok {
			continue
		}
		if len(def.Platforms) > 0 {
			if platform == "" {
				continue
			}
			allowed := false
			for _, allow := range def.Platforms {
				if platform == allow {
					allowed = true
					break
				}
			}
			if !allowed {
				continue
			}
		}
		if len(def.RequiredLabels) > 0 {
			if ctx.Labels == nil {
				continue
			}
			matched := true
			for key, val := range def.RequiredLabels {
				got, ok := ctx.Labels[key]
				if !ok || got != val {
					matched = false
					break
				}
			}
			if !matched {
				continue
			}
		}
		caps = append(caps, def.Name)
	}
	sort.Strings(caps)
	return caps
}

var defaultCapabilityCatalog = func() *CapabilityCatalog {
	catalog := NewCapabilityCatalog()
	for _, def := range defaultCapabilityDefinitions() {
		if err := catalog.Register(def); err != nil {
			panic(err)
		}
	}
	return catalog
}()

func defaultCapabilityDefinitions() []CapabilityDefinition {
	return []CapabilityDefinition{
		NewCapabilityDefinition("respond"),
		NewCapabilityDefinition("audit"),
		NewCapabilityDefinition("inventory"),
		NewCapabilityDefinition("supplychain"),
		NewCapabilityDefinition("baseline"),
		NewCapabilityDefinition("bas"),
		NewCapabilityDefinition(
			"detect.diag",
			WithRunner("detect.diag"),
		),
		NewCapabilityDefinition(
			"detect.memscan",
			WithRunner("detect.memscan"),
			WithPlatforms("windows"),
			WithRequiredLabel(LabelAllowMemscan, LabelValueTrue),
			WithRequiredLabelsReservedKeysOnly(),
		),
		NewCapabilityDefinition("action"),
	}
}
