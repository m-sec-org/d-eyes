package engine

import (
	"errors"
	"fmt"
	"sync"

	"github.com/m-sec-org/d-eyes/agent/internal/detect/scoring"
)

// ErrUnsupportedFeature indicates that the engine cannot handle a given rule construct.
var ErrUnsupportedFeature = errors.New("unsupported rule feature")

// Match describes the outcome of a single rule against a target payload.
type Match struct {
	RuleName    string
	Description string
	Tags        []string
	FilePath    string
	Strings     []MatchedString
	Metadata    map[string]string
	ScoreHints  scoring.ScoreHints
}

// MatchedString stores matched string identifier and offsets.
type MatchedString struct {
	Identifier string
	Offsets    []int
}

// ScanOptions controls engine run time behaviour.
type ScanOptions struct {
	FilePath string
}

// RuleBundle represents a compiled set of rules.
type RuleBundle interface {
	Name() string
	Version() string
	RuleCount() int
	Scan(data []byte, opt ScanOptions) ([]Match, error)
}

// BundleProvider exposes the current bundle in a thread safe way.
type BundleProvider interface {
	CurrentBundle() (RuleBundle, error)
}

// ThreadSafeProvider wraps a mutable RuleBundle with a mutex.
type ThreadSafeProvider struct {
	mu      sync.RWMutex
	bundle  RuleBundle
	version string
}

// Update replaces the active bundle.
func (p *ThreadSafeProvider) Update(bundle RuleBundle) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.bundle = bundle
	if bundle != nil {
		p.version = bundle.Version()
	} else {
		p.version = ""
	}
}

// CurrentBundle implements BundleProvider.
func (p *ThreadSafeProvider) CurrentBundle() (RuleBundle, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	if p.bundle == nil {
		return nil, fmt.Errorf("rule bundle not initialised")
	}
	return p.bundle, nil
}

// Version returns current bundle version string (best effort).
func (p *ThreadSafeProvider) Version() string {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.version
}
