package fingerprints

import (
	"embed"
	"fmt"
	"sync"

	"gopkg.in/yaml.v3"
)

//go:embed services.yaml os.yaml
var definitionsFS embed.FS

// ServiceFingerprint describes service identification rules.
type ServiceFingerprint struct {
	Name    string           `yaml:"name"`
	Match   ServiceMatch     `yaml:"match"`
	Extract []ServiceExtract `yaml:"extract"`
}

type ServiceMatch struct {
	Protocol string    `yaml:"protocol"`
	Ports    []int     `yaml:"ports"`
	Patterns []Pattern `yaml:"patterns"`
}

type ServiceExtract struct {
	Type string `yaml:"type"`
	Name string `yaml:"name"`
}

type Pattern struct {
	Type  string `yaml:"type"`
	Value string `yaml:"value"`
}

// OSFingerprint describes heuristics used for OS detection.
type OSFingerprint struct {
	OS         string       `yaml:"os"`
	Heuristics OSHeuristics `yaml:"heuristics"`
}

type OSHeuristics struct {
	TTLRange       []int           `yaml:"ttl_range"`
	TCPWindowSizes []int           `yaml:"tcp_window_sizes"`
	TCPOptions     []string        `yaml:"tcp_options"`
	Services       []OSServiceHint `yaml:"services"`
	Banners        []OSBannerHint  `yaml:"banners"`
}

type OSServiceHint struct {
	Port    int    `yaml:"port"`
	Service string `yaml:"service"`
}

type OSBannerHint struct {
	Service  string `yaml:"service"`
	Contains string `yaml:"contains"`
}

var (
	serviceOnce sync.Once
	osOnce      sync.Once

	serviceData []ServiceFingerprint
	serviceErr  error

	osData []OSFingerprint
	osErr  error
)

// LoadServiceFingerprints returns service fingerprints from embedded data.
func LoadServiceFingerprints() ([]ServiceFingerprint, error) {
	serviceOnce.Do(func() {
		data, err := definitionsFS.ReadFile("services.yaml")
		if err != nil {
			serviceErr = fmt.Errorf("load service fingerprints: %w", err)
			return
		}
		var wrapper struct {
			Services []ServiceFingerprint `yaml:"services"`
		}
		if err := yaml.Unmarshal(data, &wrapper); err != nil {
			serviceErr = fmt.Errorf("parse service fingerprints: %w", err)
			return
		}
		serviceData = wrapper.Services
	})
	return serviceData, serviceErr
}

// LoadOSFingerprints returns OS fingerprints.
func LoadOSFingerprints() ([]OSFingerprint, error) {
	osOnce.Do(func() {
		data, err := definitionsFS.ReadFile("os.yaml")
		if err != nil {
			osErr = fmt.Errorf("load os fingerprints: %w", err)
			return
		}
		var wrapper struct {
			Fingerprints []OSFingerprint `yaml:"fingerprints"`
		}
		if err := yaml.Unmarshal(data, &wrapper); err != nil {
			osErr = fmt.Errorf("parse os fingerprints: %w", err)
			return
		}
		osData = wrapper.Fingerprints
	})
	return osData, osErr
}
