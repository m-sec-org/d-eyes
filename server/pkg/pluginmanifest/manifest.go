package pluginmanifest

import (
	crypto "crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"
	"time"

	"github.com/hashicorp/go-version"
	"gopkg.in/yaml.v3"
)

// SupportedAPIVersion is the only manifest apiVersion accepted by the platform today.
const SupportedAPIVersion = "v1"

// Manifest defines the metadata and security envelope for a plugin package.
type Manifest struct {
	APIVersion        string            `yaml:"apiVersion" json:"apiVersion"`
	Name              string            `yaml:"name" json:"name"`
	Version           string            `yaml:"version" json:"version"`
	Description       string            `yaml:"description,omitempty" json:"description,omitempty"`
	Entry             string            `yaml:"entry" json:"entry"`
	ArtifactDigest    string            `yaml:"artifactDigest" json:"artifactDigest"` // sha256 of the plugin bundle
	MinAgentVersion   string            `yaml:"minAgentVersion,omitempty" json:"minAgentVersion,omitempty"`
	MaxAgentVersion   string            `yaml:"maxAgentVersion,omitempty" json:"maxAgentVersion,omitempty"`
	SignedAt          *time.Time        `yaml:"signedAt,omitempty" json:"signedAt,omitempty"`
	Tasks             []Task            `yaml:"tasks" json:"tasks"`
	Targets           []Target          `yaml:"targets,omitempty" json:"targets,omitempty"`
	Resources         ResourceLimits    `yaml:"resources,omitempty" json:"resources,omitempty"`
	Metadata          map[string]string `yaml:"metadata,omitempty" json:"metadata,omitempty"`
	Signature         Signature         `yaml:"signature" json:"signature"`
	TrustedPublishers []string          `yaml:"trustedPublishers,omitempty" json:"trustedPublishers,omitempty"`
}

// Task declares which task types a plugin adds or extends.
type Task struct {
	Name         string   `yaml:"name" json:"name"`
	Kind         string   `yaml:"kind" json:"kind"` // respond | baseline | inventory | supplychain | bas | action | audit
	Entry        string   `yaml:"entry,omitempty" json:"entry,omitempty"`
	Capabilities []string `yaml:"capabilities,omitempty" json:"capabilities,omitempty"`
}

// Target narrows where a plugin may run.
type Target struct {
	OS   string `yaml:"os" json:"os"`     // linux | windows | darwin
	Arch string `yaml:"arch" json:"arch"` // amd64 | arm64 | 386
}

// ResourceLimits hints the scheduler/Agent about resource budgets.
type ResourceLimits struct {
	CPU     string `yaml:"cpu,omitempty" json:"cpu,omitempty"`         // e.g. "500m"
	Memory  string `yaml:"memory,omitempty" json:"memory,omitempty"`   // e.g. "256Mi"
	Timeout string `yaml:"timeout,omitempty" json:"timeout,omitempty"` // e.g. "5m"
}

// Signature holds the signing material for a manifest.
type Signature struct {
	Algorithm string `yaml:"algorithm" json:"algorithm"` // ed25519
	KeyID     string `yaml:"keyID,omitempty" json:"keyID,omitempty"`
	PublicKey string `yaml:"publicKey" json:"publicKey"` // base64
	Value     string `yaml:"value" json:"value"`         // base64 signature over SigningBytes
}

// ParseManifestFromReader decodes YAML into a Manifest without applying validation.
func ParseManifestFromReader(r io.Reader) (Manifest, error) {
	dec := yaml.NewDecoder(r)
	dec.KnownFields(true)
	var m Manifest
	if err := dec.Decode(&m); err != nil {
		return Manifest{}, err
	}
	return m, nil
}

// ParseManifest parses YAML bytes then validates structure and signature.
func ParseManifest(data []byte) (Manifest, error) {
	m, err := ParseManifestFromReader(strings.NewReader(string(data)))
	if err != nil {
		return Manifest{}, err
	}
	if err := ValidateWithSignature(m); err != nil {
		return Manifest{}, err
	}
	return m, nil
}

// ValidateWithSignature performs structural validation and signature verification.
func ValidateWithSignature(m Manifest) error {
	if err := Validate(m); err != nil {
		return err
	}
	return VerifySignature(m)
}

// Validate checks manifest fields without verifying the cryptographic signature.
func Validate(m Manifest) error {
	if strings.TrimSpace(m.APIVersion) != SupportedAPIVersion {
		return fmt.Errorf("unsupported apiVersion: %s", m.APIVersion)
	}
	if strings.TrimSpace(m.Name) == "" {
		return errors.New("name is required")
	}
	if _, err := version.NewVersion(m.Version); err != nil {
		return fmt.Errorf("version must be semver: %w", err)
	}
	if strings.TrimSpace(m.Entry) == "" {
		return errors.New("entry is required")
	}
	if err := validateDigest(m.ArtifactDigest); err != nil {
		return err
	}
	if err := validateVersionConstraint(m.MinAgentVersion, "minAgentVersion"); err != nil {
		return err
	}
	if err := validateVersionConstraint(m.MaxAgentVersion, "maxAgentVersion"); err != nil {
		return err
	}
	if len(m.Tasks) == 0 {
		return errors.New("at least one task is required")
	}
	if err := validateTasks(m.Tasks); err != nil {
		return err
	}
	if err := validateTargets(m.Targets); err != nil {
		return err
	}
	if err := validateResources(m.Resources); err != nil {
		return err
	}
	if m.Signature.Algorithm == "" || m.Signature.PublicKey == "" || m.Signature.Value == "" {
		return errors.New("signature, algorithm, and publicKey are required")
	}
	return nil
}

// VerifySignature checks the manifest signature using ed25519 over the canonical payload.
func VerifySignature(m Manifest) error {
	if strings.ToLower(m.Signature.Algorithm) != "ed25519" {
		return fmt.Errorf("unsupported signature algorithm: %s", m.Signature.Algorithm)
	}
	pubKey, sig, err := decodeSignature(m.Signature)
	if err != nil {
		return err
	}
	payload, err := m.SigningBytes()
	if err != nil {
		return err
	}
	if !crypto.Verify(pubKey, payload, sig) {
		return errors.New("manifest signature verification failed")
	}
	return nil
}

// SigningBytes marshals the canonical subset of manifest fields used for signing.
func (m Manifest) SigningBytes() ([]byte, error) {
	type metadataEntry struct {
		Key   string `json:"key"`
		Value string `json:"value"`
	}
	meta := make([]metadataEntry, 0, len(m.Metadata))
	for k, v := range m.Metadata {
		meta = append(meta, metadataEntry{Key: k, Value: v})
	}
	sort.Slice(meta, func(i, j int) bool { return meta[i].Key < meta[j].Key })

	envelope := struct {
		APIVersion        string          `json:"apiVersion"`
		Name              string          `json:"name"`
		Version           string          `json:"version"`
		Entry             string          `json:"entry"`
		ArtifactDigest    string          `json:"artifactDigest"`
		MinAgentVersion   string          `json:"minAgentVersion,omitempty"`
		MaxAgentVersion   string          `json:"maxAgentVersion,omitempty"`
		SignedAt          *time.Time      `json:"signedAt,omitempty"`
		Tasks             []Task          `json:"tasks,omitempty"`
		Targets           []Target        `json:"targets,omitempty"`
		Resources         ResourceLimits  `json:"resources,omitempty"`
		Metadata          []metadataEntry `json:"metadata,omitempty"`
		TrustedPublishers []string        `json:"trustedPublishers,omitempty"`
	}{
		APIVersion:        m.APIVersion,
		Name:              m.Name,
		Version:           m.Version,
		Entry:             m.Entry,
		ArtifactDigest:    m.ArtifactDigest,
		MinAgentVersion:   m.MinAgentVersion,
		MaxAgentVersion:   m.MaxAgentVersion,
		SignedAt:          m.SignedAt,
		Tasks:             m.Tasks,
		Targets:           m.Targets,
		Resources:         m.Resources,
		Metadata:          meta,
		TrustedPublishers: m.TrustedPublishers,
	}
	return json.Marshal(envelope)
}

func validateVersionConstraint(v, field string) error {
	if strings.TrimSpace(v) == "" {
		return nil
	}
	if _, err := version.NewVersion(v); err != nil {
		return fmt.Errorf("%s must be semver: %w", field, err)
	}
	return nil
}

func validateDigest(digest string) error {
	d := strings.TrimSpace(digest)
	if len(d) != 64 {
		return fmt.Errorf("artifactDigest must be hex sha256 (64 chars)")
	}
	if _, err := hex.DecodeString(d); err != nil {
		return fmt.Errorf("artifactDigest must be hex sha256: %w", err)
	}
	return nil
}

func validateTasks(tasks []Task) error {
	allowedKinds := map[string]struct{}{
		"respond":     {},
		"baseline":    {},
		"inventory":   {},
		"supplychain": {},
		"bas":         {},
		"action":      {},
		"audit":       {},
	}
	seen := make(map[string]struct{}, len(tasks))
	for _, t := range tasks {
		if strings.TrimSpace(t.Name) == "" {
			return errors.New("task name is required")
		}
		if _, ok := allowedKinds[strings.ToLower(t.Kind)]; !ok {
			return fmt.Errorf("unsupported task kind: %s", t.Kind)
		}
		if _, dup := seen[t.Name]; dup {
			return fmt.Errorf("duplicate task name: %s", t.Name)
		}
		seen[t.Name] = struct{}{}
	}
	return nil
}

func validateTargets(targets []Target) error {
	if len(targets) == 0 {
		return nil
	}
	validOS := map[string]struct{}{
		"linux":   {},
		"windows": {},
		"darwin":  {},
	}
	validArch := map[string]struct{}{
		"amd64": {},
		"arm64": {},
		"386":   {},
	}
	for _, t := range targets {
		if _, ok := validOS[strings.ToLower(t.OS)]; !ok {
			return fmt.Errorf("unsupported target os: %s", t.OS)
		}
		if _, ok := validArch[strings.ToLower(t.Arch)]; !ok {
			return fmt.Errorf("unsupported target arch: %s", t.Arch)
		}
	}
	return nil
}

func validateResources(r ResourceLimits) error {
	if r.CPU == "" && r.Memory == "" && r.Timeout == "" {
		return nil
	}
	// Loose validation: disallow negative values and whitespace.
	if strings.Contains(r.CPU, "-") {
		return errors.New("cpu resource must not be negative")
	}
	if strings.Contains(r.Memory, "-") {
		return errors.New("memory resource must not be negative")
	}
	if strings.Contains(r.Timeout, "-") {
		return errors.New("timeout must not be negative")
	}
	return nil
}

func decodeSignature(sig Signature) (crypto.PublicKey, []byte, error) {
	pub, err := base64.StdEncoding.DecodeString(sig.PublicKey)
	if err != nil {
		return nil, nil, fmt.Errorf("invalid publicKey: %w", err)
	}
	if len(pub) != crypto.PublicKeySize {
		return nil, nil, fmt.Errorf("publicKey must be %d bytes", crypto.PublicKeySize)
	}
	sigBytes, err := base64.StdEncoding.DecodeString(sig.Value)
	if err != nil {
		return nil, nil, fmt.Errorf("invalid signature: %w", err)
	}
	if len(sigBytes) != crypto.SignatureSize {
		return nil, nil, fmt.Errorf("signature must be %d bytes", crypto.SignatureSize)
	}
	return crypto.PublicKey(pub), sigBytes, nil
}
