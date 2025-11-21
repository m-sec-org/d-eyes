package pluginmanifest

import (
	crypto "crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestValidateAndVerifyManifest(t *testing.T) {
	pub, priv, err := crypto.GenerateKey(rand.Reader)
	require.NoError(t, err)

	now := time.Now().UTC()
	m := Manifest{
		APIVersion:      SupportedAPIVersion,
		Name:            "respond-risk-score",
		Version:         "1.2.3",
		Description:     "detect/respond risk scoring plugin",
		Entry:           "./plugin.so",
		ArtifactDigest:  "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		MinAgentVersion: "1.0.0",
		SignedAt:        &now,
		Tasks: []Task{
			{Name: "respond-risk-score", Kind: "respond", Capabilities: []string{"scan", "ti"}},
		},
		Targets: []Target{{OS: "linux", Arch: "amd64"}},
		Resources: ResourceLimits{
			CPU:     "500m",
			Memory:  "256Mi",
			Timeout: "5m",
		},
		Metadata:          map[string]string{"vendor": "m-sec", "support": "oss"},
		TrustedPublishers: []string{"m-sec"},
	}
	payload, err := m.SigningBytes()
	require.NoError(t, err)
	sig := crypto.Sign(priv, payload)
	m.Signature = Signature{
		Algorithm: "ed25519",
		PublicKey: base64.StdEncoding.EncodeToString(pub),
		Value:     base64.StdEncoding.EncodeToString(sig),
	}

	require.NoError(t, ValidateWithSignature(m))
}

func TestParseManifestFromReader(t *testing.T) {
	pub, priv, err := crypto.GenerateKey(rand.Reader)
	require.NoError(t, err)

	manifestYAML := `
apiVersion: v1
name: bas-sandbox-checker
version: 0.5.0
entry: ./plugin.so
artifactDigest: bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb
tasks:
  - name: bas-sandbox-checker
    kind: bas
signature:
  algorithm: ed25519
  publicKey: %s
  value: %s
`
	digest := "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	m := Manifest{
		APIVersion:     SupportedAPIVersion,
		Name:           "bas-sandbox-checker",
		Version:        "0.5.0",
		Entry:          "./plugin.so",
		ArtifactDigest: digest,
		Tasks:          []Task{{Name: "bas-sandbox-checker", Kind: "bas"}},
	}
	payload, err := m.SigningBytes()
	require.NoError(t, err)
	sig := crypto.Sign(priv, payload)

	data := []byte(
		fmt.Sprintf(manifestYAML,
			base64.StdEncoding.EncodeToString(pub),
			base64.StdEncoding.EncodeToString(sig),
		),
	)
	got, err := ParseManifest(data)
	require.NoError(t, err)
	require.Equal(t, m.Name, got.Name)
}

func TestValidateRejectsBadVersionAndDigest(t *testing.T) {
	m := Manifest{
		APIVersion:     SupportedAPIVersion,
		Name:           "bad",
		Version:        "not-semver",
		Entry:          "./plugin.so",
		ArtifactDigest: "short",
		Tasks:          []Task{{Name: "bad", Kind: "respond"}},
		Signature: Signature{
			Algorithm: "ed25519",
			PublicKey: base64.StdEncoding.EncodeToString(make([]byte, crypto.PublicKeySize)),
			Value:     base64.StdEncoding.EncodeToString(make([]byte, crypto.SignatureSize)),
		},
	}
	err := Validate(m)
	require.Error(t, err)
}
