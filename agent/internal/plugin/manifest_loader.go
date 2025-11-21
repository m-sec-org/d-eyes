package plugin

import (
	"fmt"
	"os"

	pluginmanifest "github.com/m-sec-org/d-eyes/server/pkg/pluginmanifest"
)

// LoadManifestFromPath parses and verifies a plugin manifest file.
func LoadManifestFromPath(path string) (pluginmanifest.Manifest, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return pluginmanifest.Manifest{}, fmt.Errorf("read manifest: %w", err)
	}
	m, err := pluginmanifest.ParseManifest(data)
	if err != nil {
		return pluginmanifest.Manifest{}, fmt.Errorf("invalid manifest: %w", err)
	}
	return m, nil
}

// ValidateManifestBytes allows callers to validate manifest content without touching disk.
func ValidateManifestBytes(data []byte) (pluginmanifest.Manifest, error) {
	m, err := pluginmanifest.ParseManifest(data)
	if err != nil {
		return pluginmanifest.Manifest{}, fmt.Errorf("invalid manifest: %w", err)
	}
	return m, nil
}
