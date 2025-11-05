package rules

import (
	"embed"
	"fmt"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/m-sec-org/d-eyes/agent/internal/benchmark/engine"
)

//go:embed builtin/**/*.yaml
var builtinFS embed.FS

type ruleFile struct {
	Rules []engine.Rule `yaml:"rules"`
}

// LoadOSRules loads operating system rules for the given platform (linux/windows).
func LoadOSRules(platform string) ([]engine.Rule, error) {
	platform = strings.ToLower(platform)
	switch platform {
	case "linux":
		return loadRules("builtin/os/linux.yaml")
	case "windows":
		return loadRules("builtin/os/windows.yaml")
	default:
		return nil, fmt.Errorf("unsupported platform %s", platform)
	}
}

// LoadDatabaseRules loads database baseline rules.
func LoadDatabaseRules() ([]engine.Rule, error) {
	files := []string{
		"builtin/database/mysql.yaml",
		"builtin/database/postgresql.yaml",
		"builtin/database/mongodb.yaml",
		"builtin/database/redis.yaml",
	}
	return loadMultiple(files)
}

// LoadWebRules loads web server baseline rules.
func LoadWebRules() ([]engine.Rule, error) {
	files := []string{
		"builtin/web/apache.yaml",
		"builtin/web/nginx.yaml",
		"builtin/web/iis.yaml",
	}
	return loadMultiple(files)
}

// LoadAppServerRules loads application server baseline rules.
func LoadAppServerRules() ([]engine.Rule, error) {
	files := []string{
		"builtin/app/tomcat.yaml",
		"builtin/app/weblogic.yaml",
		"builtin/app/jboss.yaml",
	}
	return loadMultiple(files)
}

func loadMultiple(paths []string) ([]engine.Rule, error) {
	aggregated := make([]engine.Rule, 0)
	for _, p := range paths {
		rules, err := loadRules(p)
		if err != nil {
			return nil, err
		}
		aggregated = append(aggregated, rules...)
	}
	return aggregated, nil
}

func loadRules(path string) ([]engine.Rule, error) {
	data, err := builtinFS.ReadFile(filepath.ToSlash(path))
	if err != nil {
		return nil, fmt.Errorf("load rules %s: %w", path, err)
	}
	var rf ruleFile
	if err := yaml.Unmarshal(data, &rf); err != nil {
		return nil, fmt.Errorf("parse rules %s: %w", path, err)
	}
	return rf.Rules, nil
}
