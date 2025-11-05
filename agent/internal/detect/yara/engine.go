package yara

import (
	"crypto/sha1"
	"encoding/hex"
	"fmt"
	"path/filepath"
	"strings"

	"github.com/m-sec-org/d-eyes/agent/internal/detect/engine/goengine"
)

// LoadBuiltInRules loads embedded YARA rules from given filesystem (per extension) into goengine.
func LoadBuiltInRules(filenames []string, loader func(string) ([]byte, error)) ([]*goengine.Rule, error) {
	rules := make([]*goengine.Rule, 0, len(filenames))
	for _, name := range filenames {
		data, err := loader(name)
		if err != nil {
			return nil, fmt.Errorf("load rule %s: %w", name, err)
		}
		rule, err := goengine.RuleFromSource(filepath.Base(name), data)
		if err != nil {
			return nil, fmt.Errorf("parse rule %s: %w", name, err)
		}
		rules = append(rules, rule...)
	}
	return rules, nil
}

// HashRuleBundle returns unique hash identifier for rule bundle.
func HashRuleBundle(files map[string][]byte) string {
	h := sha1.New()
	keys := make([]string, 0, len(files))
	for k := range files {
		keys = append(keys, k)
	}
	// ensure deterministic ordering
	// Note: full sort handled by engine when building bundle.
	for _, k := range keys {
		h.Write([]byte(k))
		h.Write(files[k])
	}
	return hex.EncodeToString(h.Sum(nil))
}

// FilterRules limits loaded rules by prefix/tag.
func FilterRules(all []*goengine.Rule, includePrefix, includeTag string) []*goengine.Rule {
	if includePrefix == "" && includeTag == "" {
		return all
	}
	filtered := make([]*goengine.Rule, 0, len(all))
	for _, r := range all {
		if includePrefix != "" && !strings.HasPrefix(r.Name, includePrefix) {
			continue
		}
		if includeTag != "" {
			found := false
			for _, t := range r.Tags {
				if t == includeTag {
					found = true
					break
				}
			}
			if !found {
				continue
			}
		}
		filtered = append(filtered, r)
	}
	return filtered
}
