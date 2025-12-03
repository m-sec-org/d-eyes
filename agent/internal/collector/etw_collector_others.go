//go:build !windows

package collector

import "fmt"

func newETWCollector(cfg Config) (EventCollector, error) {
	return nil, fmt.Errorf("etw collector %q is not supported on this platform", cfg.Name)
}
