//go:build !linux

package collector

import "fmt"

func newEBPFCollector(cfg Config) (EventCollector, error) {
	return nil, fmt.Errorf("ebpf collector %q is only supported on Linux", cfg.Name)
}
