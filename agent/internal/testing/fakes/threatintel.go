package fakes

import "github.com/m-sec-org/d-eyes/agent/pkg/threatintel"

// ThreatIntelProvider implements tasks.SetThreatIntelProvider contract, returning
// a predefined manager or error.
type ThreatIntelProvider struct {
	Manager *threatintel.Manager
	Err     error
}

func (f ThreatIntelProvider) NewManager(cfg threatintel.Config) (*threatintel.Manager, error) {
	if f.Manager != nil {
		return f.Manager, nil
	}
	if f.Err != nil {
		return nil, f.Err
	}
	return threatintel.NewManager(cfg)
}
