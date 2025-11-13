package threatintel

import (
	"context"
	"net/http"
	"time"

	"github.com/m-sec-org/d-eyes/server/internal/model"
)

// ProviderRequest aggregates all context required by a provider.
type ProviderRequest struct {
	Job       *model.ThreatIntelJob
	Sample    *model.ThreatIntelSample
	Artifacts []model.Artifact
}

// Provider fetches verdicts from an external source (OpenTIP, MetaDefender, etc.).
type Provider interface {
	Source() model.ThreatIntelSource
	Process(ctx context.Context, req ProviderRequest) ([]*model.ThreatIntelVerdict, error)
}

// httpDoer abstracts *http.Client for easier testing.
type httpDoer interface {
	Do(req *http.Request) (*http.Response, error)
}

func newHTTPClient(timeout time.Duration) *http.Client {
	if timeout <= 0 {
		timeout = 15 * time.Second
	}
	return &http.Client{Timeout: timeout}
}

func cloneMetadata(m map[string]string) map[string]string {
	if len(m) == 0 {
		return nil
	}
	cp := make(map[string]string, len(m))
	for k, v := range m {
		cp[k] = v
	}
	return cp
}

func mergeMetadata(base map[string]string, extra map[string]string) map[string]string {
	if len(base) == 0 && len(extra) == 0 {
		return nil
	}
	out := make(map[string]string, len(base)+len(extra))
	for k, v := range base {
		out[k] = v
	}
	for k, v := range extra {
		out[k] = v
	}
	return out
}
