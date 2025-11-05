package fingerprints

import (
	"testing"
)

func TestMatchService(t *testing.T) {
	fps := []ServiceFingerprint{{
		Name: "http",
		Match: ServiceMatch{
			Protocol: "tcp",
			Ports:    []int{80},
			Patterns: []Pattern{{Type: "prefix", Value: "HTTP/1.1"}},
		},
	}}

	res := MatchService(fps, ServiceEvidence{
		Port:     80,
		Protocol: "tcp",
		Banner:   "HTTP/1.1 200 OK",
	})
	if res.Name != "http" {
		t.Fatalf("expected http, got %s", res.Name)
	}
}

func TestMatchServiceTLSCN(t *testing.T) {
	fps := []ServiceFingerprint{{
		Name: "https",
		Match: ServiceMatch{
			Protocol: "tcp",
			Ports:    []int{443},
			Patterns: []Pattern{{Type: "tls_cn", Value: "example\\.com"}},
		},
	}}

	res := MatchService(fps, ServiceEvidence{
		Port:          443,
		Protocol:      "tcp",
		TLSCommonName: "example.com",
	})
	if res.Name != "https" {
		t.Fatalf("expected https, got %s", res.Name)
	}
}

func TestMatchServiceJSONField(t *testing.T) {
	fps := []ServiceFingerprint{{
		Name: "elastic",
		Match: ServiceMatch{
			Protocol: "tcp",
			Patterns: []Pattern{{Type: "json_field", Value: "cluster_name"}},
		},
	}}

	res := MatchService(fps, ServiceEvidence{
		Port:     9200,
		Protocol: "tcp",
		Banner:   `{"cluster_name":"es-dev"}`,
	})
	if res.Name != "elastic" {
		t.Fatalf("expected elastic, got %s", res.Name)
	}
}

func TestMatchOS(t *testing.T) {
	fps := []OSFingerprint{{
		OS: "Windows",
		Heuristics: OSHeuristics{
			TTLRange: []int{110, 130},
			Services: []OSServiceHint{{Port: 445, Service: "smb"}},
		},
	}}

	name, score := MatchOS(fps, OSContext{
		TTL:      128,
		Services: map[int]string{445: "smb"},
	})
	if name != "Windows" {
		t.Fatalf("expected Windows, got %s", name)
	}
	if score <= 0 {
		t.Fatalf("expected score > 0")
	}
}
