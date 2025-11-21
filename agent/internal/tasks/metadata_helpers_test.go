package tasks

import (
	"net"
	"testing"
)

func TestMergeMetadataIgnoresBlankKeys(t *testing.T) {
	dst := map[string]string{"existing": "value"}
	mergeMetadata(dst, map[string]string{" ": "ignored", "k": "v"})
	if len(dst) != 2 {
		t.Fatalf("expected 2 keys, got %d", len(dst))
	}
	if dst["k"] != "v" {
		t.Fatalf("expected dst['k']=v, got %s", dst["k"])
	}
}

func TestCloneMetadataReturnsNilForEmpty(t *testing.T) {
	if cloneMetadata(nil) != nil {
		t.Fatalf("expected nil clone for nil input")
	}
	src := map[string]string{"a": "b"}
	clone := cloneMetadata(src)
	clone["a"] = "mutated"
	if src["a"] != "b" {
		t.Fatalf("clone must not mutate source")
	}
}

func TestLooksLikePath(t *testing.T) {
	cases := []struct {
		in  string
		out string
	}{
		{"/var/log/syslog", "/var/log/syslog"},
		{"artifact.zip", "artifact.zip"},
		{"   ", ""},
		{"hello", ""},
	}
	for _, tc := range cases {
		if got := looksLikePath(tc.in); got != tc.out {
			t.Fatalf("looksLikePath(%q)=%q want %q", tc.in, got, tc.out)
		}
	}
}

func TestIsPublicIPv4(t *testing.T) {
	if isPublicIPv4(nil) {
		t.Fatal("nil is not public")
	}
	if isPublicIPv4(net.ParseIP("10.0.0.1")) {
		t.Fatal("private IP should be false")
	}
	if !isPublicIPv4(net.ParseIP("8.8.8.8")) {
		t.Fatal("expected public IP true")
	}
}
