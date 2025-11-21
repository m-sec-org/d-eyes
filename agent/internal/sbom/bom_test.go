package sbom

import "testing"

func TestNewMsecSbomDefaults(t *testing.T) {
	bom := NewMsecSbom()
	if bom.SerialNumber == "" || bom.SpecVersion == 0 {
		t.Fatalf("bom should have defaults")
	}
}

func TestNewMetadataTimestamp(t *testing.T) {
	meta := NewMetadata()
	if meta.Timestamp == "" {
		t.Fatalf("metadata must include timestamp")
	}
}
