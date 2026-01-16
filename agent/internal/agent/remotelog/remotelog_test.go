package remotelog

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestFormat_StructureAndNormalization(t *testing.T) {
	line := Format("grpc.connect", NewRedactor(), Field{Key: "Task ID", Value: "abc 123"}, Field{Key: "dur_ms", Value: 15})
	require.Contains(t, line, Prefix)
	require.Contains(t, line, "event=grpc.connect")
	require.Contains(t, line, `task_id="abc 123"`)
	require.Contains(t, line, "dur_ms=15")
}

func TestFormat_RedactsSensitiveKeys(t *testing.T) {
	line := Format("grpc.register", NewRedactor(), Field{Key: "agent_token", Value: "nsfocus"}, Field{Key: "X-API-Key", Value: "nsfocus_123"})
	require.Contains(t, line, "agent_token=<redacted>")
	require.Contains(t, line, "x-api-key=<redacted>")
	require.NotContains(t, line, "nsfocus_123")
	require.NotContains(t, line, "nsfocus")
}

func TestFormat_RedactsSecretsFromValues(t *testing.T) {
	redactor := NewRedactor("nsfocus")
	line := Format("grpc.error", redactor, Field{Key: "err", Value: errors.New("invalid agent token: nsfocus")})
	require.NotContains(t, line, "nsfocus")
	require.Contains(t, line, "<redacted>")
}

func TestJSONTopLevelKeys(t *testing.T) {
	keys := JSONTopLevelKeys([]byte(`{"a":1,"b":{"c":2},"d":[1,2]}`))
	require.Equal(t, []string{"a", "b", "d"}, keys)
	require.Nil(t, JSONTopLevelKeys([]byte(`[]`)))
	require.Nil(t, JSONTopLevelKeys([]byte(``)))
}

func TestStringMapKeys(t *testing.T) {
	keys := StringMapKeys(map[string]string{"b": "2", "a": "1"})
	require.Equal(t, []string{"a", "b"}, keys)
	require.Nil(t, StringMapKeys(nil))
}
