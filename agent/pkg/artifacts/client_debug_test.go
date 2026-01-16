package artifacts

import (
	"errors"
	"net/url"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestSafeURLPathStripsQueryAndFragment(t *testing.T) {
	secret := "nsfocus_123"
	raw := "https://example.com/api/v1/artifacts/upload/token-123?X-API-Key=" + secret + "&X-Amz-Signature=abc#frag"
	require.Equal(t, "/api/v1/artifacts/upload/token-123", safeURLPath(raw))
}

func TestSanitizeHTTPErrorStripsQuery(t *testing.T) {
	secret := "api-key-secret"
	raw := "https://example.com/api/v1/artifacts/upload/token-123?X-API-Key=" + secret
	err := sanitizeHTTPError(&url.Error{Op: "Put", URL: raw, Err: errors.New("dial failed")})
	require.Error(t, err)
	require.Contains(t, err.Error(), "/api/v1/artifacts/upload/token-123")
	require.NotContains(t, err.Error(), secret)
	require.NotContains(t, err.Error(), "X-API-Key")
	require.NotContains(t, err.Error(), "?")
}
