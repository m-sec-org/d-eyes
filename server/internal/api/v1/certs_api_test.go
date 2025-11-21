package v1_test

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/require"

	v1 "github.com/m-sec-org/d-eyes/server/internal/api/v1"
	"github.com/m-sec-org/d-eyes/server/internal/certmanager"
	"github.com/m-sec-org/d-eyes/server/internal/security"
)

func setupCertRouter(t *testing.T, role string) *gin.Engine {
	t.Helper()
	gin.SetMode(gin.TestMode)
	handler := &v1.CertHandler{Manager: &certmanager.Manager{}}
	router := gin.New()
	router.Use(func(c *gin.Context) {
		security.WithPrincipal(c, security.Principal{User: "tester", Role: role})
	})
	api := router.Group("/api/v1")
	handler.RegisterRoutes(api)
	return router
}

func TestCertRotateRequiresAdmin(t *testing.T) {
	router := setupCertRouter(t, "operator")
	req := httptest.NewRequest(http.MethodPost, "/api/v1/certs/rotate", nil)

	resp := performRequest(router, req)
	require.Equal(t, http.StatusForbidden, resp.Code)
}

func TestIssueAgentCertValidatesCommonName(t *testing.T) {
	router := setupCertRouter(t, "admin")
	req := httptest.NewRequest(http.MethodPost, "/api/v1/certs/agent", bytes.NewReader([]byte(`{}`)))
	req.Header.Set("Content-Type", "application/json")

	resp := performRequest(router, req)
	require.Equal(t, http.StatusBadRequest, resp.Code)
	require.Contains(t, resp.Body.String(), "CommonName")
}
