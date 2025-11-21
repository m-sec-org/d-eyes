package v1_test

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/require"

	v1 "github.com/m-sec-org/d-eyes/server/internal/api/v1"
	"github.com/m-sec-org/d-eyes/server/internal/plugins"
)

func setupPluginRouter(t *testing.T) *gin.Engine {
	t.Helper()
	gin.SetMode(gin.TestMode)
	handler := &v1.PluginHandler{Manager: plugins.NewManager()}
	router := gin.New()
	api := router.Group("/api/v1")
	handler.RegisterRoutes(api)
	return router
}

func TestPluginGetReturnsNotFound(t *testing.T) {
	router := setupPluginRouter(t)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/plugins/ghost", nil)

	resp := performRequest(router, req)
	require.Equal(t, http.StatusNotFound, resp.Code)
}

func TestPluginInstallRejectsInvalidBase64(t *testing.T) {
	router := setupPluginRouter(t)
	body, _ := json.Marshal(map[string]string{
		"manifest": "@@@not-base64@@@",
		"encoding": "base64",
	})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/plugins", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")

	resp := performRequest(router, req)
	require.Equal(t, http.StatusBadRequest, resp.Code)
	require.Contains(t, resp.Body.String(), "decode")
}
