package security

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"

	"github.com/m-sec-org/d-eyes/server/internal/config"
)

func TestMFAMiddleware(t *testing.T) {
	gin.SetMode(gin.TestMode)
	cfg := config.MFAConfig{
		Enabled:       true,
		Header:        "X-Test-MFA",
		RequiredRoles: []string{"admin"},
		Secrets: map[string]string{
			"alice": "123456",
		},
	}
	store := NewMFAStore(cfg)
	router := gin.New()
	router.Use(func(c *gin.Context) {
		WithPrincipal(c, Principal{User: "alice", Role: "admin"})
	})
	router.Use(store.Middleware())
	router.GET("/secure", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"ok": true})
	})

	req := httptest.NewRequest(http.MethodGet, "/secure", nil)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	if rr.Code != http.StatusForbidden {
		t.Fatalf("expected forbidden without mfa header, got %d", rr.Code)
	}

	req = httptest.NewRequest(http.MethodGet, "/secure", nil)
	req.Header.Set("X-Test-MFA", "123456")
	rr = httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected OK with mfa header, got %d", rr.Code)
	}
}
