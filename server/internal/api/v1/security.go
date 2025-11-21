package v1

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/m-sec-org/d-eyes/server/internal/security"
)

// SecurityHandler exposes MFA management endpoints for admins.
type SecurityHandler struct {
	MFAStore   *security.MFAStore
	HTTPClient *http.Client
}

// RegisterRoutes wires security endpoints.
func (h *SecurityHandler) RegisterRoutes(r *gin.RouterGroup) {
	if h == nil {
		return
	}
	group := r.Group("/security")
	group.GET("/mfa", h.getMFAConfig)
	group.POST("/mfa/secrets", h.updateMFASecrets)
}

func (h *SecurityHandler) getMFAConfig(c *gin.Context) {
	if !requireAdmin(c) {
		return
	}
	if h.MFAStore == nil {
		c.JSON(http.StatusOK, gin.H{"enabled": false})
		return
	}
	secrets := h.MFAStore.Secrets()
	c.JSON(http.StatusOK, gin.H{
		"enabled": h.MFAStore.Enabled(),
		"secrets": secrets,
		"header":  strings.TrimSpace(h.MFAStore.Header()),
	})
}

func (h *SecurityHandler) updateMFASecrets(c *gin.Context) {
	if !requireAdmin(c) {
		return
	}
	if h.MFAStore == nil || !h.MFAStore.Enabled() {
		c.JSON(http.StatusBadRequest, gin.H{"error": "mfa disabled"})
		return
	}
	var req struct {
		Secrets   map[string]string `json:"secrets"`
		RemoteURL string            `json:"remote_url"`
		AuthToken string            `json:"auth_token"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	var secrets map[string]string
	var err error
	if req.RemoteURL != "" {
		secrets, err = h.fetchSecrets(c.Request.Context(), req.RemoteURL, req.AuthToken)
		if err != nil {
			c.JSON(http.StatusBadGateway, gin.H{"error": err.Error()})
			return
		}
	} else {
		secrets = req.Secrets
	}
	if len(secrets) == 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "no secrets provided"})
		return
	}
	h.MFAStore.MergeSecrets(secrets)
	c.JSON(http.StatusOK, gin.H{"status": "updated", "total": len(h.MFAStore.Secrets())})
}

func (h *SecurityHandler) fetchSecrets(ctx context.Context, url, token string) (map[string]string, error) {
	client := h.HTTPClient
	if client == nil {
		client = &http.Client{Timeout: 10 * time.Second}
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("remote fetch failed: %s", resp.Status)
	}
	var secrets map[string]string
	if err := json.NewDecoder(resp.Body).Decode(&secrets); err != nil {
		return nil, err
	}
	return secrets, nil
}
