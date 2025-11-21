package v1

import (
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/m-sec-org/d-eyes/server/internal/certmanager"
)

// CertHandler exposes certificate lifecycle endpoints.
type CertHandler struct {
	Manager *certmanager.Manager
}

// RegisterRoutes wires TLS management endpoints.
func (h *CertHandler) RegisterRoutes(r *gin.RouterGroup) {
	if h == nil || h.Manager == nil {
		return
	}
	r.GET("/certs/ca", h.getCA)
	r.POST("/certs/rotate", h.rotate)
	r.POST("/certs/agent", h.issueAgentCert)
}

func (h *CertHandler) getCA(c *gin.Context) {
	pem, expires := h.Manager.CACertificate()
	c.JSON(http.StatusOK, gin.H{
		"ca_pem":     string(pem),
		"expires_at": expires.UTC(),
	})
}

func (h *CertHandler) rotate(c *gin.Context) {
	if !requireAdmin(c) {
		return
	}
	result, err := h.Manager.Rotate()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"ca_pem":            string(result.CAPEM),
		"server_pem":        string(result.ServerPEM),
		"ca_expires_at":     result.CANotAfter.UTC(),
		"server_expires_at": result.ServerExpiry.UTC(),
	})
}

type agentCertRequest struct {
	CommonName string  `json:"common_name" binding:"required"`
	TTLHours   float64 `json:"ttl_hours,omitempty"`
}

func (h *CertHandler) issueAgentCert(c *gin.Context) {
	if !requireAdmin(c) {
		return
	}
	var body agentCertRequest
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	var ttl time.Duration
	if body.TTLHours > 0 {
		ttl = time.Duration(body.TTLHours * float64(time.Hour))
	}
	bundle, err := h.Manager.IssueAgentCertificate(strings.TrimSpace(body.CommonName), ttl)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusCreated, gin.H{
		"cert_pem":   string(bundle.CertPEM),
		"key_pem":    string(bundle.KeyPEM),
		"ca_pem":     string(bundle.CAPEM),
		"expires_at": bundle.ExpiresAt.UTC(),
	})
}
