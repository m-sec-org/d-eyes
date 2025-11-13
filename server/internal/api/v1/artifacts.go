package v1

import (
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/m-sec-org/d-eyes/server/internal/artifacts"
)

// ArtifactHandler exposes endpoints for artifact uploads.
type ArtifactHandler struct {
	Manager *artifacts.Manager
}

func (h *ArtifactHandler) RegisterRoutes(r *gin.RouterGroup) {
	if h == nil || h.Manager == nil {
		return
	}
	group := r.Group("/artifacts")
	group.POST("/presign", h.createUpload)
	group.PUT("/upload/:id", h.upload)
}

type presignRequest struct {
	Filename    string `json:"filename" binding:"required"`
	ContentType string `json:"content_type"`
	Hash        string `json:"hash"`
	Size        int64  `json:"size"`
	Encryption  string `json:"encryption"`
}

type presignResponse struct {
	UploadID  string    `json:"upload_id"`
	UploadURL string    `json:"upload_url"`
	ExpiresAt time.Time `json:"expires_at"`
}

func (h *ArtifactHandler) createUpload(c *gin.Context) {
	var req presignRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	meta := artifacts.Metadata{
		Filename:    strings.TrimSpace(req.Filename),
		ContentType: strings.TrimSpace(req.ContentType),
		Hash:        strings.TrimSpace(req.Hash),
		Encryption:  strings.TrimSpace(req.Encryption),
		Size:        req.Size,
	}
	id, expiresAt, err := h.Manager.CreateUpload(meta)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	base := requestBaseURL(c)
	uploadURL := base + "/api/v1/artifacts/upload/" + id.String()
	c.JSON(http.StatusOK, presignResponse{
		UploadID:  id.String(),
		UploadURL: uploadURL,
		ExpiresAt: expiresAt,
	})
}

func (h *ArtifactHandler) upload(c *gin.Context) {
	idStr := c.Param("id")
	id, err := uuid.Parse(idStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid upload id"})
		return
	}
	if err := h.Manager.WriteUpload(id, c.Request.Body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"status": "uploaded"})
}

func requestBaseURL(c *gin.Context) string {
	scheme := "http"
	if c.Request.TLS != nil {
		scheme = "https"
	} else if forwarded := strings.TrimSpace(c.GetHeader("X-Forwarded-Proto")); forwarded != "" {
		scheme = forwarded
	}
	host := c.Request.Host
	if host == "" {
		host = "localhost"
	}
	return scheme + "://" + host
}
