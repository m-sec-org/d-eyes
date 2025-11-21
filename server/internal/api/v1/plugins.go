package v1

import (
	"encoding/base64"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"

	"github.com/m-sec-org/d-eyes/server/internal/plugins"
	"github.com/m-sec-org/d-eyes/server/internal/streams"
)

// PluginHandler exposes plugin marketplace APIs.
type PluginHandler struct {
	Manager *plugins.Manager
	Stream  *streams.Hub
}

// RegisterRoutes wires plugin endpoints when manager is provided.
func (h *PluginHandler) RegisterRoutes(r *gin.RouterGroup) {
	if h == nil || h.Manager == nil {
		return
	}
	r.GET("/plugins", h.list)
	r.GET("/plugins/:name", h.get)
	r.POST("/plugins", h.install)
	r.POST("/plugins/:name/rollback", h.rollback)
	if h.Stream != nil {
		r.GET("/plugins/stream", streams.SSEHandler(h.Stream))
	}
}

func (h *PluginHandler) list(c *gin.Context) {
	c.JSON(http.StatusOK, h.Manager.List())
}

func (h *PluginHandler) get(c *gin.Context) {
	rec, ok := h.Manager.Get(c.Param("name"))
	if !ok {
		c.JSON(http.StatusNotFound, gin.H{"error": "plugin not found"})
		return
	}
	c.JSON(http.StatusOK, rec)
}

type installRequest struct {
	Manifest string `json:"manifest" binding:"required"`
	Encoding string `json:"encoding,omitempty"`
}

func (h *PluginHandler) install(c *gin.Context) {
	var body installRequest
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	payload := strings.TrimSpace(body.Manifest)
	if payload == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "manifest is required"})
		return
	}
	if strings.EqualFold(body.Encoding, "base64") {
		decoded, err := base64.StdEncoding.DecodeString(payload)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "manifest base64 decode failed"})
			return
		}
		payload = string(decoded)
	}
	record, err := h.Manager.Install(c.Request.Context(), []byte(payload))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error(), "record": record})
		return
	}
	c.JSON(http.StatusCreated, record)
}

func (h *PluginHandler) rollback(c *gin.Context) {
	record, err := h.Manager.Rollback(c.Request.Context(), c.Param("name"))
	if err != nil {
		status := http.StatusBadRequest
		if strings.Contains(strings.ToLower(err.Error()), "not found") {
			status = http.StatusNotFound
		}
		c.JSON(status, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, record)
}
