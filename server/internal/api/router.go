package api

import (
	"net/http"

	"github.com/gin-gonic/gin"

	v1 "github.com/m-sec-org/d-eyes/server/internal/api/v1"
	"github.com/m-sec-org/d-eyes/server/internal/config"
)

func NewRouter(cfg config.Config, taskHandler *v1.TaskHandler, metricsHandler gin.HandlerFunc) *gin.Engine {
	r := gin.New()
	r.Use(gin.Recovery())

	r.GET("/healthz", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"status": "ok"})
	})

	if cfg.Metrics.Enabled && metricsHandler != nil {
		r.GET(cfg.Metrics.Path, metricsHandler)
	}

	apiGroup := r.Group("/api/v1")
	if len(cfg.Security.APIKeys) > 0 {
		apiGroup.Use(apiKeyMiddleware(cfg.Security.APIKeys))
	}
	taskHandler.RegisterRoutes(apiGroup)

	return r
}

func apiKeyMiddleware(keys []string) gin.HandlerFunc {
	normalized := make([]string, 0, len(keys))
	for _, k := range keys {
		if k != "" {
			normalized = append(normalized, k)
		}
	}
	return func(c *gin.Context) {
		if len(normalized) == 0 {
			return
		}
		header := c.GetHeader("X-API-Key")
		if header == "" {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "missing api key"})
			return
		}
		for _, allowed := range normalized {
			if subtleConstantTimeEquals(header, allowed) {
				return
			}
		}
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "invalid api key"})
	}
}

func subtleConstantTimeEquals(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	var diff byte
	for i := 0; i < len(a); i++ {
		diff |= a[i] ^ b[i]
	}
	return diff == 0
}
