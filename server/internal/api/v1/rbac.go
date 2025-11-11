package v1

import (
	"net/http"

	"github.com/gin-gonic/gin"

	"github.com/m-sec-org/d-eyes/server/internal/rbac"
)

// RBACHandler returns configured policies.
type RBACHandler struct {
	Enforcer *rbac.Enforcer
}

func (h *RBACHandler) RegisterRoutes(r *gin.RouterGroup) {
	if h == nil || h.Enforcer == nil {
		return
	}
	r.GET("/rbac/policies", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"policies": h.Enforcer.Policies()})
	})
}
