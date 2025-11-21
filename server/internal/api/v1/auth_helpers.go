package v1

import (
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"

	"github.com/m-sec-org/d-eyes/server/internal/security"
)

func requireAdmin(c *gin.Context) bool {
	principal := security.PrincipalFrom(c)
	if strings.ToLower(principal.Role) != "admin" {
		c.JSON(http.StatusForbidden, gin.H{"error": "admin role required"})
		return false
	}
	return true
}
