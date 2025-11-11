package v1

import (
	"net/http"
	"strconv"
	"strings"

	"github.com/gin-gonic/gin"

	"github.com/m-sec-org/d-eyes/server/internal/auditlog"
)

// AuditHandler exposes read APIs for audit logs.
type AuditHandler struct {
	Logs *auditlog.Manager
}

func (h *AuditHandler) RegisterRoutes(r *gin.RouterGroup) {
	if h == nil || h.Logs == nil {
		return
	}
	r.GET("/audit/events", h.listEvents)
}

func (h *AuditHandler) listEvents(c *gin.Context) {
	filter := auditlog.Filter{
		Actor:    c.Query("actor"),
		Resource: c.Query("resource"),
		Action:   c.Query("action"),
	}
	if limit := strings.TrimSpace(c.Query("limit")); limit != "" {
		if v, err := strconv.Atoi(limit); err == nil {
			filter.Limit = v
		}
	}
	events := h.Logs.List(filter)
	c.JSON(http.StatusOK, gin.H{"items": events})
}
