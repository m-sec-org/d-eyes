package api

import (
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"

	v1 "github.com/m-sec-org/d-eyes/server/internal/api/v1"
	"github.com/m-sec-org/d-eyes/server/internal/config"
	"github.com/m-sec-org/d-eyes/server/internal/security"
)

func NewRouter(
	cfg config.Config,
	taskHandler *v1.TaskHandler,
	templateHandler *v1.TemplateHandler,
	reportHandler *v1.ReportHandler,
	catalogHandler *v1.TaskCatalogHandler,
	pluginHandler *v1.PluginHandler,
	basScenarioHandler *v1.BASScenarioHandler,
	agentHandler *v1.AgentHandler,
	auditHandler *v1.AuditHandler,
	rbacHandler *v1.RBACHandler,
	artifactHandler *v1.ArtifactHandler,
	threatIntelHandler *v1.ThreatIntelHandler,
	behaviorHandler *v1.BehaviorHandler,
	complianceHandler *v1.ComplianceHandler,
	playbookHandler *v1.PlaybookHandler,
	certHandler *v1.CertHandler,
	securityHandler *v1.SecurityHandler,
	opsHandler *v1.OpsHandler,
	mfaStore *security.MFAStore,
	metricsHandler gin.HandlerFunc,
	taskStreamHandler gin.HandlerFunc,
	threatStreamHandler gin.HandlerFunc,
	anomalyStreamHandler gin.HandlerFunc,
) *gin.Engine {
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
	apiGroup.Use(principalMiddleware())
	if mfaStore != nil && mfaStore.Enabled() {
		apiGroup.Use(mfaStore.Middleware())
	}

	if taskHandler != nil {
		taskHandler.RegisterRoutes(apiGroup)
	}
	if templateHandler != nil {
		templateHandler.RegisterRoutes(apiGroup)
	}
	if reportHandler != nil {
		reportHandler.RegisterRoutes(apiGroup)
	}
	if catalogHandler != nil {
		catalogHandler.RegisterRoutes(apiGroup)
	}
	if pluginHandler != nil {
		pluginHandler.RegisterRoutes(apiGroup)
	}
	if basScenarioHandler != nil {
		basScenarioHandler.RegisterRoutes(apiGroup)
	}
	if agentHandler != nil {
		agentHandler.RegisterRoutes(apiGroup)
	}
	if auditHandler != nil {
		auditHandler.RegisterRoutes(apiGroup)
	}
	if rbacHandler != nil {
		rbacHandler.RegisterRoutes(apiGroup)
	}
	if artifactHandler != nil {
		artifactHandler.RegisterRoutes(apiGroup)
	}
	if threatIntelHandler != nil {
		threatIntelHandler.RegisterRoutes(apiGroup)
	}
	if behaviorHandler != nil {
		behaviorHandler.RegisterRoutes(apiGroup)
	}
	if complianceHandler != nil {
		complianceHandler.RegisterRoutes(apiGroup)
	}
	if playbookHandler != nil {
		playbookHandler.RegisterRoutes(apiGroup)
	}
	if certHandler != nil {
		certHandler.RegisterRoutes(apiGroup)
	}
	if securityHandler != nil {
		securityHandler.RegisterRoutes(apiGroup)
	}
	if opsHandler != nil {
		opsHandler.RegisterRoutes(apiGroup)
	}
	if taskStreamHandler != nil {
		apiGroup.GET("/tasks/stream", taskStreamHandler)
	}
	if threatStreamHandler != nil {
		apiGroup.GET("/threat-intel/stream", threatStreamHandler)
	}
	if anomalyStreamHandler != nil {
		apiGroup.GET("/anomalies/stream", anomalyStreamHandler)
	}

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

func principalMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		user := strings.TrimSpace(c.GetHeader("X-User"))
		if user == "" {
			user = "api-client"
		}
		role := strings.ToLower(strings.TrimSpace(c.GetHeader("X-User-Role")))
		if role == "" {
			role = "operator"
		}
		security.WithPrincipal(c, security.Principal{User: user, Role: role})
		c.Next()
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
