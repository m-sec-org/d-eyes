package v1

import (
	"net/http"
	"strconv"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/m-sec-org/d-eyes/server/internal/model"
	"github.com/m-sec-org/d-eyes/server/internal/store"
)

// BehaviorHandler exposes anomaly query endpoints.
type BehaviorHandler struct {
	Store store.Store
}

func (h *BehaviorHandler) RegisterRoutes(r *gin.RouterGroup) {
	if h == nil || h.Store == nil {
		return
	}
	legacy := r.Group("/behavior")
	legacy.GET("/anomalies", h.queryAnomalies)
	legacy.GET("/anomalies/:id", h.getAnomaly)

	anomalies := r.Group("/anomalies")
	anomalies.GET("", h.queryAnomalies)
	anomalies.GET("/:id", h.getAnomaly)
	anomalies.GET("/:id/graph", h.getAnomalyGraph)
}

func (h *BehaviorHandler) queryAnomalies(c *gin.Context) {
	limit := 50
	if v := c.Query("limit"); v != "" {
		if parsed, err := strconv.Atoi(v); err == nil && parsed > 0 {
			limit = parsed
		}
	}
	filter := model.AnomalyFilter{Limit: limit}
	if agentParam := c.Query("agent_id"); agentParam != "" {
		if id, err := uuid.Parse(agentParam); err == nil {
			filter.AgentID = &id
		} else {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid agent_id"})
			return
		}
	}
	if taskParam := c.Query("task_id"); taskParam != "" {
		if id, err := uuid.Parse(taskParam); err == nil {
			filter.TaskID = &id
		} else {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid task_id"})
			return
		}
	}
	if ioc := strings.TrimSpace(c.Query("ioc")); ioc != "" {
		filter.IOC = ioc
	}
	statusVals := c.QueryArray("status")
	if len(statusVals) == 0 {
		if single := c.Query("status"); single != "" {
			statusVals = strings.Split(single, ",")
		}
	}
	if len(statusVals) > 0 {
		filter.Status = statusVals
	}
	if minScore := c.Query("min_score"); minScore != "" {
		if parsed, err := strconv.ParseFloat(minScore, 64); err == nil {
			filter.MinScore = parsed
		}
	}
	anomalies, err := h.Store.ListAnomaliesByFilter(c.Request.Context(), filter)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"items": anomalies})
}

func (h *BehaviorHandler) getAnomaly(c *gin.Context) {
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid anomaly id"})
		return
	}
	anomaly, err := h.Store.GetAnomaly(c.Request.Context(), id)
	if err != nil {
		if err == store.ErrNotFound {
			c.JSON(http.StatusNotFound, gin.H{"error": "anomaly not found"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, anomaly)
}

func (h *BehaviorHandler) getAnomalyGraph(c *gin.Context) {
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid anomaly id"})
		return
	}
	graph, err := h.Store.GetAnomalyGraph(c.Request.Context(), id)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	if graph == nil {
		graph = &model.AnomalyGraph{}
	}
	c.JSON(http.StatusOK, graph)
}
