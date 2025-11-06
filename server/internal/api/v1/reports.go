package v1

import (
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/m-sec-org/d-eyes/server/internal/model"
	"github.com/m-sec-org/d-eyes/server/internal/store"
)

// ReportHandler 聚合任务结果并提供导出能力。
type ReportHandler struct {
	Store store.Store
}

func (h *ReportHandler) RegisterRoutes(r *gin.RouterGroup) {
	if h == nil || h.Store == nil {
		return
	}
	group := r.Group("/reports")
	group.GET("/summary", h.summary)
	group.GET("/export", h.export)
}

type reportItem struct {
	ResultID     string            `json:"result_id"`
	TaskID       string            `json:"task_id"`
	TaskType     string            `json:"task_type"`
	Profile      string            `json:"profile,omitempty"`
	RunID        string            `json:"run_id,omitempty"`
	AgentID      string            `json:"agent_id,omitempty"`
	Status       string            `json:"status"`
	ScenarioID   string            `json:"scenario_id,omitempty"`
	ScenarioName string            `json:"scenario_name,omitempty"`
	ErrorMessage string            `json:"error_message,omitempty"`
	ExitCode     int32             `json:"exit_code"`
	ErrorCode    string            `json:"error_code,omitempty"`
	Metadata     map[string]string `json:"metadata,omitempty"`
	CompletedAt  time.Time         `json:"completed_at"`
}

type summaryResponse struct {
	Items  []reportItem   `json:"items"`
	Totals map[string]int `json:"totals"`
	Status map[string]int `json:"status_totals"`
}

func (h *ReportHandler) summary(c *gin.Context) {
	taskType := model.TaskType(strings.TrimSpace(c.Query("type")))
	limit := parseLimit(c.Query("limit"), 50)
	results, err := h.Store.ListTaskResults(c.Request.Context(), taskType, limit)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	items := make([]reportItem, 0, len(results))
	totals := make(map[string]int)
	statusTotals := make(map[string]int)
	for _, res := range results {
		items = append(items, toReportItem(res))
		totals[string(res.TaskType)]++
		statusTotals[string(res.Status)]++
	}
	c.JSON(http.StatusOK, summaryResponse{
		Items:  items,
		Totals: totals,
		Status: statusTotals,
	})
}

func (h *ReportHandler) export(c *gin.Context) {
	taskType := model.TaskType(strings.TrimSpace(c.Query("type")))
	limit := parseLimit(c.Query("limit"), 200)
	format := strings.ToLower(strings.TrimSpace(c.Query("format")))
	if format == "" {
		format = "json"
	}
	results, err := h.Store.ListTaskResults(c.Request.Context(), taskType, limit)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	switch format {
	case "json":
		payload := make([]reportItem, 0, len(results))
		for _, res := range results {
			payload = append(payload, toReportItem(res))
		}
		c.Header("Content-Disposition", fmt.Sprintf(`attachment; filename="reports-%d.json"`, time.Now().Unix()))
		c.JSON(http.StatusOK, payload)
	case "html":
		html := buildHTMLReport(results)
		c.Header("Content-Type", "text/html; charset=utf-8")
		c.Header("Content-Disposition", fmt.Sprintf(`attachment; filename="reports-%d.html"`, time.Now().Unix()))
		_, _ = c.Writer.WriteString(html)
	default:
		c.JSON(http.StatusBadRequest, gin.H{"error": "unsupported format"})
	}
}

func toReportItem(res *model.TaskResult) reportItem {
	item := reportItem{
		ResultID:     res.ID.String(),
		TaskID:       res.TaskID.String(),
		TaskType:     string(res.TaskType),
		Profile:      res.Profile,
		Status:       string(res.Status),
		ScenarioID:   res.ScenarioID,
		ScenarioName: res.ScenarioName,
		ErrorMessage: res.ErrorMessage,
		ExitCode:     res.ExitCode,
		ErrorCode:    res.ErrorCode,
		Metadata:     res.Metadata,
		CompletedAt:  res.CompletedAt,
	}
	if res.RunID != uuid.Nil {
		item.RunID = res.RunID.String()
	}
	if res.AgentID != uuid.Nil {
		item.AgentID = res.AgentID.String()
	}
	return item
}

func buildHTMLReport(results []*model.TaskResult) string {
	var builder strings.Builder
	builder.WriteString("<!DOCTYPE html><html><head><meta charset=\"utf-8\"><title>D-Eyes Reports</title>")
	builder.WriteString("<style>body{font-family:Arial, sans-serif;} table{border-collapse:collapse;width:100%;} th,td{border:1px solid #ccc;padding:6px;text-align:left;} th{background:#f5f5f5;}</style></head><body>")
	builder.WriteString("<h1>D-Eyes Report Summary</h1>")
	builder.WriteString("<table><thead><tr><th>Completed At</th><th>Task Type</th><th>Status</th><th>Task ID</th><th>Scenario</th><th>Error</th></tr></thead><tbody>")
	for _, res := range results {
		escScenario := templateHTMLEscape(res.ScenarioName)
		escError := templateHTMLEscape(res.ErrorMessage)
		builder.WriteString("<tr>")
		builder.WriteString("<td>" + res.CompletedAt.Format(time.RFC3339) + "</td>")
		builder.WriteString("<td>" + templateHTMLEscape(string(res.TaskType)) + "</td>")
		builder.WriteString("<td>" + templateHTMLEscape(string(res.Status)) + "</td>")
		builder.WriteString("<td>" + res.TaskID.String() + "</td>")
		builder.WriteString("<td>" + escScenario + "</td>")
		builder.WriteString("<td>" + escError + "</td>")
		builder.WriteString("</tr>")
	}
	builder.WriteString("</tbody></table></body></html>")
	return builder.String()
}

func templateHTMLEscape(s string) string {
	replacer := strings.NewReplacer(
		"&", "&amp;",
		"<", "&lt;",
		">", "&gt;",
		`"`, "&quot;",
		"'", "&#39;",
	)
	return replacer.Replace(s)
}

func parseLimit(raw string, fallback int) int {
	if raw == "" {
		return fallback
	}
	if v, err := strconv.Atoi(raw); err == nil && v > 0 {
		return v
	}
	return fallback
}
