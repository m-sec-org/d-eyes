package v1

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net/http"
	"strconv"
	"strings"
	"text/template"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/m-sec-org/d-eyes/server/internal/auditlog"
	"github.com/m-sec-org/d-eyes/server/internal/model"
	"github.com/m-sec-org/d-eyes/server/internal/reporttemplates"
	"github.com/m-sec-org/d-eyes/server/internal/security"
	"github.com/m-sec-org/d-eyes/server/internal/store"
)

// ReportHandler 聚合任务结果并提供导出能力。
type ReportHandler struct {
	Store     store.Store
	Templates *reporttemplates.Manager
	Audit     *auditlog.Manager
}

func (h *ReportHandler) recordAudit(c *gin.Context, action, resource, result string) {
	if h == nil || h.Audit == nil {
		return
	}
	principal := security.PrincipalFrom(c)
	h.Audit.Record(auditlog.Event{
		Actor:    principal.User,
		Role:     principal.Role,
		Action:   action,
		Resource: resource,
		Result:   result,
	})
}

func (h *ReportHandler) RegisterRoutes(r *gin.RouterGroup) {
	if h == nil || h.Store == nil {
		return
	}
	group := r.Group("/reports")
	group.GET("/summary", h.summary)
	group.GET("/export", h.export)
	if h.Templates != nil {
		group.GET("/templates", h.listTemplates)
		group.POST("/templates", h.createTemplate)
		group.PUT("/templates/:id", h.updateTemplate)
		group.DELETE("/templates/:id", h.deleteTemplate)
		group.POST("/generate", h.generateReport)
	}
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
	Status map[string]int `json:"status"`
	Trends *summaryTrends `json:"trends,omitempty"`
}

type metricTrend struct {
	Delta float64 `json:"delta"`
	Trend string  `json:"trend,omitempty"`
}

type summaryTrends struct {
	Period string                 `json:"period,omitempty"`
	Totals map[string]metricTrend `json:"totals,omitempty"`
	Status map[string]metricTrend `json:"status,omitempty"`
}

func (h *ReportHandler) summary(c *gin.Context) {
	taskType := model.TaskType(strings.TrimSpace(c.Query("type")))
	limit := parseLimit(c.Query("limit"), 50)
	windowHours := parseWindowHours(c.Query("window_hours"), 24)
	results, err := h.Store.ListTaskResults(c.Request.Context(), taskType, limit)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	items := make([]reportItem, 0, len(results))
	totals := make(map[string]int)
	statusTotals := make(map[string]int)
	currentTotals := make(map[string]int)
	previousTotals := make(map[string]int)
	currentStatus := make(map[string]int)
	previousStatus := make(map[string]int)
	now := time.Now().UTC()
	windowDuration := time.Duration(windowHours) * time.Hour
	currentWindowStart := now.Add(-windowDuration)
	previousWindowStart := currentWindowStart.Add(-windowDuration)
	for _, res := range results {
		items = append(items, toReportItem(res))
		tType := string(res.TaskType)
		status := string(res.Status)
		totals[tType]++
		statusTotals[status]++
		switch {
		case !res.CompletedAt.Before(currentWindowStart):
			currentTotals[tType]++
			currentStatus[status]++
		case !res.CompletedAt.Before(previousWindowStart):
			previousTotals[tType]++
			previousStatus[status]++
		}
	}
	c.JSON(http.StatusOK, summaryResponse{
		Items:  items,
		Totals: totals,
		Status: statusTotals,
		Trends: buildSummaryTrends(windowHours, currentTotals, previousTotals, currentStatus, previousStatus),
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

func (h *ReportHandler) listTemplates(c *gin.Context) {
	templates := h.Templates.List()
	c.JSON(http.StatusOK, templates)
}

func (h *ReportHandler) createTemplate(c *gin.Context) {
	var req reporttemplates.Template
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	created, err := h.Templates.Create(req)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	h.recordAudit(c, "report.template.create", "report-template:"+created.ID.String(), "accepted")
	c.JSON(http.StatusCreated, created)
}

func (h *ReportHandler) updateTemplate(c *gin.Context) {
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid template id"})
		return
	}
	var req reporttemplates.Template
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	updated, err := h.Templates.Update(id, req)
	if err != nil {
		status := http.StatusBadRequest
		if errors.Is(err, reporttemplates.ErrNotFound) {
			status = http.StatusNotFound
		}
		c.JSON(status, gin.H{"error": err.Error()})
		return
	}
	h.recordAudit(c, "report.template.update", "report-template:"+id.String(), "accepted")
	c.JSON(http.StatusOK, updated)
}

func (h *ReportHandler) deleteTemplate(c *gin.Context) {
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid template id"})
		return
	}
	if err := h.Templates.Delete(id); err != nil {
		status := http.StatusBadRequest
		if errors.Is(err, reporttemplates.ErrNotFound) {
			status = http.StatusNotFound
		}
		c.JSON(status, gin.H{"error": err.Error()})
		return
	}
	h.recordAudit(c, "report.template.delete", "report-template:"+id.String(), "accepted")
	c.Status(http.StatusNoContent)
}

func (h *ReportHandler) generateReport(c *gin.Context) {
	var req struct {
		TaskID     string `json:"task_id" binding:"required"`
		TemplateID string `json:"template_id" binding:"required"`
		Format     string `json:"format"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	taskID, err := uuid.Parse(req.TaskID)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid task_id"})
		return
	}
	templateID, err := uuid.Parse(req.TemplateID)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid template_id"})
		return
	}
	tmpl, err := h.Templates.Get(templateID)
	if err != nil {
		status := http.StatusBadRequest
		if errors.Is(err, reporttemplates.ErrNotFound) {
			status = http.StatusNotFound
		}
		c.JSON(status, gin.H{"error": err.Error()})
		return
	}
	format := strings.ToLower(strings.TrimSpace(req.Format))
	if format == "" {
		format = strings.ToLower(tmpl.Format)
	}
	ctx := c.Request.Context()
	task, run, exec, err := h.loadExecution(ctx, taskID)
	if err != nil {
		status := http.StatusInternalServerError
		if errors.Is(err, store.ErrNotFound) {
			status = http.StatusNotFound
		}
		c.JSON(status, gin.H{"error": err.Error()})
		return
	}
	data := map[string]any{
		"task":         task,
		"run":          run,
		"result":       exec,
		"generated_at": time.Now().UTC(),
		"template":     tmpl,
	}
	switch format {
	case "json":
		c.Header("Content-Type", "application/json")
		c.JSON(http.StatusOK, data)
	case "html":
		buf := bytes.Buffer{}
		t, err := template.New(tmpl.Name).Parse(tmpl.Body)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid template body"})
			return
		}
		if err := t.Execute(&buf, data); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		c.Header("Content-Type", "text/html; charset=utf-8")
		c.Header("Content-Disposition", fmt.Sprintf(`attachment; filename="report-%s.html"`, taskID))
		_, _ = c.Writer.Write(buf.Bytes())
	default:
		c.JSON(http.StatusBadRequest, gin.H{"error": "unsupported format"})
	}
	h.recordAudit(c, "report.generate"+"."+format, "task:"+taskID.String(), "completed")
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

func buildSummaryTrends(windowHours int, currentTotals, previousTotals, currentStatus, previousStatus map[string]int) *summaryTrends {
	totalTrends := combineTrends(currentTotals, previousTotals)
	statusTrends := combineTrends(currentStatus, previousStatus)
	if len(totalTrends) == 0 && len(statusTrends) == 0 {
		return nil
	}
	return &summaryTrends{
		Period: fmt.Sprintf("较前 %d 小时", windowHours),
		Totals: totalTrends,
		Status: statusTrends,
	}
}

func combineTrends(current map[string]int, previous map[string]int) map[string]metricTrend {
	if len(current) == 0 && len(previous) == 0 {
		return nil
	}
	result := make(map[string]metricTrend)
	for key := range previous {
		result[key] = metricTrendFrom(current[key], previous[key])
	}
	for key := range current {
		if _, exists := result[key]; exists {
			continue
		}
		result[key] = metricTrendFrom(current[key], previous[key])
	}
	return result
}

func metricTrendFrom(current int, previous int) metricTrend {
	if previous == 0 {
		if current == 0 {
			return metricTrend{Delta: 0, Trend: "flat"}
		}
		return metricTrend{Delta: 100, Trend: "up"}
	}
	change := float64(current-previous) / float64(previous) * 100
	change = math.Round(change*10) / 10
	direction := "flat"
	switch {
	case change > 0:
		direction = "up"
	case change < 0:
		direction = "down"
	}
	return metricTrend{Delta: change, Trend: direction}
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

func parseWindowHours(raw string, fallback int) int {
	if fallback <= 0 {
		fallback = 24
	}
	if raw == "" {
		return fallback
	}
	v, err := strconv.Atoi(raw)
	if err != nil {
		return fallback
	}
	if v < 1 {
		return fallback
	}
	if v > 168 {
		return 168
	}
	return v
}

func (h *ReportHandler) loadExecution(ctx context.Context, taskID uuid.UUID) (*model.Task, *model.TaskRun, *model.ExecutionResult, error) {
	task, err := h.Store.GetTask(ctx, taskID)
	if err != nil {
		return nil, nil, nil, err
	}
	run, err := h.Store.GetLatestTaskRun(ctx, taskID)
	if err != nil {
		return nil, nil, nil, err
	}
	var exec model.ExecutionResult
	if len(run.Summary) > 0 {
		if err := json.Unmarshal(run.Summary, &exec); err != nil {
			return nil, nil, nil, err
		}
	}
	return task, run, &exec, nil
}
