package scoring

import (
	"strings"
)

// RiskScore summarises quantified risk.
type RiskScore struct {
	Total     float64        `json:"total"`
	Level     string         `json:"level"`
	Breakdown ScoreBreakdown `json:"breakdown"`
}

// ScoreBreakdown stores component contribution.
type ScoreBreakdown struct {
	Severity    float64 `json:"severity"`
	Prevalence  float64 `json:"prevalence"`
	Exploitable float64 `json:"exploitable"`
	Impact      float64 `json:"impact"`
}

// ScoreHints derived from metadata or rule naming.
type ScoreHints struct {
	Severity   string
	Category   string
	Threat     string
	Confidence float64
}

// RemediationPlan enumerates recovery steps.
type RemediationPlan struct {
	Priority   string            `json:"priority"`
	Steps      []RemediationStep `json:"steps"`
	References []string          `json:"references"`
}

// RemediationStep describes single actionable hint.
type RemediationStep struct {
	Action      string `json:"action"`
	Description string `json:"description"`
	Command     string `json:"command,omitempty"`
}

// Calculate determines risk score using heuristics.
func Calculate(ruleName string, hints ScoreHints, tags []string) RiskScore {
	category := resolveCategory(ruleName, hints, tags)
	breakdown := ScoreBreakdown{}

	switch category {
	case "ransomware":
		breakdown.Severity = 4.0
		breakdown.Prevalence = 2.0
		breakdown.Exploitable = 1.5
		breakdown.Impact = 2.0
	case "webshell":
		breakdown.Severity = 3.3
		breakdown.Prevalence = 1.8
		breakdown.Exploitable = 1.5
		breakdown.Impact = 1.5
	case "botnet":
		breakdown.Severity = 3.5
		breakdown.Prevalence = 1.7
		breakdown.Exploitable = 1.7
		breakdown.Impact = 1.8
	case "coinminer":
		breakdown.Severity = 2.5
		breakdown.Prevalence = 1.8
		breakdown.Exploitable = 1.6
		breakdown.Impact = 1.2
	default:
		breakdown.Severity = 2.0
		breakdown.Prevalence = 1.0
		breakdown.Exploitable = 1.0
		breakdown.Impact = 1.0
	}

	total := breakdown.Severity*2.5 + breakdown.Prevalence + breakdown.Exploitable + breakdown.Impact
	level := classify(total)

	return RiskScore{
		Total:     round(total, 1),
		Level:     level,
		Breakdown: breakdown,
	}
}

func classify(score float64) string {
	switch {
	case score >= 9:
		return "Critical"
	case score >= 7.5:
		return "High"
	case score >= 5:
		return "Medium"
	case score > 0:
		return "Low"
	default:
		return "Informational"
	}
}

func round(value float64, decimals int) float64 {
	pow := 1.0
	for i := 0; i < decimals; i++ {
		pow *= 10
	}
	return float64(int(value*pow+0.5)) / pow
}

func resolveCategory(ruleName string, hints ScoreHints, tags []string) string {
	ruleLower := strings.ToLower(ruleName)
	if hints.Category != "" {
		return hints.Category
	}
	for _, tag := range tags {
		tagLower := strings.ToLower(tag)
		switch {
		case strings.Contains(tagLower, "ransom"):
			return "ransomware"
		case strings.Contains(tagLower, "webshell"):
			return "webshell"
		case strings.Contains(tagLower, "miner"):
			return "coinminer"
		case strings.Contains(tagLower, "botnet"):
			return "botnet"
		}
	}
	switch {
	case strings.Contains(ruleLower, "ransom"):
		return "ransomware"
	case strings.Contains(ruleLower, "webshell"):
		return "webshell"
	case strings.Contains(ruleLower, "botnet"):
		return "botnet"
	case strings.Contains(ruleLower, "coin") || strings.Contains(ruleLower, "miner"):
		return "coinminer"
	default:
		return "generic-malware"
	}
}

// ResolveRemediation returns category oriented response steps.
func ResolveRemediation(ruleName string, tags []string) RemediationPlan {
	category := resolveCategory(ruleName, ScoreHints{}, tags)
	plan := RemediationPlan{}

	switch category {
	case "ransomware":
		plan.Priority = "critical"
		plan.Steps = []RemediationStep{
			{Action: "isolate", Description: "立即隔离受感染主机，阻断对内外部网络访问"},
			{Action: "preserve", Description: "采集关键日志和内存镜像以用于取证"},
			{Action: "kill-process", Description: "查杀相关恶意进程，清理计划任务和自启动项"},
			{Action: "restore", Description: "从可信备份恢复业务系统，复核最近的权限变更"},
		}
		plan.References = []string{
			"https://www.cisa.gov/stopransomware",
			"https://msec.nsfocus.com",
		}
	case "webshell":
		plan.Priority = "high"
		plan.Steps = []RemediationStep{
			{Action: "backup", Description: "备份站点目录和日志，保留证据"},
			{Action: "eradicate", Description: "删除 Webshell 文件，修复上传/执行漏洞"},
			{Action: "reset-secret", Description: "更换网站后台、数据库等敏感凭据"},
			{Action: "hardening", Description: "加强 WAF/主机防护策略及巡检"},
		}
	case "botnet":
		plan.Priority = "high"
		plan.Steps = []RemediationStep{
			{Action: "network-block", Description: "阻断恶意C2通信，封禁可疑IP/域名"},
			{Action: "process-analysis", Description: "定位并清除注入进程和落地文件"},
			{Action: "patch", Description: "修复被利用的远程服务漏洞"},
		}
	case "coinminer":
		plan.Priority = "medium"
		plan.Steps = []RemediationStep{
			{Action: "resource-monitor", Description: "识别高CPU/内存占用进程并终止"},
			{Action: "cleanup", Description: "清理挖矿脚本、计划任务和定时下载器"},
			{Action: "baseline", Description: "校准服务器SSH/密钥策略，增强口令安全"},
		}
	default:
		plan.Priority = "medium"
		plan.Steps = []RemediationStep{
			{Action: "analyse", Description: "分析样本行为，评估影响范围"},
			{Action: "eradicate", Description: "删除恶意文件与残留项"},
		}
	}
	return plan
}
