//go:build linux || windows || darwin

package config

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

// ConfigType 配置文件类型
type ConfigType string

const (
	ConfigTypeYAML ConfigType = "yaml"
	ConfigTypeJSON ConfigType = "json"
)

// BaseConfig 基础配置结构
type BaseConfig struct {
	// 检查项配置
	CheckItems map[string]CheckItemConfig `yaml:"check_items" json:"check_items"`
	// 扫描配置
	ScanConfig ScanConfig `yaml:"scan_config" json:"scan_config"`
	// 平台特定配置
	PlatformConfig map[string]interface{} `yaml:"platform_config" json:"platform_config"`
}

// CheckItemConfig 检查项配置
type CheckItemConfig struct {
	// 是否启用
	Enabled bool `yaml:"enabled" json:"enabled"`
	// 风险级别
	Severity string `yaml:"severity" json:"severity"`
	// 检查参数
	Params map[string]interface{} `yaml:"params" json:"params"`
	// 自定义规则
	CustomRules []string `yaml:"custom_rules" json:"custom_rules"`
}

// ScanConfig 扫描配置
type ScanConfig struct {
	// 超时时间（秒）
	Timeout int `yaml:"timeout" json:"timeout"`
	// 并发数
	Concurrency int `yaml:"concurrency" json:"concurrency"`
	// 重试次数
	RetryCount int `yaml:"retry_count" json:"retry_count"`
	// 跳过的检查项
	SkipChecks []string `yaml:"skip_checks" json:"skip_checks"`
}

// ConfigManager 配置管理器
type ConfigManager struct {
	config BaseConfig
}

// NewConfigManager 创建配置管理器
func NewConfigManager() *ConfigManager {
	return &ConfigManager{
		config: BaseConfig{
			CheckItems:     make(map[string]CheckItemConfig),
			PlatformConfig: make(map[string]interface{}),
			ScanConfig: ScanConfig{
				Timeout:     300,
				Concurrency: 5,
				RetryCount:  1,
				SkipChecks:  make([]string, 0),
			},
		},
	}
}

// LoadConfig 加载配置文件
func (cm *ConfigManager) LoadConfig(configPath string) error {
	if configPath == "" {
		// 使用默认配置
		cm.loadDefaultConfig()
		return nil
	}

	// 检查文件是否存在
	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		return fmt.Errorf("配置文件不存在: %s", configPath)
	}

	// 读取文件内容
	content, err := ioutil.ReadFile(configPath)
	if err != nil {
		return fmt.Errorf("读取配置文件失败: %w", err)
	}

	// 根据文件扩展名判断配置类型
	ext := filepath.Ext(configPath)
	switch ext {
	case ".yaml", ".yml":
		err = yaml.Unmarshal(content, &cm.config)
	case ".json":
		err = json.Unmarshal(content, &cm.config)
	default:
		return fmt.Errorf("不支持的配置文件格式: %s", ext)
	}

	if err != nil {
		return fmt.Errorf("解析配置文件失败: %w", err)
	}

	// 验证配置
	return cm.validateConfig()
}

// GetConfig 获取配置
func (cm *ConfigManager) GetConfig() BaseConfig {
	return cm.config
}

// IsCheckEnabled 检查某个检查项是否启用
func (cm *ConfigManager) IsCheckEnabled(checkID string) bool {
	if checkConfig, exists := cm.config.CheckItems[checkID]; exists {
		return checkConfig.Enabled
	}
	// 默认启用
	return true
}

// GetCheckSeverity 获取检查项的风险级别
func (cm *ConfigManager) GetCheckSeverity(checkID string) string {
	if checkConfig, exists := cm.config.CheckItems[checkID]; exists && checkConfig.Severity != "" {
		return checkConfig.Severity
	}
	// 默认中等风险
	return "MEDIUM"
}

// IsCheckSkipped 检查是否跳过某个检查项
func (cm *ConfigManager) IsCheckSkipped(checkID string) bool {
	for _, skip := range cm.config.ScanConfig.SkipChecks {
		if skip == checkID {
			return true
		}
	}
	return false
}

// loadDefaultConfig 加载默认配置
func (cm *ConfigManager) loadDefaultConfig() {
	// 设置默认检查项配置
	defaultChecks := []string{
		"os_account_empty_password",
		"os_account_lockout",
		"os_ssh_config",
		"os_firewall_status",
		"os_auto_update",
	}

	for _, checkID := range defaultChecks {
		cm.config.CheckItems[checkID] = CheckItemConfig{
			Enabled:  true,
			Severity: "MEDIUM",
			Params:   make(map[string]interface{}),
		}
	}
}

// validateConfig 验证配置
func (cm *ConfigManager) validateConfig() error {
	// 验证扫描配置
	if cm.config.ScanConfig.Timeout <= 0 {
		cm.config.ScanConfig.Timeout = 300
	}
	if cm.config.ScanConfig.Concurrency <= 0 {
		cm.config.ScanConfig.Concurrency = 5
	}
	if cm.config.ScanConfig.RetryCount < 0 {
		cm.config.ScanConfig.RetryCount = 0
	}

	return nil
}
