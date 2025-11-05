//go:build linux || windows || darwin

package config

import (
	"io/ioutil"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNewConfigManager(t *testing.T) {
	configManager := NewConfigManager()
	assert.NotNil(t, configManager)

	// 验证默认配置
	config := configManager.GetConfig()
	assert.NotNil(t, config.CheckItems)
	assert.NotNil(t, config.PlatformConfig)
	assert.Equal(t, 300, config.ScanConfig.Timeout)
	assert.Equal(t, 5, config.ScanConfig.Concurrency)
	assert.Equal(t, 1, config.ScanConfig.RetryCount)
}

func TestConfigManager_LoadDefaultConfig(t *testing.T) {
	configManager := NewConfigManager()

	// 不指定配置文件路径，应该加载默认配置
	err := configManager.LoadConfig("")
	assert.NoError(t, err)

	// 验证默认配置项是否加载
	config := configManager.GetConfig()
	assert.NotEmpty(t, config.CheckItems)

	// 验证一些默认检查项
	expectedChecks := []string{
		"os_account_empty_password",
		"os_account_lockout",
		"os_ssh_config",
		"os_firewall_status",
		"os_auto_update",
	}

	for _, checkID := range expectedChecks {
		checkConfig, exists := config.CheckItems[checkID]
		assert.True(t, exists)
		assert.True(t, checkConfig.Enabled)
		assert.Equal(t, "MEDIUM", checkConfig.Severity)
	}
}

func TestConfigManager_LoadYAMLConfig(t *testing.T) {
	// 创建临时YAML配置文件
	tempDir, err := ioutil.TempDir("", "config-test")
	assert.NoError(t, err)
	defer os.RemoveAll(tempDir)

	yamlContent := `
check_items:
  test_check_1:
    enabled: true
    severity: HIGH
    params:
      key1: value1
  test_check_2:
    enabled: false
    severity: LOW
scan_config:
  timeout: 600
  concurrency: 10
  retry_count: 3
  skip_checks:
    - skip_check_1
    - skip_check_2
`

	yamlPath := filepath.Join(tempDir, "config.yaml")
	err = ioutil.WriteFile(yamlPath, []byte(yamlContent), 0644)
	assert.NoError(t, err)

	// 加载YAML配置
	configManager := NewConfigManager()
	err = configManager.LoadConfig(yamlPath)
	assert.NoError(t, err)

	// 验证配置是否正确加载
	config := configManager.GetConfig()

	// 验证check_items
	testCheck1, exists := config.CheckItems["test_check_1"]
	assert.True(t, exists)
	assert.True(t, testCheck1.Enabled)
	assert.Equal(t, "HIGH", testCheck1.Severity)
	assert.Equal(t, "value1", testCheck1.Params["key1"])

	testCheck2, exists := config.CheckItems["test_check_2"]
	assert.True(t, exists)
	assert.False(t, testCheck2.Enabled)
	assert.Equal(t, "LOW", testCheck2.Severity)

	// 验证scan_config
	assert.Equal(t, 600, config.ScanConfig.Timeout)
	assert.Equal(t, 10, config.ScanConfig.Concurrency)
	assert.Equal(t, 3, config.ScanConfig.RetryCount)
	assert.Contains(t, config.ScanConfig.SkipChecks, "skip_check_1")
	assert.Contains(t, config.ScanConfig.SkipChecks, "skip_check_2")
}

func TestConfigManager_LoadJSONConfig(t *testing.T) {
	// 创建临时JSON配置文件
	tempDir, err := ioutil.TempDir("", "config-test")
	assert.NoError(t, err)
	defer os.RemoveAll(tempDir)

	jsonContent := `{
  "check_items": {
    "test_check_1": {
      "enabled": true,
      "severity": "CRITICAL",
      "params": {
        "key1": "value1"
      }
    }
  },
  "scan_config": {
    "timeout": 120,
    "concurrency": 3,
    "retry_count": 0
  }
}`

	jsonPath := filepath.Join(tempDir, "config.json")
	err = ioutil.WriteFile(jsonPath, []byte(jsonContent), 0644)
	assert.NoError(t, err)

	// 加载JSON配置
	configManager := NewConfigManager()
	err = configManager.LoadConfig(jsonPath)
	assert.NoError(t, err)

	// 验证配置是否正确加载
	config := configManager.GetConfig()

	// 验证check_items
	testCheck1, exists := config.CheckItems["test_check_1"]
	assert.True(t, exists)
	assert.True(t, testCheck1.Enabled)
	assert.Equal(t, "CRITICAL", testCheck1.Severity)
	assert.Equal(t, "value1", testCheck1.Params["key1"])

	// 验证scan_config
	assert.Equal(t, 120, config.ScanConfig.Timeout)
	assert.Equal(t, 3, config.ScanConfig.Concurrency)
	assert.Equal(t, 0, config.ScanConfig.RetryCount)
}

func TestConfigManager_LoadConfig_FileNotFound(t *testing.T) {
	configManager := NewConfigManager()
	err := configManager.LoadConfig("nonexistent_config.yaml")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "配置文件不存在")
}

func TestConfigManager_LoadConfig_UnsupportedFormat(t *testing.T) {
	// 创建临时文件，但使用不支持的扩展名
	tempDir, err := ioutil.TempDir("", "config-test")
	assert.NoError(t, err)
	defer os.RemoveAll(tempDir)

	invalidPath := filepath.Join(tempDir, "config.txt")
	err = ioutil.WriteFile(invalidPath, []byte("test"), 0644)
	assert.NoError(t, err)

	configManager := NewConfigManager()
	err = configManager.LoadConfig(invalidPath)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "不支持的配置文件格式")
}

func TestConfigManager_LoadConfig_InvalidYAML(t *testing.T) {
	// 创建临时文件，包含无效的YAML内容
	tempDir, err := ioutil.TempDir("", "config-test")
	assert.NoError(t, err)
	defer os.RemoveAll(tempDir)

	invalidYAMLPath := filepath.Join(tempDir, "invalid.yaml")
	err = ioutil.WriteFile(invalidYAMLPath, []byte("invalid: yaml: content"), 0644)
	assert.NoError(t, err)

	configManager := NewConfigManager()
	err = configManager.LoadConfig(invalidYAMLPath)
	assert.Error(t, err)
}

func TestConfigManager_LoadConfig_InvalidJSON(t *testing.T) {
	// 创建临时文件，包含无效的JSON内容
	tempDir, err := ioutil.TempDir("", "config-test")
	assert.NoError(t, err)
	defer os.RemoveAll(tempDir)

	invalidJSONPath := filepath.Join(tempDir, "invalid.json")
	err = ioutil.WriteFile(invalidJSONPath, []byte("{invalid json}"), 0644)
	assert.NoError(t, err)

	configManager := NewConfigManager()
	err = configManager.LoadConfig(invalidJSONPath)
	assert.Error(t, err)
}

func TestConfigManager_IsCheckEnabled(t *testing.T) {
	configManager := NewConfigManager()

	// 测试默认启用
	assert.True(t, configManager.IsCheckEnabled("non_existent_check"))

	// 创建临时配置文件，设置一些检查项的启用状态
	tempDir, err := ioutil.TempDir("", "config-test")
	assert.NoError(t, err)
	defer os.RemoveAll(tempDir)

	configContent := `
check_items:
  enabled_check:
    enabled: true
  disabled_check:
    enabled: false
`

	configPath := filepath.Join(tempDir, "config.yaml")
	err = ioutil.WriteFile(configPath, []byte(configContent), 0644)
	assert.NoError(t, err)

	// 加载配置
	err = configManager.LoadConfig(configPath)
	assert.NoError(t, err)

	// 测试检查项的启用状态
	assert.True(t, configManager.IsCheckEnabled("enabled_check"))
	assert.False(t, configManager.IsCheckEnabled("disabled_check"))
	assert.True(t, configManager.IsCheckEnabled("non_existent_check")) // 默认启用
}

func TestConfigManager_GetCheckSeverity(t *testing.T) {
	configManager := NewConfigManager()

	// 测试默认风险级别
	assert.Equal(t, "MEDIUM", configManager.GetCheckSeverity("non_existent_check"))

	// 创建临时配置文件，设置一些检查项的风险级别
	tempDir, err := ioutil.TempDir("", "config-test")
	assert.NoError(t, err)
	defer os.RemoveAll(tempDir)

	configContent := `
check_items:
  critical_check:
    severity: CRITICAL
  high_check:
    severity: HIGH
`

	configPath := filepath.Join(tempDir, "config.yaml")
	err = ioutil.WriteFile(configPath, []byte(configContent), 0644)
	assert.NoError(t, err)

	// 加载配置
	err = configManager.LoadConfig(configPath)
	assert.NoError(t, err)

	// 测试检查项的风险级别
	assert.Equal(t, "CRITICAL", configManager.GetCheckSeverity("critical_check"))
	assert.Equal(t, "HIGH", configManager.GetCheckSeverity("high_check"))
	assert.Equal(t, "MEDIUM", configManager.GetCheckSeverity("non_existent_check")) // 默认中危
}

func TestConfigManager_IsCheckSkipped(t *testing.T) {
	configManager := NewConfigManager()

	// 测试默认不跳过
	assert.False(t, configManager.IsCheckSkipped("any_check"))

	// 创建临时配置文件，设置跳过的检查项
	tempDir, err := ioutil.TempDir("", "config-test")
	assert.NoError(t, err)
	defer os.RemoveAll(tempDir)

	configContent := `
scan_config:
  skip_checks:
    - skipped_check_1
    - skipped_check_2
`

	configPath := filepath.Join(tempDir, "config.yaml")
	err = ioutil.WriteFile(configPath, []byte(configContent), 0644)
	assert.NoError(t, err)

	// 加载配置
	err = configManager.LoadConfig(configPath)
	assert.NoError(t, err)

	// 测试是否跳过检查项
	assert.True(t, configManager.IsCheckSkipped("skipped_check_1"))
	assert.True(t, configManager.IsCheckSkipped("skipped_check_2"))
	assert.False(t, configManager.IsCheckSkipped("not_skipped_check"))
}

func TestConfigManager_validateConfig(t *testing.T) {
	// 测试验证配置，确保无效的配置会被修正
	configManager := &ConfigManager{
		config: BaseConfig{
			ScanConfig: ScanConfig{
				Timeout:     -1,
				Concurrency: -1,
				RetryCount:  -1,
			},
		},
	}

	// 执行验证
	err := configManager.validateConfig()
	assert.NoError(t, err)

	// 验证配置是否被正确修正
	assert.Equal(t, 300, configManager.config.ScanConfig.Timeout)   // 默认值
	assert.Equal(t, 5, configManager.config.ScanConfig.Concurrency) // 默认值
	assert.Equal(t, 0, configManager.config.ScanConfig.RetryCount)  // 修正为0
}
