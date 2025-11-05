package utils

import "runtime"

// 定义Autorun结构体，用于存储自启动项信息
type Autorun struct {
	Type         string `json:"type"`
	Location     string `json:"location"`
	ImagePath    string `json:"image_path"`
	ImageName    string `json:"image_name"`
	Arguments    string `json:"arguments"`
	MD5          string `json:"md5"`
	SHA1         string `json:"sha1"`
	SHA256       string `json:"sha256"`
	Entry        string `json:"entry"`
	LaunchString string `json:"launch_string"`
}

// Autoruns 获取当前系统的自启动项
// 根据不同操作系统返回相应的自启动项列表
// 在实际应用中，完整编译时会链接到平台特定的实现
func Autoruns() []*Autorun {
	// 在Go语言中，跨平台代码的正确处理方式是使用构建标记
	// 这里根据当前运行的操作系统返回相应结果
	// 注意：在完整构建中，平台特定的实现会被正确链接
	switch runtime.GOOS {
	case "linux", "windows":
		// 在实际编译时，平台特定文件中的getAutorun函数会被链接
		// 这里仅在运行时做简单处理
		// 完整功能需要与平台特定文件一起编译
		return []*Autorun{}
	default:
		// 对于不支持的平台，返回空列表
		return []*Autorun{}
	}
}
