package sbom

import (
	"github.com/CycloneDX/cyclonedx-go"
	cdx "github.com/CycloneDX/cyclonedx-go"
)

// Component 解析出来的结果
type Component struct {
	// 父组件 目前java会有 更新到java组件中了 这里只存放 组件结果
	//Parent Parent
	BomRef string `json:"bom-ref"`
	// 一般java会有
	GroupId string `json:"group"`
	// scope 也是一般java会有
	Scope cdx.Scope `json:"scope"`
	// 类型都是library
	Type         cyclonedx.ComponentType `json:"type"`
	Author       string                  `json:"author"`
	Name         string                  `json:"name"`
	Version      string                  `json:"version"`
	Dependencies []*Component            `json:"dependencies"`
	// 是否是开发依赖
	Develop bool `json:"develop"`
	// 描述
	Description string
	Purl        string             `json:"purl"`
	Licenses    cyclonedx.Licenses `json:"licenses"`
	Hashes      *[]cyclonedx.Hash  `json:"hashes"`
	// todo 需要删除
	// 真实版本 类似 ~= 2.2.3 >=3.1.3，后续msec官网会开放接口
	// 方便传到msec后端进行更详细的检测，获取到版本范围内最新得版本
	CompleteVersion string `json:"complete_version"`
	// 添加一个语言类型 生成purl的时候要用到
	PurlType string
	// key value 类型的值
	KeyMap map[string]string
}
