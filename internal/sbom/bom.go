package sbom

import (
	"github.com/CycloneDX/cyclonedx-go"
	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/google/uuid"
	"github.com/m-sec-org/d-eyes/internal/constant"
	"time"
)

// NewMsecSbom 获取组件依赖关系表，和组件版本范围内最新的组件版本，请对接msec sbom分析接口
func NewMsecSbom() *cyclonedx.BOM {
	return &cyclonedx.BOM{
		SerialNumber: uuid.New().String(),
		BOMFormat:    constant.BOMFormat,
		SpecVersion:  cyclonedx.SpecVersion1_5,
		Version:      1,
	}
}

func NewMetadata() *cdx.Metadata {
	return &cdx.Metadata{
		Timestamp: time.Now().Format("2006-01-02T15:04:05Z"),
	}
}
