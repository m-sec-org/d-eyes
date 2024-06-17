package sbom

import (
	"github.com/CycloneDX/cyclonedx-go"
	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/m-sec-org/d-eyes/internal/constant"
	"github.com/package-url/packageurl-go"
)

type Result struct {
	// 项目目录
	FileDirectory string
	// 开始时间
	StartTime string
	// 结束时间
	EndTime string
	// 耗时
	TimeConsuming string
	// 生成的文件数,主要是在同一个项目下面 有多种语言的依赖去进行解析，解析完合并依赖，到最后进行生成文件
	// 和下面的ResultComponent 长度一样
	CreateFile      int32
	ResultComponent []ResultComponent
	Files           []FileInfoUse
	// 输出文件地址
	OutFilePath string
	err         error
}

type ResultComponent struct {
	LanguageType constant.LanguageType
	Component    []*Component
	// 检测的依赖文件数,主要是考虑到同一个文件路径下可能存在多个项目的依赖
	// 解析多个文件合并出来一个sbom
	Files []FileInfoUse
}

type FileInfoUse struct {
	FileSize int64
	// 这是目录+文件名
	FileFullPath string
	FileName     string
}

func (com *ResultComponent) Add() {
	for _, c := range com.Component {
		c.Type = cyclonedx.ComponentTypeLibrary
		var qualifier []packageurl.Qualifier
		if len(c.KeyMap) > 0 {
			for s, s2 := range c.KeyMap {
				qualifier = append(qualifier, packageurl.Qualifier{
					Key:   s,
					Value: s2,
				})
			}
		}
		switch c.PurlType {
		case constant.TypePyPi:
			{
				purl := packageurl.NewPackageURL(
					packageurl.TypePyPi,
					"",
					c.Name,
					c.Version,
					qualifier,
					"",
				).String()
				c.BomRef = purl
				c.Purl = purl
			}
		case constant.TypeMaven:
			{
				purl := packageurl.NewPackageURL(
					packageurl.TypeMaven,
					c.GroupId,
					c.Name,
					c.Version,
					qualifier,
					"",
				).String()
				c.BomRef = purl
				c.Purl = purl
			}
		}
	}
}
func (com *ResultComponent) Cover() []cdx.Component {
	var resCdx []cdx.Component
	for _, c := range com.Component {
		resCdx = append(resCdx, cdx.Component{
			Type:        c.Type,
			Name:        c.Name,
			Version:     c.Version,
			Scope:       c.Scope,
			Description: c.Description,
			Hashes:      c.Hashes,
			Licenses:    &c.Licenses,
			PackageURL:  c.Purl,
			BOMRef:      c.Purl,
		})
	}
	return resCdx
}
