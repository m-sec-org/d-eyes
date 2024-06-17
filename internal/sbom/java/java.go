package java

import (
	"context"
	"fmt"
	"github.com/m-sec-org/d-eyes/internal"
	"github.com/m-sec-org/d-eyes/internal/constant"
	"github.com/m-sec-org/d-eyes/internal/sbom"
	"github.com/m-sec-org/d-eyes/pkg/color"
	"slices"
)

func init() {
	javaSbom := NewJavaSbom()
	internal.RegisterSbomLanguage(javaSbom)
}

var FileParse []string

type Sbom struct {
	UseCheckFiles []sbom.FileInfoUse
}

func NewJavaSbom() *Sbom {
	return &Sbom{}
}

func (s *Sbom) Language() string {
	return constant.Java.String()
}

func (s *Sbom) FileCheck(FileName string) bool {
	// 检查绝对路径 获取绝对路径的文件名 看是否符合给定的文件名
	if slices.Contains(FileParse, FileName) {
		return true
	}
	return false
}
func (s *Sbom) AddFile(file sbom.FileInfoUse) {
	s.UseCheckFiles = append(s.UseCheckFiles, file)
}

func (s *Sbom) MsecSbom(ctx context.Context) []sbom.ResultComponent {
	var resCom []sbom.ResultComponent
	for _, javaPlugin := range AllPluginJava {
		for _, file := range s.UseCheckFiles {
			if javaPlugin.FileCheck(file.FileName) {
				javaPlugin.AddFile(file)
			}
		}
		parse, err := javaPlugin.Parse(ctx)
		if err != nil {
			fmt.Println(color.Red.Sprintf("%s 解析失败", javaPlugin.PluginName()))
		} else {
			resCom = append(resCom, parse...)
		}
	}
	return resCom
}

var AllPluginJava []PluginJava

// PluginJava java检测插件
type PluginJava interface {
	Parse(context.Context) ([]sbom.ResultComponent, error)
	FileCheck(string) bool
	GetCheckFile() string
	AddFile(sbom.FileInfoUse)
	PluginName() string
}

func RegisterPluginJava(java PluginJava) {
	AllPluginJava = append(AllPluginJava, java)
	FileParse = append(FileParse, java.GetCheckFile())
}
