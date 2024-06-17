package python

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
	pythonSbom := NewPythonSbom()
	internal.RegisterSbomLanguage(pythonSbom)
}

type Sbom struct {
	UseCheckFiles []sbom.FileInfoUse
}

func NewPythonSbom() *Sbom {
	return &Sbom{}
}

func (s *Sbom) Language() string {
	return constant.Python.String()
}

func (s *Sbom) FileCheck(FileName string) bool {
	if slices.Contains(FileParse, FileName) {
		return true
	}
	return false
}

func (s *Sbom) MsecSbom(ctx context.Context) []sbom.ResultComponent {
	var resCom []sbom.ResultComponent
	for _, file := range s.UseCheckFiles {
		for _, pythonPlugin := range AllPluginPython {
			if pythonPlugin.FileCheck(file.FileName) {
				parse, err := pythonPlugin.Parse(ctx, file)
				if err != nil {
					// 文件%s解析失败
					fmt.Println(color.Red.Sprintf("Failed to parse the %s file", file.FileName))
				} else {
					resCom = append(resCom, parse)
				}
			}
		}
	}
	return resCom
}

var FileParse []string

func (s *Sbom) AddFile(file sbom.FileInfoUse) {
	s.UseCheckFiles = append(s.UseCheckFiles, file)
}

var AllPluginPython []PluginPython

// PluginPython python检测插件
type PluginPython interface {
	Parse(context.Context, sbom.FileInfoUse) (sbom.ResultComponent, error)
	FileCheck(string) bool
	GetCheckFile() string
}

func RegisterPluginPython(python PluginPython) {
	AllPluginPython = append(AllPluginPython, python)
	FileParse = append(FileParse, python.GetCheckFile())
}
