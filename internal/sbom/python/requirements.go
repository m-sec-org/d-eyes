package python

import (
	"bufio"
	"context"
	"github.com/m-sec-org/d-eyes/internal/constant"
	"github.com/m-sec-org/d-eyes/internal/sbom"
	"github.com/m-sec-org/d-eyes/internal/utils"

	"os"
	"strings"
)

func init() {
	RegisterPluginPython(NewParseRequirements())
}

type ParseRequirements struct {
	FileName  string
	CheckFile []sbom.FileInfoUse
}

func NewParseRequirements() *ParseRequirements {
	return &ParseRequirements{
		FileName:  "requirements.txt",
		CheckFile: make([]sbom.FileInfoUse, 0),
	}
}

func (python *ParseRequirements) FileCheck(fileName string) bool {
	if strings.TrimSpace(fileName) == python.FileName {
		return true
	} else {
		return false
	}
}
func (python *ParseRequirements) GetCheckFile() string {
	return python.FileName
}

func (python *ParseRequirements) Parse(_ context.Context, file sbom.FileInfoUse) (sbom.ResultComponent, error) {
	var resCom sbom.ResultComponent
	f, err := os.Open(file.FileFullPath)
	if err != nil {
		return sbom.ResultComponent{}, nil
	}
	defer func(f *os.File) {
		err := f.Close()
		if err != nil {

		}
	}(f)

	resCom.Files = append(resCom.Files, file)
	resCom.LanguageType = constant.Python

	requirements := parseRequirements(f)
	resCom.Component = requirements
	return resCom, nil
}

type Library struct {
	Name            string
	Constraint      string
	Version         string
	CompleteVersion string
}

func parseRequirements(f *os.File) []*sbom.Component {

	var libraries []*sbom.Component

	scanner := bufio.NewScanner(f)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if strings.HasPrefix(strings.TrimSpace(line), "#") {
			// Ignore comment lines
			continue
		}

		semiSplit := strings.SplitN(line, ";", 2)

		line = semiSplit[0]

		constraint := ""
		version := ""
		name := line
		constraintIndex := strings.IndexAny(line, "<>==~")

		if constraintIndex != -1 {
			name = strings.TrimSpace(line[:constraintIndex])
			versions := strings.TrimSpace(line[constraintIndex:])
			spaceIndex := strings.Index(versions, " ")
			if spaceIndex != -1 {
				constraint = versions[:spaceIndex]
				version = versions[spaceIndex+1:]
			} else {
				constraint = versions
			}
		}
		if strings.Contains(name, "[") {
			split := strings.Split(name, "[")
			name = strings.Trim(split[0], " ")
		}
		library := sbom.Component{Name: name, CompleteVersion: constraint + version, PurlType: constant.TypePyPi}
		libraries = append(libraries, &library)
	}

	if err := scanner.Err(); err != nil {
		return nil
	}
	// 解析版本
	for _, requirement := range libraries {
		version, err1 := utils.ParseVersion(requirement.CompleteVersion)
		if err1 != nil {
			// 版本解析失败
			requirement.Version = version
		} else {
			requirement.Version = version
		}
	}
	return libraries
}
