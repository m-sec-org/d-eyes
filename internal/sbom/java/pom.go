package java

import (
	"context"
	"encoding/xml"
	"fmt"
	"github.com/CycloneDX/cyclonedx-go"
	"github.com/m-sec-org/d-eyes/internal/constant"
	"github.com/m-sec-org/d-eyes/internal/sbom"
	"github.com/m-sec-org/d-eyes/internal/utils"
	"github.com/m-sec-org/d-eyes/pkg/color"
	"github.com/package-url/packageurl-go"
	"io"
	"os"
	"slices"
	"strings"
)

func init() {
	RegisterPluginJava(NewParsePom())
}

type ParsePoms struct {
	FileName  string
	CheckFile []sbom.FileInfoUse
}

func NewParsePom() *ParsePoms {
	return &ParsePoms{
		FileName:  "pom.xml",
		CheckFile: make([]sbom.FileInfoUse, 0),
	}
}

func (pom *ParsePoms) FileCheck(fileName string) bool {
	if strings.TrimSpace(fileName) == pom.FileName {
		return true
	} else {
		return false
	}
}

func (pom *ParsePoms) GetCheckFile() string {
	return pom.FileName
}
func (pom *ParsePoms) Parse(ctx context.Context) ([]sbom.ResultComponent, error) {
	var resultComponent []sbom.ResultComponent
	var projects []*Project
	for _, file := range pom.CheckFile {
		pom, err := parsePom(ctx, file)
		if err != nil {
			fmt.Println(color.Magenta.Sprint(err.Error()))
			continue
		}
		projects = append(projects, pom)
	}
	projectTemp, err := parseModules(ctx, projects)
	if err != nil {
		return []sbom.ResultComponent{}, err
	}
	for _, project := range projectTemp {
		var ResultComponentTemp sbom.ResultComponent
		componentUtils, uses := project.coverToComponentUtils()
		ResultComponentTemp.Component = componentUtils
		ResultComponentTemp.Files = uses
		ResultComponentTemp.LanguageType = constant.Java
		resultComponent = append(resultComponent, ResultComponentTemp)
	}
	return resultComponent, nil
}

func (pom *ParsePoms) AddFile(file sbom.FileInfoUse) {
	pom.CheckFile = append(pom.CheckFile, file)
}

func (pom *ParsePoms) PluginName() string {
	return "pom插件"
}

type Project struct {
	XMLName              xml.Name     `xml:"project"`
	Parent               Parent       `xml:"parent"`
	GroupId              string       `xml:"groupId"`
	ArtifactId           string       `xml:"artifactId"`
	Version              string       `xml:"version"`
	Description          string       `xml:"description"`
	Licenses             []License    `xml:"licenses>license"`
	Dependencies         []Dependency `xml:"dependencies>dependency"`
	Properties           Properties   `xml:"properties"`
	DependencyManagement []Dependency `xml:"dependencyManagement>dependencies>dependency"`
	Modules              []string     `xml:"modules>module"`
	File                 sbom.FileInfoUse
	Child                []*Project
}

func (project *Project) addVersion() {
	if len(project.DependencyManagement) > 0 {
		for index, dependency := range project.DependencyManagement {
			if strings.Contains(dependency.Version, "$") {
				versionString := dependency.Version[2 : len(dependency.Version)-1]
				s, ok := project.Properties.Entries[versionString]
				if ok {
					project.DependencyManagement[index].Version = s
				} else {
					project.DependencyManagement[index].Version = ""
				}
			}
			if dependency.Type == "" {
				project.DependencyManagement[index].Type = "jar"
			} else {
				project.DependencyManagement[index].Type = dependency.Type
			}
		}
	}
	if len(project.Dependencies) > 0 {
		for index, dependency := range project.Dependencies {
			if dependency.Type == "" {
				project.Dependencies[index].Type = "jar"
			} else {
				project.Dependencies[index].Type = dependency.Type
			}
			if dependency.Version == "${project.version}" && project.Parent.Version != "" {
				project.Dependencies[index].Version = project.Parent.Version
			}
			if dependency.Version == "${project.version}" && project.Parent.Version == "" {
				project.Dependencies[index].Version = ""
			}
		}
	}
}

func (project *Project) checkParent() bool {
	if project.Parent.Version == "" && project.Parent.GroupId == "" && project.Parent.ArtifactId == "" {
		return false
	}
	return true
}
func (project *Project) addChild(p *Project) {
	project.Child = append(project.Child, p)
}
func (project *Project) parseChild(p *Project) {
	// Project的Child  转化为 Component

}
func (project *Project) coverToComponent() []*sbom.Component {
	// Project 转化为 Component
	var components []*sbom.Component

	if project.checkParent() {
		// 有 Parent
		component, b := coverComponent(project.Parent)
		if b {
			components = append(components, &component)
		}
	}
	if len(project.DependencyManagement) > 0 {
		for _, dependency := range project.DependencyManagement {
			component, b := coverComponent(dependency)
			if b {
				components = append(components, &component)
			}
		}
	}
	if len(project.Dependencies) > 0 {
		for _, dependency := range project.Dependencies {
			component, b := coverComponent(dependency)
			if b {
				components = append(components, &component)
			}
		}
	}
	var componentTemp sbom.Component
	var purl *packageurl.PackageURL
	componentTemp.Type = cyclonedx.ComponentTypeLibrary
	componentTemp.GroupId = project.GroupId
	componentTemp.Name = project.ArtifactId
	componentTemp.Version = project.Version
	purl = packageurl.NewPackageURL(
		packageurl.TypeMaven,    // 包类型，例如：maven, npm, pypi, etc.
		project.GroupId,         // 命名空间
		project.ArtifactId,      // 包名
		project.Version,         // 版本
		packageurl.Qualifiers{}, // 附加的参数（可选）
		"",                      // 子路径（可选）
	)
	componentTemp.Purl = purl.String()
	componentTemp.BomRef = purl.String()
	components = append(components, &componentTemp)
	return components
}

func (project *Project) coverToComponentUtils() ([]*sbom.Component, []sbom.FileInfoUse) {
	// 一般来说 这里的都是顶层pom 不会有Parent 但是不排除某些项目存在 Parent 这里分两种情况
	// 1.第一种就是网络良好的情况 尝试下载Parent pom 文件再去解析这个pom文件 把这个pom文件解析结果添加到 Child 再去获取组件
	// 2.网络不好的情况下 直接忽略 Parent 把 Parent 当一个组件进行处理
	var res []*sbom.Component
	var file []sbom.FileInfoUse
	file = append(file, project.File)
	if project.checkParent() {
		// 有 Parent
		if constant.NetWork && project.Parent.Version != "" && project.Parent.GroupId != "" && project.Parent.ArtifactId != "" {
			// 网络正常,尝试下载 pom文件
			pomUrl := fmt.Sprintf("%s%s/%s/%s/%s-%s.pom", constant.JavaMaven, strings.ReplaceAll(project.Parent.GroupId, ".", "/"), project.Parent.ArtifactId, project.Parent.Version, project.Parent.ArtifactId, project.Parent.Version)
			data, err := utils.DownloadFile(pomUrl)
			if err != nil {
				// 下载出错 按照 没有Parent处理
				component := project.coverToComponent()
				res = append(res, component...)
				if len(project.Child) > 0 {
					for _, child := range project.Child {
						child.coverToComponentUtils()
						file = append(file, child.File)
					}
				}
				return res, file
			} else {
				// 下载成功
				var project1 Project
				err = xml.Unmarshal(data, &project1)
				if err != nil {
				}
				project1.addVersion()
				project1.addChild(project)
				component := project1.coverToComponent()
				res = append(res, component...)
				return res, file
			}
		} else {
			// 网络异常直接 把 Parent当作一个组件进行处理
			component := project.coverToComponent()
			res = append(res, component...)
			if len(project.Child) > 0 {
				for _, child := range project.Child {
					child.coverToComponentUtils()
					file = append(file, child.File)
				}
			}
			return res, file
		}
	} else {
		// 无 Parent
		component := project.coverToComponent()
		res = append(res, component...)
		if len(project.Child) > 0 {
			for _, child := range project.Child {
				child.coverToComponentUtils()
				file = append(file, child.File)
			}
		}
		return res, file
	}
}

type Properties struct {
	Entries map[string]string `xml:",any"`
}

func (p *Properties) UnmarshalXML(d *xml.Decoder, start xml.StartElement) error {
	p.Entries = make(map[string]string)
	for {
		// Read the next token
		token, err := d.Token()
		if err != nil {
			break
		}

		// Check if the token is a start element
		switch element := token.(type) {
		case xml.StartElement:
			// Read the element name and its content
			var value string
			if err := d.DecodeElement(&value, &element); err != nil {
				return err
			}
			p.Entries[element.Name.Local] = value
		case xml.EndElement:
			// Break the loop if we reach the end of properties element
			if element.Name.Local == start.Name.Local {
				return nil
			}
		}
	}
	return nil
}

type Parent struct {
	GroupId     string `xml:"groupId"`
	ArtifactId  string `xml:"artifactId"`
	Version     string `xml:"version"`
	Description string `xml:"description"`
}

type License struct {
	Name string `xml:"name"`
}

type Dependency struct {
	GroupId    string `xml:"groupId"`
	ArtifactId string `xml:"artifactId"`
	Version    string `xml:"version"`
	Scope      string `xml:"scope"`
	Type       string `xml:"type"`
}

func coverComponent[T Dependency | Parent](value T) (sbom.Component, bool) {

	switch v := any(value).(type) {
	case Dependency:
		var componentTemp sbom.Component
		componentTemp.Type = cyclonedx.ComponentTypeLibrary
		componentTemp.GroupId = v.GroupId
		componentTemp.Name = v.ArtifactId
		componentTemp.Version = v.Version
		var purl *packageurl.PackageURL
		if v.Scope != "" && v.Type != "" {
			purl = packageurl.NewPackageURL(
				packageurl.TypeMaven, // 包类型，例如：maven, npm, pypi, etc.
				v.GroupId,            // 命名空间
				v.ArtifactId,         // 包名
				v.Version,            // 版本
				packageurl.Qualifiers{{
					"scope", v.Scope,
				}, {
					"type", v.Type,
				}}, // 附加的参数（可选）
				"", // 子路径（可选）
			)
		}
		if v.Scope != "" {
			purl = packageurl.NewPackageURL(
				packageurl.TypeMaven, // 包类型，例如：maven, npm, pypi, etc.
				v.GroupId,            // 命名空间
				v.ArtifactId,         // 包名
				v.Version,            // 版本
				packageurl.Qualifiers{{
					"scope", v.Scope,
				}}, // 附加的参数（可选）
				"", // 子路径（可选）
			)
		}
		if v.Type != "" {
			purl = packageurl.NewPackageURL(
				packageurl.TypeMaven, // 包类型，例如：maven, npm, pypi, etc.
				v.GroupId,            // 命名空间
				v.ArtifactId,         // 包名
				v.Version,            // 版本
				packageurl.Qualifiers{{
					"type", v.Type,
				}}, // 附加的参数（可选）
				"", // 子路径（可选）
			)
		}
		if v.Scope == "" && v.Type == "" {
			purl = packageurl.NewPackageURL(
				packageurl.TypeMaven,    // 包类型，例如：maven, npm, pypi, etc.
				v.GroupId,               // 命名空间
				v.ArtifactId,            // 包名
				v.Version,               // 版本
				packageurl.Qualifiers{}, // 附加的参数（可选）
				"",                      // 子路径（可选）
			)
		}
		componentTemp.Purl = purl.String()
		componentTemp.BomRef = purl.String()
		return componentTemp, true
	case Parent:
		var componentTemp sbom.Component
		var purl *packageurl.PackageURL
		componentTemp.Type = cyclonedx.ComponentTypeLibrary
		componentTemp.GroupId = v.GroupId
		componentTemp.Name = v.ArtifactId
		componentTemp.Version = v.Version
		purl = packageurl.NewPackageURL(
			packageurl.TypeMaven,    // 包类型，例如：maven, npm, pypi, etc.
			v.GroupId,               // 命名空间
			v.ArtifactId,            // 包名
			v.Version,               // 版本
			packageurl.Qualifiers{}, // 附加的参数（可选）
			"",                      // 子路径（可选）
		)
		componentTemp.Purl = purl.String()
		componentTemp.BomRef = purl.String()
		return componentTemp, true
	default:
		return sbom.Component{}, false
	}
}
func parsePom(context context.Context, file sbom.FileInfoUse) (*Project, error) {
	var project Project
	project.File = file
	f, err := os.Open(file.FileFullPath)
	if err != nil {
		return nil, err
	}
	defer func(f *os.File) {
		err := f.Close()
		if err != nil {

		}
	}(f)
	data, _ := io.ReadAll(f)

	err = xml.Unmarshal(data, &project)
	if err != nil {
		return nil, err
	}
	project.addVersion()
	return &project, nil
}
func parseModules(context context.Context, projects []*Project) ([]*Project, error) {
	var remove []*Project
	for index, project := range projects {
		if len(project.Modules) > 0 {
			for _, p := range projects {
				if slices.Contains(project.Modules, p.ArtifactId) {
					projects[index].addChild(p)
					remove = append(remove, p)
				}
			}
		}
	}
	person1 := removePerson(projects, remove)
	return person1, nil
}
func removePerson(projects []*Project, target []*Project) []*Project {
	var newPeople []*Project
	for _, person := range projects {
		if slices.Contains(target, person) {
		} else {
			newPeople = append(newPeople, person)
		}
	}
	return newPeople
}
