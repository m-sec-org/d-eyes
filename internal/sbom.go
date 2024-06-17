package internal

import (
	"context"
	"fmt"
	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/m-sec-org/d-eyes/internal/constant"
	"github.com/m-sec-org/d-eyes/internal/sbom"
	"github.com/m-sec-org/d-eyes/internal/utils"
	"github.com/m-sec-org/d-eyes/pkg/color"
	"github.com/urfave/cli/v2"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
)

type SbomOptions struct {
	// 项目目录
	ProjectPath string
	// 具体文件所在位置
	FileFullPath string
	// 用户输入的语言类型
	LanguageType string
	// 转换后的语言类型
	//ConvertLanguageType common.LanguageType
	// 输出目录
	OutPath string
	// 输出文件类型
	OutType string
	// cdx  转换后的 输出文件类型
	OutC cdx.BOMFileFormat
}

var SbomOption SbomOptions
var SbomCommand *cli.Command

func NewSbomOptions() SbomOptions {
	return SbomOptions{}
}
func init() {
	SbomOption = NewSbomOptions()
	// 获取组件依赖关系表，和组件版本范围内最新的组件版本，请对接msec sbom分析接口
	SbomCommand = &cli.Command{
		Name:    "sbom",
		Aliases: []string{"sm"},
		// 读取依赖文件生成sbom清单
		Usage: "Read the dependency file to generate the sbom list",
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:    "path",
				Aliases: []string{"p"},
				// 检测指定目录
				Usage:       "Detect specified directory",
				Destination: &SbomOption.ProjectPath,
			},
			&cli.StringFlag{
				Name:    "file",
				Aliases: []string{"f"},
				// 检测指定文件
				Usage:       "Detect specified file",
				Destination: &SbomOption.FileFullPath,
			},
			&cli.StringFlag{
				Name:    "out",
				Aliases: []string{"o"},
				// 设置输出目录
				Usage:       "Set output directory",
				Destination: &SbomOption.OutPath,
			},
			&cli.StringFlag{
				Name:    "type",
				Aliases: []string{"t"},
				// 设置输出文件类型
				Usage:       "Set the output file type. The default output type is json",
				Destination: &SbomOption.OutType,
				// 默认生成文件类型是json
				Value: "json",
			},
		},
		Action:      runSbom,
		Subcommands: make([]*cli.Command, 0),
	}
	RegisterCommand(SbomCommand)
}

var AllSbom []MsecSbom

// RegisterSbomLanguage 注册msec文件检查插件
func RegisterSbomLanguage(m MsecSbom) {
	AllSbom = append(AllSbom, m)
}

type MsecSbom interface {
	AddFile(use sbom.FileInfoUse)
	Language() string
	FileCheck(FileName string) bool
	MsecSbom(ctx context.Context) []sbom.ResultComponent
}
type SbomSub interface {
	InitCommand() *cli.Command
	Action(c *cli.Context) error
	Parse(string string)
}

// RegisterSbomSub 注册命令检查插件
func RegisterSbomSub(s SbomSub) {
	SbomCommand.Subcommands = append(SbomCommand.Subcommands, s.InitCommand())
}
func runSbom(c *cli.Context) error {
	utils.CheckNetwork()
	defer func() {
	}()

	SbomOption.ParseSbomOption(false)

	var waitingCheckFileList []sbom.FileInfoUse
	fmt.Println(SbomOption.FileFullPath)
	if SbomOption.ProjectPath != "" {

		_ = filepath.Walk(SbomOption.ProjectPath, func(path string, info fs.FileInfo, err error) error {
			if info.IsDir() {
				// 是目录的话就跳过那几个目录
				if slices.Contains(constant.SkipDir, info.Name()) {
					// filepath.SkipDir 表示跳过这个目录
					return filepath.SkipDir
				}
				return nil
			}
			var fileInfo sbom.FileInfoUse
			fileInfo.FileSize = info.Size()
			fileInfo.FileName = info.Name()
			fileInfo.FileFullPath = path
			waitingCheckFileList = append(waitingCheckFileList, fileInfo)
			if err != nil {

			}
			return nil
		})
	}
	if SbomOption.FileFullPath != "" {

		var fileInfo sbom.FileInfoUse
		stat, err := os.Stat(SbomOption.FileFullPath)
		if err != nil {

			fmt.Println(color.Red.Sprint(err.Error()))
			os.Exit(1)
		} else {
			fileInfo.FileName = stat.Name()
			fileInfo.FileFullPath = SbomOption.FileFullPath
			fileInfo.FileSize = stat.Size()
			waitingCheckFileList = append(waitingCheckFileList, fileInfo)
		}
	}
	ctx := context.Background()
	var resCheck []sbom.ResultComponent
	for _, msecSbom := range AllSbom {
		for _, file := range waitingCheckFileList {
			if msecSbom.FileCheck(file.FileName) {
				msecSbom.AddFile(file)
			}

		}
		component := msecSbom.MsecSbom(ctx)
		resCheck = append(resCheck, component...)
		ResultFunc(resCheck)
	}
	return nil
}
func (sbom SbomOptions) ParseSbomOption(flag bool) {
	if flag {
		// 命令解析
	} else {
		// 文件解析
		// ProjectPath 和 FileFullPath 必须得有一个
		if SbomOption.ProjectPath == "" && SbomOption.FileFullPath == "" {
			// 请输入项目目录，或者文件位
			fmt.Println(color.Red.Sprint("Please enter the project directory, or file bits"))
			os.Exit(1)
		}
	}
	// 如果 ProjectPath 和 FileFullPath 同时出现使用 FileFullPath
	if SbomOption.ProjectPath != "" && SbomOption.FileFullPath != "" {
		// 检测到项目目录和文件同时存在，将使用文件进行检测。
		fmt.Println(color.Yellow.Sprint("If both the project directory and the file are detected, the file will be used for detection."))
		SbomOption.ProjectPath = ""
	}

	if SbomOption.FileFullPath != "" {
		checkPath, info, err := utils.CheckPath(SbomOption.FileFullPath)
		if err != nil {
			// 文件不存在，请检查输入
			fmt.Println(color.Red.Sprint("File does not exist, please check the input"))
			os.Exit(1)
		}
		// 这里要求他必须是个文件
		if !info.IsDir() {
			SbomOption.FileFullPath = checkPath
		} else {
			SbomOption.FileFullPath = ""
			// 参数F只支持输入文
			fmt.Println(color.Red.Sprint("Parameter F supports only input files"))

			os.Exit(1)
		}

	}
	if SbomOption.ProjectPath != "" {
		checkPath, info, err := utils.CheckPath(SbomOption.ProjectPath)
		if err != nil {
			// 目录不存在，请检查输入
			fmt.Println(color.Red.Sprint("The directory does not exist, please check the input"))
		} else {

			if info.IsDir() {
				SbomOption.ProjectPath = checkPath
			} else {
				SbomOption.ProjectPath = ""
				// 参数P只支持输入目录
				fmt.Println(color.Red.Sprint("Parameter P supports only the input directory"))
				os.Exit(1)
			}
		}

	}
	if SbomOption.OutType != "" {
		if SbomOption.OutType != "xml" && SbomOption.OutType != "json" {
			// 输出格式参数设置有误，将使用默认输出格式json
			fmt.Println(color.Red.Sprint("The output format parameter is incorrectly set. The default output format will be json"))
			SbomOption.OutType = "json"
			SbomOption.OutC = cdx.BOMFileFormatJSON
		}
		if SbomOption.OutType == "xml" {
			SbomOption.OutType = "xml"
			SbomOption.OutC = cdx.BOMFileFormatXML
		}
		if SbomOption.OutType == "json" {
			SbomOption.OutType = "json"
			SbomOption.OutC = cdx.BOMFileFormatJSON
		}
	}
	if SbomOption.OutType == "" {
		SbomOption.OutType = "json"
		SbomOption.OutC = cdx.BOMFileFormatJSON
	}
	//当前目录地址
	dir, _ := os.Getwd()
	// 默认输出到当前执行目录下
	if SbomOption.OutPath == "" {

		// 未指定输出目录，将在当前执行目录下生成sbom
		fmt.Println(color.Yellow.Sprint("If the output directory is not specified, the sbom will be generated in the current execution directory"))
		SbomOption.OutPath = dir
	}
	if SbomOption.OutPath != "" {
		checkPath, info, err := utils.CheckPath(SbomOption.OutPath)
		if err != nil {
			// 输出目录不存在，请检查输入
			fmt.Println(color.Red.Sprint("The output directory does not exist, please check the input"))
			SbomOption.OutPath = dir
		} else {
			if info.IsDir() {
				SbomOption.OutPath = checkPath
			} else {
				SbomOption.OutPath = dir
			}
		}

	}
}

func ResultFunc(resCheck []sbom.ResultComponent) {
	var num = 1
	fmt.Println()
	for _, component := range resCheck {
		switch SbomOption.OutC {
		case cdx.BOMFileFormatJSON:
			file, _ := os.Create(filepath.Join(SbomOption.OutPath, fmt.Sprintf("%s_%d.json", component.LanguageType.String(), num)))
			component.Add()
			resCdx := component.Cover()
			bom := sbom.NewMsecSbom()
			bom.Metadata = sbom.NewMetadata()
			bom.Components = &resCdx
			// Encode the BOM
			err := cdx.NewBOMEncoder(file, SbomOption.OutC).
				SetPretty(true).
				Encode(bom)
			if err != nil {
				fmt.Println(color.Yellow.Sprint(err.Error()))
			}
		case cdx.BOMFileFormatXML:
			file, _ := os.Create(filepath.Join(SbomOption.OutPath, fmt.Sprintf("%s_%d.json", component.LanguageType.String(), num)))
			component.Add()
			resCdx := component.Cover()
			bom := sbom.NewMsecSbom()
			bom.Metadata = sbom.NewMetadata()
			bom.Components = &resCdx
			// Encode the BOM
			err := cdx.NewBOMEncoder(file, SbomOption.OutC).
				SetPretty(true).
				Encode(bom)
			if err != nil {
				fmt.Println(color.Yellow.Sprint(err.Error()))
			}
		}
		num++
	}
}
