//go:build linux || windows

package detect

import (
	//_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"

	"github.com/hillu/go-yara/v4"
	"github.com/urfave/cli/v2"
	"github.com/xuri/excelize/v2"

	"github.com/m-sec-org/d-eyes/internal"
	"github.com/m-sec-org/d-eyes/internal/constant"
	"github.com/m-sec-org/d-eyes/internal/utils"
	"github.com/m-sec-org/d-eyes/pkg/color"
	"github.com/m-sec-org/d-eyes/yaraRules"
)

var fileCompiler *yara.Compiler
var FileErr error
var FileExcelErr error
var YaraFileScanOption *YaraFileScanOptions

func init() {
	YaraFileScanOption = NewDetectPluginYaraFileScan()
	internal.RegisterDetectSubcommands(YaraFileScanOption)
}

type YaraFileScanOptions struct {
	// 指定要扫描的文件夹
	Path string
	// 自定义rule
	RulePath string
	// yara规则
	Rules *yara.Rules
	// yara规则是否获取到
	RulesErr error
	// 线程
	Thread int
	// 路径列表
	PathList []string
	internal.BaseOption
}

func NewDetectPluginYaraFileScan() *YaraFileScanOptions {
	return &YaraFileScanOptions{
		Path:     "",
		RulePath: "",
		Rules:    nil,
		RulesErr: nil,
		Thread:   0,
		PathList: nil,
		BaseOption: internal.BaseOption{
			Name:        "yara file scan",
			Author:      "msec",
			Description: "msec community love to develop, yara scan system file plug-in",
		},
	}
}

type FileResult struct {
	Risk     string
	RiskPath string
}

func (scan *YaraFileScanOptions) InitCommand() []*cli.Command {
	return []*cli.Command{
		{
			Name: "filescan",
			// 使用yara规则扫描指定的文件或文件夹
			Usage:   "Command for scanning filesystem",
			Aliases: []string{"fs"},
			Action:  scan.Action,
			Flags: []cli.Flag{
				&cli.StringFlag{
					Name:    "path",
					Aliases: []string{"p"},
					// 指定的文件或文件夹进行扫描
					Usage:       "The specified file or folder is scanned\n                     example: --path C:\\ or -p C:\\,D:\\ \n                     Empty means scan all files, use with caution!\n",
					Destination: &YaraFileScanOption.Path,
				},
				&cli.StringFlag{
					Name:    "rule",
					Aliases: []string{"r"},
					// 指定yara规则进行扫描,默认为内置yara规则
					Usage:       "Specifies the yara rule for scanning. The default is the built-in yara rule\n                     example: --rule C:\\Botnet.BlackMoon.yar or -r C:\\Botnet.BlackMoon.yar",
					Destination: &YaraFileScanOption.RulePath,
				},
				&cli.IntFlag{
					Name:    "thread",
					Aliases: []string{"t"},
					// 指定扫描线程
					Usage:       "Assigned scan thread\n                       example: --thread 50 or -t 50",
					Destination: &YaraFileScanOption.Thread,
					// 默认线程数量
					Value: 50,
				},
			},
		},
	}
}
func (scan *YaraFileScanOptions) Action(c *cli.Context) error {
	var result []FileResult
	var AllFile = make(chan string, 500)
	var scanTotal int64
	Wg := &sync.WaitGroup{}
	dir, err := os.Getwd()
	if err != nil {
		//fmt.Println(color.Magenta.Sprintf("获取当前目录失败"))
		fmt.Println(color.Magenta.Sprintf("Failed to obtain the current directory. Procedure"))
		// 获取目录失败就退出
		os.Exit(1)
	}
	// 初始化 YARA
	fileCompiler, FileErr = yara.NewCompiler()
	if FileErr != nil {
		//fmt.Println(color.Magenta.Sprintf("创建 YARA 编译器失败"))
		fmt.Println(color.Magenta.Sprintf("Failed to create the YARA compiler"))
		os.Exit(1)
	}
	if scan.RulePath != "" {
		scan.LoadOneRule(scan.RulePath)
		if scan.RulesErr != nil {
			fmt.Println(color.Magenta.Sprint(scan.RulesErr.Error()))
			os.Exit(1)
		}
	}
	if scan.RulePath == "" {
		scan.LoadBuiltRule()
		if scan.RulesErr != nil {
			fmt.Println(color.Magenta.Sprint(scan.RulesErr.Error()))
			os.Exit(1)
		}
	}
	if scan.Path == "" {
		// 扫描当前目录下的所有文件以及子文件
		for i := 0; i < scan.Thread; i++ {
			go scan.scanFile(AllFile, Wg, &result)
		}
		_ = filepath.Walk(
			dir, func(path string, info fs.FileInfo, _ error) error {
				if !info.IsDir() {
					// 不是目录
					if !slices.Contains(constant.SkipSuffix, strings.ToLower(filepath.Ext(info.Name()))) && info.Name() != "D-Eyes.exe" {
						// 添加文件到chan
						AllFile <- path
						Wg.Add(1)
						scanTotal += 1
					}
				}
				return nil
			},
		)
	}
	// 扫描用户指定目录
	if scan.Path != "" {
		for i := 0; i < scan.Thread; i++ {
			go scan.scanFile(AllFile, Wg, &result)
		}
		pathListTemp := strings.Split(scan.Path, ",")
		for _, pathTemp := range pathListTemp {
			pathUse, info, err := utils.CheckPath(pathTemp)
			if err != nil {
				// 输入的路径有问题
			} else {
				if !info.IsDir() {
					// 不是目录
					AllFile <- pathUse
					Wg.Add(1)
					scanTotal += 1
				} else {
					_ = filepath.Walk(
						pathUse, func(path string, info fs.FileInfo, _ error) error {
							if !info.IsDir() {
								// 不是目录
								if !slices.Contains(constant.SkipSuffix, strings.ToLower(filepath.Ext(info.Name()))) && info.Name() != "D-Eyes.exe" {
									// 添加文件到chan
									AllFile <- path
									Wg.Add(1)
									scanTotal += 1
								}
							}
							return nil
						},
					)
				}
			}
		}
	}
	Wg.Wait()
	if len(result) > 0 {
		length := len(result)
		vulSumTmp := 0
		categories := map[string]string{
			"A1": "Risk Description", "B1": "Risk File Path",
		}
		var values = make(map[string]string)
		for i := 0; i < length; i++ {
			vulSumTmp++
			fmt.Println(color.Magenta.Sprint("[ Risk ", vulSumTmp, " ]"))
			fmt.Print("Risk Description: ")
			fmt.Println(color.Magenta.Sprint(result[i].Risk))
			fmt.Print("Risk File Path: ")
			fmt.Println(color.Magenta.Sprint(result[i].RiskPath))
			excelValueTmpA := "A" + strconv.Itoa(vulSumTmp+1)
			excelValueTmpB := "B" + strconv.Itoa(vulSumTmp+1)
			values[excelValueTmpA] = result[i].Risk
			values[excelValueTmpB] = result[i].RiskPath
		}
		//output to a excel
		f := excelize.NewFile()
		FileExcelErr = f.SetColWidth("Sheet1", "A", "B", 50)
		for k, v := range categories {
			FileExcelErr = f.SetCellValue("Sheet1", k, v)
		}
		for k, v := range values {
			FileExcelErr = f.SetCellValue("Sheet1", k, v)
		}
		style, err := f.NewStyle(
			&excelize.Style{
				Font: &excelize.Font{
					Bold:  true,
					Size:  11,
					Color: "e83723",
				},
			},
		)
		if err != nil {
			fmt.Println(err)
		}
		FileExcelErr = f.SetCellStyle("Sheet1", "A1", "A1", style)
		FileExcelErr = f.SetCellStyle("Sheet1", "B1", "B1", style)
		// save the result to d-eyes.xlsx
		if err := f.SaveAs(dir + "d-eyes.xlsx"); err != nil {
			fmt.Println(err)
		}
	} else {
		fmt.Println(color.Green.Sprint("No suspicious files found. Your computer is safe with the rules you choose."))
	}
	//
	fmt.Println(color.Magenta.Sprintf("The scan is complete. %d files have been scanned", scanTotal))
	close(AllFile)
	return nil
}
func (scan *YaraFileScanOptions) LoadBuiltRule() {
	err := fs.WalkDir(
		yaraRules.RulesFS, ".", func(path string, d os.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if !d.IsDir() && strings.Contains(d.Name(), ".yar") {
				ruleContent, err := yaraRules.RulesFS.ReadFile(path)
				if err != nil {
					return err
				}
				err = fileCompiler.AddString(string(ruleContent), "")
				if err != nil {
					return err
				}
			}
			return nil
		},
	)
	if err != nil {
		//fmt.Println(color.Magenta.Sprintf("加载内置yara规则失败"))
		fmt.Println(color.Magenta.Sprintf("Failed to load the built-in yara rule"))
		scan.Rules = nil
		scan.RulesErr = err

	}
	// 获取编译后的规则
	rules, err := fileCompiler.GetRules()
	if err != nil {
		//fmt.Println(color.Magenta.Sprintf("获取内置yara规则失败"))
		fmt.Println(color.Magenta.Sprintf("Failed to obtain the built-in yara rule. Procedure"))
		scan.Rules = nil
		scan.RulesErr = err

	}
	scan.Rules = rules
	scan.RulesErr = nil
}
func (scan *YaraFileScanOptions) LoadOneRule(rulePath string) {
	path, info, err := utils.CheckPath(rulePath)
	if err != nil {
		scan.Rules = nil
		scan.RulesErr = errors.New("failed to obtain the built-in yara rule. Procedure")
	}
	if path != "" && info != nil {
		if !info.IsDir() {
			//open the yara rule
			file, err := os.OpenFile(path, os.O_RDONLY, 0666)
			if err != nil {
				scan.Rules = nil
				scan.RulesErr = fmt.Errorf("could not open rules file \"%s\", reason: %w", path, err)

			}
			defer func(file *os.File) {
				err := file.Close()
				if err != nil {

				}
			}(file)

			errRet := fileCompiler.AddFile(file, "")
			if errRet != nil {
				scan.Rules = nil
				scan.RulesErr = fmt.Errorf("could not compile rules file \"%s\", reason: %w", path, err)

			}
			scan.Rules, scan.RulesErr = fileCompiler.GetRules()
		}
	}
	scan.Rules = nil
	scan.RulesErr = errors.New("failed to obtain the built-in yara rule. Procedure")
}
func (scan *YaraFileScanOptions) scanFile(files chan string, wg *sync.WaitGroup, result *[]FileResult) {
	for targetFile := range files {
		//fmt.Printf("扫描文件： %s\n", targetFile)
		var matches yara.MatchRules
		err := scan.Rules.ScanFile(targetFile, 0, 0, &matches)
		if err != nil {
			wg.Done()
			continue
		}
		if len(matches) != 0 {
			data := matches[0].Metas[0]
			dataType, _ := json.Marshal(data)
			dataString := string(dataType)
			meta := strings.Split(dataString, ":")[2]
			metaTmp := strings.Trim(meta, "\"}")
			resTmp := FileResult{Risk: metaTmp, RiskPath: targetFile}
			*result = append(*result, resTmp)
		}
		wg.Done()
	}
}
