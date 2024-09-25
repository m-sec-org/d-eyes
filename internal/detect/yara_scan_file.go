//go:build linux || windows || darwin

package detect

import (
	//_ "embed"
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/hillu/go-yara/v4"
	"github.com/urfave/cli/v2"
	"github.com/xuri/excelize/v2"

	"github.com/m-sec-org/d-eyes/internal"
	"github.com/m-sec-org/d-eyes/internal/constant"
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
	// 超时时间
	Timeout time.Duration
	// 输出excel
	EnableExcel bool
	// 排除目录
	ExcludeDir cli.StringSlice
	internal.BaseOption
}

func NewDetectPluginYaraFileScan() *YaraFileScanOptions {
	return &YaraFileScanOptions{
		Path:     "",
		RulePath: "",
		Rules:    nil,
		RulesErr: nil,
		Thread:   0,
		Timeout:  0,
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
					Usage:       "The specified file or folder is scanned\n                     example: --path C:\\ or -p C:\\,D:\\ \n                     Empty means scan current dir\n",
					Destination: &YaraFileScanOption.Path,
					Value:       "./",
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
				&cli.DurationFlag{
					Name:    "timeout",
					Aliases: []string{"to"},
					// 指定扫描超时时间
					Usage:       "scan timeout for single file in seconds\n          example: --timeout 50 or -to 50",
					Destination: &YaraFileScanOption.Timeout,
					Value:       10,
				},
				&cli.BoolFlag{
					Name:        "excel",
					Usage:       "Output the scan results to an excel file",
					Destination: &YaraFileScanOption.EnableExcel,
					Value:       false,
				},
				&cli.StringSliceFlag{
					Name:        "exclude",
					Aliases:     []string{"e"},
					Usage:       "Exclude directories",
					Destination: &YaraFileScanOption.ExcludeDir,
					Value:       cli.NewStringSlice(),
				},
			},
		},
	}
}
func (scan *YaraFileScanOptions) Action(c *cli.Context) error {
	selfPath, err := os.Getwd()
	if err != nil {
		//fmt.Println(color.Magenta.Sprintf("获取当前目录失败"))
		fmt.Println(color.Magenta.Sprintf("Failed to obtain the current directory. Procedure"))
		// 获取目录失败就退出
		os.Exit(1)
	}
	selfExecutable, err := os.Executable()
	if err != nil {
		fmt.Println(color.Magenta.Sprintf("Failed to obtain the current executable file. Procedure"))
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
		scan.LoadYaraRule(os.DirFS(scan.RulePath))
	} else {
		scan.LoadYaraRule(yaraRules.RulesFS)
	}
	if scan.RulesErr != nil {
		fmt.Println(color.Magenta.Sprint(scan.RulesErr.Error()))
		os.Exit(1)
	}
	if scan.Path == "" {
		scan.Path = "./"
	}

	var scanTotal int64
	scanJobChan := make(chan string, 500)
	scanResultChan := make(chan FileResult, 500)

	// 结果输出协程
	vulSumTmp := 0
	f := excelize.NewFile()
	if scan.EnableExcel {
		_ = f.SetCellValue("Sheet1", "A1", "Risk Description")
		_ = f.SetCellValue("Sheet1", "B1", "Risk File Path")
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
		_ = f.SetCellStyle("Sheet1", "A1", "A1", style)
		_ = f.SetCellStyle("Sheet1", "B1", "B1", style)
	}
	var wgRes sync.WaitGroup
	wgRes.Add(1)
	go func() {
		wgRes.Done()
		for res := range scanResultChan {
			vulSumTmp++
			fmt.Println(color.Magenta.Sprint("[ Risk ", vulSumTmp, " ]"))
			fmt.Print("Risk Description: ")
			fmt.Println(color.Magenta.Sprint(res.Risk))
			fmt.Print("Risk File Path: ")
			fmt.Println(color.Magenta.Sprint(res.RiskPath))
			if scan.EnableExcel {
				index := strconv.Itoa(vulSumTmp + 1)
				cellA := "A" + index
				cellB := "B" + index
				_ = f.SetCellValue("Sheet1", cellA, res.Risk)
				_ = f.SetCellValue("Sheet1", cellB, res.RiskPath)
			}
		}
	}()

	wgScan := sync.WaitGroup{}
	wgScan.Add(scan.Thread)
	// 启动文件扫描协程
	for i := 0; i < scan.Thread; i++ {
		go scan.scanFileWorker(scanJobChan, scanResultChan, &wgScan)
	}

	// 启动路径遍历生产者
	pathListTemp := strings.Split(scan.Path, ",")
	for i := range pathListTemp {
		// get abs path
		pathAbs, err := filepath.Abs(pathListTemp[i])
		if err != nil {
			fmt.Println(color.Red.Sprintf("Failed to get the absolute path of the specified file or folder. Procedure"))
			continue
		}
		err = filepath.WalkDir(
			pathAbs, func(path string, d fs.DirEntry, err error) error {
				for _, pattern := range scan.ExcludeDir.Value() {
					ok, _ := filepath.Match(pattern, path)
					if ok {
						return filepath.SkipDir
					}
				}
				if d.IsDir() {
					return nil
				}
				// 跳过扫描白名单
				if slices.Contains(constant.SkipSuffix, filepath.Ext(d.Name())) {
					return nil
				}
				// 跳过扫描自身
				if path == selfExecutable {
					return nil
				}
				scanJobChan <- path
				scanTotal += 1
				return nil
			},
		)
		if err != nil {
			// todo 更详细的错误信息和等级
			continue
		}
	}
	close(scanJobChan)
	wgScan.Wait()
	close(scanResultChan)
	wgRes.Wait()
	if scan.EnableExcel {
		err := f.SaveAs(filepath.Join(selfPath, "result.xlsx"))
		if err != nil {
			fmt.Println(err)
		}
	}
	if vulSumTmp == 0 {
		fmt.Println(color.Green.Sprint("No suspicious files found. Your computer is safe with the rules you choose."))
	}
	fmt.Println(color.Magenta.Sprintf("The scan is complete. %d files have been scanned", scanTotal))
	return nil
}

func (scan *YaraFileScanOptions) LoadYaraRule(ruleFs fs.FS) {
	err := fs.WalkDir(
		ruleFs, ".", func(path string, d os.DirEntry, err error) error {
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

func (scan *YaraFileScanOptions) scanFileWorker(scanJobChan chan string, resultChan chan FileResult, wg *sync.WaitGroup) {
	defer wg.Done()
	for targetFile := range scanJobChan {
		//fmt.Printf("扫描文件： %s\n", targetFile)
		var matches yara.MatchRules
		err := scan.Rules.ScanFile(targetFile, 0, time.Second*scan.Timeout, &matches)
		if err != nil {
			//fmt.Println(color.Red.Sprint("扫描失败", targetFile, " ", err))
			continue
		}
		for i := range matches {
			for j := range matches[i].Metas {
				data := matches[i].Metas[j]
				dataType, _ := json.Marshal(data)
				dataString := string(dataType)
				meta := strings.Split(dataString, ":")[2]
				metaTmp := strings.Trim(meta, "\"}")
				resultChan <- FileResult{Risk: metaTmp, RiskPath: targetFile}
			}
		}
	}
}
