//go:build linux || windows || darwin

package detect

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/urfave/cli/v2"
	"github.com/xuri/excelize/v2"

	"github.com/m-sec-org/d-eyes/agent/internal"
	"github.com/m-sec-org/d-eyes/agent/internal/constant"
	"github.com/m-sec-org/d-eyes/agent/internal/detect/backend"
	"github.com/m-sec-org/d-eyes/agent/internal/detect/engine"
	"github.com/m-sec-org/d-eyes/agent/internal/detect/scoring"
	"github.com/m-sec-org/d-eyes/agent/pkg/color"
)

var YaraFileScanOption *YaraFileScanOptions

func init() {
	YaraFileScanOption = NewDetectPluginYaraFileScan()
	internal.RegisterDetectSubcommands(YaraFileScanOption)
}

// YaraFileScanOptions defines CLI parameters for filesystem scanning.
type YaraFileScanOptions struct {
	Path        string
	RulePath    string
	Backend     string
	Thread      int
	Timeout     time.Duration
	EnableExcel bool
	ExcludeDir  cli.StringSlice
	internal.BaseOption
}

// NewDetectPluginYaraFileScan returns command binder.
func NewDetectPluginYaraFileScan() *YaraFileScanOptions {
	return &YaraFileScanOptions{
		Thread:  runtime.NumCPU(),
		Timeout: 10 * time.Second,
		BaseOption: internal.BaseOption{
			Name:        "yara file scan",
			Author:      "msec",
			Description: "msec community love to develop, yara scan system file plug-in",
		},
	}
}

// DetectionResult holds aggregated output per dangerous file.
type DetectionResult struct {
	RuleName       string
	Description    string
	FilePath       string
	Tags           []string
	MatchedString  []string
	Risk           scoring.RiskScore
	Remediation    scoring.RemediationPlan
	Partial        bool
	PartialReasons []string
}

// InitCommand registers CLI command.
func (scan *YaraFileScanOptions) InitCommand() []*cli.Command {
	return []*cli.Command{
		{
			Name:    "filescan",
			Usage:   "Scan files or directories with rule engine",
			Aliases: []string{"fs"},
			Action:  scan.Action,
			Flags: []cli.Flag{
				&cli.StringFlag{
					Name:        "path",
					Aliases:     []string{"p"},
					Usage:       "Target file or directory list, separated by comma",
					Destination: &YaraFileScanOption.Path,
					Value:       "./",
				},
				&cli.StringFlag{
					Name:        "rule",
					Aliases:     []string{"r"},
					Usage:       "Custom rule file or directory",
					Destination: &YaraFileScanOption.RulePath,
				},
				&cli.StringFlag{
					Name:        "backend",
					Usage:       "YARA backend (auto|native|portable). Defaults to env D_EYES_YARA_BACKEND or auto.",
					Destination: &YaraFileScanOption.Backend,
				},
				&cli.IntFlag{
					Name:        "thread",
					Aliases:     []string{"t"},
					Destination: &YaraFileScanOption.Thread,
					Value:       runtime.NumCPU(),
				},
				&cli.DurationFlag{
					Name:        "timeout",
					Aliases:     []string{"to"},
					Destination: &YaraFileScanOption.Timeout,
					Value:       30 * time.Second,
				},
				&cli.BoolFlag{
					Name:        "excel",
					Usage:       "Output detection report to Excel",
					Destination: &YaraFileScanOption.EnableExcel,
					Value:       false,
				},
				&cli.StringSliceFlag{
					Name:        "exclude",
					Aliases:     []string{"e"},
					Usage:       "Glob patterns to skip when traversing directories",
					Destination: &YaraFileScanOption.ExcludeDir,
					Value:       cli.NewStringSlice(),
				},
			},
		},
	}
}

// Action executes filesystem scan.
func (scan *YaraFileScanOptions) Action(_ *cli.Context) error {
	if scan.Path == "" {
		scan.Path = "./"
	}

	result, err := backend.Load(backend.Options{
		RulePath: scan.RulePath,
		Mode:     resolveBackendMode(scan.Backend),
	})
	if err != nil {
		return err
	}
	bundle := result.Bundle

	fmt.Printf("Loaded %d rules (backend=%s engine=%s version=%s)\n",
		bundle.RuleCount(), result.Backend, bundle.Name(), bundle.Version())
	if result.Stats.TotalRuleFiles > 0 {
		fmt.Printf("Rule coverage: %.1f%% (%d/%d files)\n",
			result.Stats.Coverage()*100,
			result.Stats.LoadedRuleFiles,
			result.Stats.TotalRuleFiles,
		)
		if result.Fallback && result.FallbackReason != "" {
			fmt.Println(color.Yellow.Sprintf("Fallback reason: %s", result.FallbackReason))
		}
	}

	targets := strings.Split(scan.Path, ",")
	for i := range targets {
		targets[i] = strings.TrimSpace(targets[i])
	}

	scanJobChan := make(chan string, 512)
	resultChan := make(chan DetectionResult, 512)

	var wgWorkers sync.WaitGroup
	threadCount := scan.Thread
	if threadCount <= 0 {
		threadCount = runtime.NumCPU()
	}
	for i := 0; i < threadCount; i++ {
		wgWorkers.Add(1)
		go scan.scanFileWorker(bundle, scanJobChan, resultChan, &wgWorkers)
	}

	var wgCollector sync.WaitGroup
	wgCollector.Add(1)
	go scan.collectResults(resultChan)

	selfExecutable, _ := os.Executable()
	var scanned int64
	for _, item := range targets {
		if item == "" {
			continue
		}
		info, err := os.Stat(item)
		if err != nil {
			fmt.Println(color.Red.Sprintf("skip %s: %v", item, err))
			continue
		}
		if info.IsDir() {
			filepath.WalkDir(item, func(path string, d fs.DirEntry, err error) error {
				if err != nil {
					return nil
				}
				if d.IsDir() {
					for _, pattern := range scan.ExcludeDir.Value() {
						match, _ := filepath.Match(pattern, path)
						if match {
							return filepath.SkipDir
						}
					}
					return nil
				}
				if path == selfExecutable {
					return nil
				}
				if slices.Contains(constant.SkipSuffix, strings.ToLower(filepath.Ext(d.Name()))) {
					return nil
				}
				scanned++
				scanJobChan <- path
				return nil
			})
		} else {
			if item == selfExecutable {
				continue
			}
			if slices.Contains(constant.SkipSuffix, strings.ToLower(filepath.Ext(item))) {
				continue
			}
			scanned++
			scanJobChan <- item
		}
	}

	close(scanJobChan)
	wgWorkers.Wait()
	close(resultChan)
	wgCollector.Wait()

	fmt.Println(color.Green.Sprintf("Scan finished. Total files analysed: %d", scanned))
	return nil
}

func (scan *YaraFileScanOptions) scanFileWorker(bundle engine.RuleBundle, jobs <-chan string, results chan<- DetectionResult, wg *sync.WaitGroup) {
	defer wg.Done()
	for path := range jobs {
		data, err := os.ReadFile(path)
		if err != nil {
			fmt.Println(color.Red.Sprintf("read %s error: %v", path, err))
			continue
		}
		matches, err := bundle.Scan(data, engine.ScanOptions{FilePath: path})
		if err != nil {
			fmt.Println(color.Red.Sprintf("scan %s error: %v", path, err))
			continue
		}
		for _, match := range matches {
			result := DetectionResult{
				RuleName:       match.RuleName,
				Description:    match.Description,
				FilePath:       path,
				Tags:           match.Tags,
				MatchedString:  extractStringIDs(match.Strings),
				Partial:        match.Partial,
				PartialReasons: append([]string{}, match.PartialReasons...),
			}
			result.Risk = scoring.Calculate(match.RuleName, match.ScoreHints, match.Tags)
			if match.Partial {
				result.Risk.Total *= 0.8
				result.Risk.Level = result.Risk.Level + " (partial)"
			}
			result.Remediation = scoring.ResolveRemediation(match.RuleName, match.Tags)
			results <- result
		}
	}
}

func extractStringIDs(stringsMatched []engine.MatchedString) []string {
	if len(stringsMatched) == 0 {
		return nil
	}
	ids := make([]string, 0, len(stringsMatched))
	for _, item := range stringsMatched {
		ids = append(ids, item.Identifier)
	}
	return ids
}

func (scan *YaraFileScanOptions) collectResults(results <-chan DetectionResult) {
	var (
		counter int
		excel   *excelize.File
	)
	if scan.EnableExcel {
		excel = excelize.NewFile()
		headers := []string{"Rule", "Description", "File Path", "Risk Level", "Risk Score", "Matched Strings", "Remediation Priority", "Partial", "Partial Reasons"}
		for i, header := range headers {
			cell, _ := excelize.CoordinatesToCellName(i+1, 1)
			excel.SetCellValue("Sheet1", cell, header)
		}
		style, _ := excel.NewStyle(&excelize.Style{
			Font: &excelize.Font{Bold: true, Size: 11, Color: "e83723"},
		})
		excel.SetCellStyle("Sheet1", "A1", "G1", style)
	}
	for res := range results {
		counter++
		printDetection(res, counter)

		if excel != nil {
			row := counter + 1
			values := []any{
				res.RuleName,
				res.Description,
				res.FilePath,
				res.Risk.Level,
				res.Risk.Total,
				strings.Join(res.MatchedString, ","),
				res.Remediation.Priority,
				res.Partial,
				strings.Join(res.PartialReasons, "; "),
			}
			for col, value := range values {
				cell, _ := excelize.CoordinatesToCellName(col+1, row)
				excel.SetCellValue("Sheet1", cell, value)
			}
		}
	}
	if scan.EnableExcel && excel != nil {
		if err := excel.SaveAs("d-eyes-filescan.xlsx"); err != nil {
			fmt.Println(color.Red.Sprintf("failed to save excel: %v", err))
		} else {
			fmt.Println(color.Green.Sprintf("Excel report saved to d-eyes-filescan.xlsx"))
		}
	}
	if counter == 0 {
		fmt.Println(color.Green.Sprint("No suspicious files detected with current rule set."))
	}
}

func printDetection(res DetectionResult, counter int) {
	fmt.Println(color.Magenta.Sprintf("[ Detection %d ] %s", counter, res.RuleName))
	if res.Description != "" {
		fmt.Println("Description:", res.Description)
	}
	fmt.Println("File:", res.FilePath)
	fmt.Printf("Risk: %s (%.1f)\n", res.Risk.Level, res.Risk.Total)
	if len(res.MatchedString) > 0 {
		fmt.Println("Matched:", strings.Join(res.MatchedString, ", "))
	}
	if res.Partial {
		reason := strings.Join(res.PartialReasons, "; ")
		if reason == "" {
			reason = "portable engine could not fully evaluate metadata expressions"
		}
		fmt.Println(color.Yellow.Sprintf("Partial evaluation: %s", reason))
	}
	if res.Remediation.Priority != "" {
		fmt.Printf("Remediation Priority: %s\n", res.Remediation.Priority)
		for _, step := range res.Remediation.Steps {
			fmt.Printf("  - [%s] %s", step.Action, step.Description)
			if step.Command != "" {
				fmt.Printf(" (cmd: %s)", step.Command)
			}
			fmt.Println()
		}
	}
	fmt.Println()
}
