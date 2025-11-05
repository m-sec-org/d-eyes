package tasks

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/m-sec-org/d-eyes/agent/pkg/reporting"
)

type supplyChainRunner struct{}

func SupplyChainRunner() TaskRunner {
	return &supplyChainRunner{}
}

func (s *supplyChainRunner) Run(ctx context.Context, req TaskRequest) (TaskResult, error) {
	mode := strings.ToLower(getStringFlag(req.Flags, "mode", "generate"))
	switch mode {
	case "capture":
		return s.captureEnvironment(ctx, req)
	default:
		return s.generateSBOM(ctx, req)
	}
}

func (s *supplyChainRunner) generateSBOM(ctx context.Context, req TaskRequest) (TaskResult, error) {
	paths := splitList(getStringFlag(req.Flags, "path", ""))
	filePath := getStringFlag(req.Flags, "file", "")
	if len(paths) == 0 && filePath == "" {
		return TaskResult{}, errors.New("supplychain generate 需要 --path 或 --file")
	}

	components := make([]componentRecord, 0)
	notes := make([]string, 0)

	for _, p := range paths {
		select {
		case <-ctx.Done():
			return TaskResult{}, ctx.Err()
		default:
		}
		found, err := scanProjectManifests(ctx, p)
		if err != nil {
			notes = append(notes, fmt.Sprintf("扫描 %s 失败: %v", p, err))
			continue
		}
		components = append(components, found...)
	}

	if filePath != "" {
		select {
		case <-ctx.Done():
			return TaskResult{}, ctx.Err()
		default:
		}
		found, err := scanManifestFile(filePath)
		if err != nil {
			notes = append(notes, fmt.Sprintf("解析 %s 失败: %v", filePath, err))
		} else {
			components = append(components, found...)
		}
	}

	outputType := normalizeOutputType(getStringFlag(req.Flags, "type", "json"))

	record, err := writeSupplyChainReport(req, "generate", outputType, components, notes)
	if err != nil {
		return TaskResult{}, err
	}

	risks := map[string]int{}
	if len(components) > 0 {
		risks["low"] = len(components)
	}

	return TaskResult{
		Outputs: []reporting.OutputRecord{record},
		Risks:   risks,
		Notes:   notes,
	}, nil
}

func (s *supplyChainRunner) captureEnvironment(ctx context.Context, req TaskRequest) (TaskResult, error) {
	cmd := exec.CommandContext(ctx, "pip", "list", "--format=freeze")
	out, err := cmd.Output()
	if err != nil {
		return TaskResult{}, fmt.Errorf("pip list 执行失败: %w", err)
	}

	components := parseRequirements(string(out), "pip-list")
	outputType := normalizeOutputType(getStringFlag(req.Flags, "type", "json"))

	record, err := writeSupplyChainReport(req, "capture", outputType, components, nil)
	if err != nil {
		return TaskResult{}, err
	}
	risks := map[string]int{}
	if len(components) > 0 {
		risks["medium"] = len(components)
	}
	return TaskResult{
		Outputs: []reporting.OutputRecord{record},
		Risks:   risks,
	}, nil
}

type componentRecord struct {
	Name    string `json:"name"`
	Version string `json:"version,omitempty"`
	Type    string `json:"type"`
	Source  string `json:"source"`
	Path    string `json:"path,omitempty"`
}

func scanProjectManifests(ctx context.Context, root string) ([]componentRecord, error) {
	info, err := os.Stat(root)
	if err != nil {
		return nil, err
	}
	if !info.IsDir() {
		return scanManifestFile(root)
	}

	var records []componentRecord
	err = filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		if d.IsDir() {
			if strings.HasPrefix(d.Name(), ".git") || d.Name() == "node_modules" || d.Name() == "vendor" {
				return filepath.SkipDir
			}
			return nil
		}
		switch strings.ToLower(filepath.Base(path)) {
		case "package.json":
			found, err := parsePackageJSON(path)
			if err != nil {
				return err
			}
			records = append(records, found...)
		case "requirements.txt":
			records = append(records, parseRequirementsFile(path, "requirements.txt")...)
		case "go.mod":
			records = append(records, parseGoMod(path)...)
		case "pom.xml":
			records = append(records, parseMavenPom(path)...)
		}
		return nil
	})
	return records, err
}

func scanManifestFile(path string) ([]componentRecord, error) {
	switch strings.ToLower(filepath.Base(path)) {
	case "package.json":
		return parsePackageJSON(path)
	case "requirements.txt":
		return parseRequirementsFile(path, "requirements.txt"), nil
	case "go.mod":
		return parseGoMod(path), nil
	case "pom.xml":
		return parseMavenPom(path), nil
	default:
		return nil, fmt.Errorf("不支持的 manifest 类型: %s", path)
	}
}

func parsePackageJSON(path string) ([]componentRecord, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	var payload struct {
		Dependencies    map[string]string `json:"dependencies"`
		DevDependencies map[string]string `json:"devDependencies"`
	}
	if err := json.NewDecoder(file).Decode(&payload); err != nil {
		return nil, err
	}
	records := make([]componentRecord, 0)
	for name, version := range payload.Dependencies {
		records = append(records, componentRecord{Name: name, Version: version, Type: "npm", Source: "package.json", Path: path})
	}
	for name, version := range payload.DevDependencies {
		records = append(records, componentRecord{Name: name, Version: version, Type: "npm-dev", Source: "package.json", Path: path})
	}
	return records, nil
}

func parseRequirements(content, source string) []componentRecord {
	records := make([]componentRecord, 0)
	scanner := bufio.NewScanner(strings.NewReader(content))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		name := line
		version := ""
		if idx := strings.Index(line, "=="); idx != -1 {
			name = strings.TrimSpace(line[:idx])
			version = strings.TrimSpace(line[idx+2:])
		}
		records = append(records, componentRecord{Name: name, Version: version, Type: "python", Source: source})
	}
	return records
}

func parseRequirementsFile(path, source string) []componentRecord {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	records := parseRequirements(string(data), source)
	for i := range records {
		records[i].Path = path
	}
	return records
}

func parseGoMod(path string) []componentRecord {
	file, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer file.Close()
	records := make([]componentRecord, 0)
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if !strings.HasPrefix(line, "require ") {
			continue
		}
		line = strings.TrimPrefix(line, "require ")
		line = strings.Trim(line, "()")
		fields := strings.Fields(line)
		if len(fields) >= 2 {
			records = append(records, componentRecord{
				Name:    fields[0],
				Version: fields[1],
				Type:    "gomod",
				Source:  "go.mod",
				Path:    path,
			})
		}
	}
	return records
}

func parseMavenPom(path string) []componentRecord {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	content := string(data)
	lines := strings.Split(content, "\n")
	records := make([]componentRecord, 0)
	var groupID, artifactID, version string
	for _, line := range lines {
		line = strings.TrimSpace(line)
		switch {
		case strings.HasPrefix(line, "<groupId>"):
			groupID = extractTagValue(line, "groupId")
		case strings.HasPrefix(line, "<artifactId>"):
			artifactID = extractTagValue(line, "artifactId")
		case strings.HasPrefix(line, "<version>"):
			version = extractTagValue(line, "version")
		case strings.HasPrefix(line, "</dependency>"):
			if artifactID != "" {
				name := artifactID
				if groupID != "" {
					name = groupID + ":" + artifactID
				}
				records = append(records, componentRecord{
					Name:    name,
					Version: version,
					Type:    "maven",
					Source:  "pom.xml",
					Path:    path,
				})
			}
			groupID, artifactID, version = "", "", ""
		}
	}
	return records
}

func extractTagValue(line, tag string) string {
	open := fmt.Sprintf("<%s>", tag)
	close := fmt.Sprintf("</%s>", tag)
	line = strings.TrimSpace(line)
	line = strings.TrimPrefix(line, open)
	line = strings.TrimSuffix(line, close)
	return strings.TrimSpace(line)
}

func writeSupplyChainReport(req TaskRequest, mode, format string, components []componentRecord, notes []string) (reporting.OutputRecord, error) {
	file, path, err := req.Manager.CreateFile("supplychain", req.Name+"-"+mode, format)
	if err != nil {
		return reporting.OutputRecord{}, err
	}
	defer file.Close()
	summary := struct {
		Mode           string            `json:"mode"`
		Profile        string            `json:"profile"`
		ComponentCount int               `json:"component_count"`
		Components     []componentRecord `json:"components"`
		Notes          []string          `json:"notes,omitempty"`
		Generated      time.Time         `json:"generated"`
	}{
		Mode:           mode,
		Profile:        req.Profile,
		ComponentCount: len(components),
		Components:     components,
		Notes:          notes,
		Generated:      time.Now().UTC(),
	}
	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(summary); err != nil {
		return reporting.OutputRecord{}, err
	}
	return reporting.OutputRecord{Label: "供应链报告", Path: path}, nil
}

func splitList(value string) []string {
	if strings.TrimSpace(value) == "" {
		return nil
	}
	raw := strings.Split(value, ",")
	out := make([]string, 0, len(raw))
	for _, item := range raw {
		item = strings.TrimSpace(item)
		if item != "" {
			out = append(out, item)
		}
	}
	return out
}

func normalizeOutputType(format string) string {
	switch strings.ToLower(strings.TrimSpace(format)) {
	case "xml":
		return "xml"
	case "json", "":
		return "json"
	default:
		return "json"
	}
}
