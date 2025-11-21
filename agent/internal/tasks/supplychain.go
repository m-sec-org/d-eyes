package tasks

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/m-sec-org/d-eyes/agent/internal/tasks/taskcache"
	"github.com/m-sec-org/d-eyes/agent/pkg/reporting"
)

const (
	supplyChainCacheNamespace = "supplychain.generate"
)

var (
	supplyChainCacheTTL         = 6 * time.Hour
	supplyChainManifestCacheTTL = 24 * time.Hour
)

type supplyChainCollector interface {
	Generate(ctx context.Context, req TaskRequest) (TaskResult, error)
	Capture(ctx context.Context, req TaskRequest) (TaskResult, error)
}

type supplyChainRunner struct{}
type collectorWrappedRunner struct {
	collector supplyChainCollector
}

func SupplyChainRunner() TaskRunner {
	return &supplyChainRunner{}
}

func SupplyChainRunnerWithCollector(c supplyChainCollector) TaskRunner {
	if c == nil {
		return SupplyChainRunner()
	}
	return &collectorWrappedRunner{collector: c}
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

func (r *collectorWrappedRunner) Run(ctx context.Context, req TaskRequest) (TaskResult, error) {
	mode := strings.ToLower(getStringFlag(req.Flags, "mode", "generate"))
	switch mode {
	case "capture":
		return r.collector.Capture(ctx, req)
	default:
		return r.collector.Generate(ctx, req)
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
	outputType := normalizeOutputType(getStringFlag(req.Flags, "type", "json"))
	cacheKey := supplyChainCacheKey(paths, filePath, outputType)
	if cached, ok, err := restoreSupplyChainCache(req, cacheKey, outputType); err == nil && ok {
		return cached, nil
	} else if err != nil {
		notes = append(notes, fmt.Sprintf("供应链缓存恢复失败: %v", err))
	}

	var manifestIdx *manifestCache
	if cache, err := loadManifestCache(cacheKey, supplyChainManifestCacheTTL); err == nil {
		manifestIdx = cache
	} else if err != nil {
		notes = append(notes, fmt.Sprintf("增量索引加载失败: %v", err))
	}

	stats := manifestStats{}

	for _, p := range paths {
		select {
		case <-ctx.Done():
			return TaskResult{}, ctx.Err()
		default:
		}
		found, err := scanProjectManifests(ctx, p, manifestIdx, &stats)
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
		found, err := scanManifestFile(filePath, manifestIdx, &stats)
		if err != nil {
			notes = append(notes, fmt.Sprintf("解析 %s 失败: %v", filePath, err))
		} else {
			components = append(components, found...)
		}
	}

	if manifestIdx != nil {
		if err := manifestIdx.Save(); err != nil {
			notes = append(notes, fmt.Sprintf("增量索引写入失败: %v", err))
		}
	}

	record, metadata, err := writeSupplyChainReport(req, "generate", outputType, components, notes)
	if err != nil {
		return TaskResult{}, err
	}

	risks := map[string]int{}
	if len(components) > 0 {
		risks["low"] = len(components)
	}

	if stats.Total() > 0 {
		notes = append(notes, fmt.Sprintf("复用 %d 个 manifest，重新解析 %d 个", stats.Reused, stats.Refreshed))
	}

	cacheNamespace := supplyChainCacheNamespace
	if metadata == nil {
		metadata = make(map[string]string)
	}
	metadata["cache.manifest_total"] = strconv.Itoa(stats.Total())
	metadata["cache.manifest_reused"] = strconv.Itoa(stats.Reused)
	metadata["cache.manifest_refreshed"] = strconv.Itoa(stats.Refreshed)
	if stats.Total() > 0 {
		ratio := float64(stats.Reused) / float64(stats.Total())
		metadata["cache.reuse_ratio"] = fmt.Sprintf("%.2f", ratio)
	}
	setCacheMetadata(metadata, cacheNamespace, cacheKey, "manifest-delta", supplyChainCacheTTL)

	cacheMeta := cloneStringMap(metadata)
	embedRiskMetadata(cacheMeta, risks)
	if err := taskcache.SaveFile(cacheNamespace, cacheKey, record.Path, cacheMeta); err != nil {
		notes = append(notes, fmt.Sprintf("供应链缓存写入失败: %v", err))
	}

	return TaskResult{
		Outputs:  []reporting.OutputRecord{record},
		Risks:    risks,
		Notes:    notes,
		Metadata: metadata,
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

	record, metadata, err := writeSupplyChainReport(req, "capture", outputType, components, nil)
	if err != nil {
		return TaskResult{}, err
	}
	risks := map[string]int{}
	if len(components) > 0 {
		risks["medium"] = len(components)
	}
	return TaskResult{
		Outputs:  []reporting.OutputRecord{record},
		Risks:    risks,
		Metadata: metadata,
	}, nil
}

type componentRecord struct {
	Name    string `json:"name"`
	Version string `json:"version,omitempty"`
	Type    string `json:"type"`
	Source  string `json:"source"`
	Path    string `json:"path,omitempty"`
}

type manifestStats struct {
	Reused    int
	Refreshed int
}

func (m manifestStats) Total() int {
	return m.Reused + m.Refreshed
}

func supplyChainCacheKey(paths []string, filePath, outputType string) string {
	parts := []string{outputType}
	ordered := append([]string(nil), paths...)
	sort.Strings(ordered)
	parts = append(parts, ordered...)
	if filePath != "" {
		parts = append(parts, "file:"+filePath)
	}
	raw := strings.Join(parts, "|")
	sum := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(sum[:])
}

func restoreSupplyChainCache(req TaskRequest, cacheKey, outputType string) (TaskResult, bool, error) {
	file, path, err := req.Manager.CreateFile("supplychain", req.Name+"-generate", outputType)
	if err != nil {
		return TaskResult{}, false, err
	}
	file.Close()
	taskcache.PurgeExpired(supplyChainCacheNamespace, supplyChainCacheTTL)
	meta, ok, err := taskcache.RestoreTo(supplyChainCacheNamespace, cacheKey, supplyChainCacheTTL, path)
	if err != nil || !ok {
		_ = os.Remove(path)
		return TaskResult{}, ok, err
	}
	markCacheHit(meta, supplyChainCacheTTL)
	result := TaskResult{
		Outputs:  []reporting.OutputRecord{{Label: "供应链报告", Path: path}},
		Notes:    []string{"命中供应链缓存"},
		Metadata: meta,
		Risks:    metadataToRisk(meta),
	}
	if len(result.Risks) == 0 {
		if countStr := meta["component_count"]; countStr != "" {
			if n, err := strconv.Atoi(countStr); err == nil && n > 0 {
				result.Risks = map[string]int{"low": n}
			}
		}
	}
	return result, true, nil
}

func scanProjectManifests(ctx context.Context, root string, idx *manifestCache, stats *manifestStats) ([]componentRecord, error) {
	info, err := os.Stat(root)
	if err != nil {
		return nil, err
	}
	if !info.IsDir() {
		return scanManifestFile(root, idx, stats)
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
		case "package.json", "requirements.txt", "go.mod", "pom.xml":
			found, err := scanManifestFile(path, idx, stats)
			if err != nil {
				return err
			}
			records = append(records, found...)
		}
		return nil
	})
	return records, err
}

func scanManifestFile(path string, idx *manifestCache, stats *manifestStats) ([]componentRecord, error) {
	var fingerprint string
	var fpErr error
	if idx != nil {
		fingerprint, fpErr = fileFingerprint(path)
		if fpErr == nil {
			if cached, ok := idx.Lookup(path, fingerprint); ok {
				if stats != nil {
					stats.Reused++
				}
				return cached, nil
			}
		}
	}
	var comps []componentRecord
	var err error
	switch strings.ToLower(filepath.Base(path)) {
	case "package.json":
		comps, err = parsePackageJSON(path)
	case "requirements.txt":
		comps = parseRequirementsFile(path, "requirements.txt")
	case "go.mod":
		comps = parseGoMod(path)
	case "pom.xml":
		comps = parseMavenPom(path)
	default:
		return nil, fmt.Errorf("不支持的 manifest 类型: %s", path)
	}
	if err != nil {
		return nil, err
	}
	if stats != nil {
		stats.Refreshed++
	}
	if idx != nil && fpErr == nil {
		idx.Update(path, fingerprint, comps)
	}
	return comps, nil
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

func writeSupplyChainReport(req TaskRequest, mode, format string, components []componentRecord, notes []string) (reporting.OutputRecord, map[string]string, error) {
	file, path, err := req.Manager.CreateFile("supplychain", req.Name+"-"+mode, format)
	if err != nil {
		return reporting.OutputRecord{}, nil, err
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
		return reporting.OutputRecord{}, nil, err
	}

	meta := map[string]string{
		"mode":            mode,
		"profile":         req.Profile,
		"component_count": fmt.Sprintf("%d", len(components)),
		"report_path":     path,
	}
	if len(notes) > 0 {
		meta["notes_count"] = fmt.Sprintf("%d", len(notes))
	}
	sources := make(map[string]struct{})
	for _, c := range components {
		if c.Source != "" {
			sources[c.Source] = struct{}{}
		}
	}
	if len(sources) > 0 {
		list := make([]string, 0, len(sources))
		for src := range sources {
			list = append(list, src)
		}
		meta["sources"] = strings.Join(list, ",")
	}
	if len(components) > 0 && components[0].Type != "" {
		meta["primary_type"] = components[0].Type
	}
	return reporting.OutputRecord{Label: "供应链报告", Path: path}, meta, nil
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
