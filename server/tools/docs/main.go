package main

import (
	"archive/zip"
	"bufio"
	"bytes"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"
)

type manifest struct {
	Current  string    `yaml:"current"`
	Releases []release `yaml:"releases"`
}

type release struct {
	Name  string `yaml:"name"`
	Notes string `yaml:"notes"`
}

type lintError struct {
	File    string
	Line    int
	Message string
}

func (l lintError) String() string {
	if l.Line > 0 {
		return fmt.Sprintf("%s:%d %s", l.File, l.Line, l.Message)
	}
	return fmt.Sprintf("%s %s", l.File, l.Message)
}

type docFile struct {
	Rel string
	Abs string
}

func main() {
	mode := flag.String("mode", "lint", "Specify lint or publish")
	manifestPath := flag.String("manifest", "docs/version.yaml", "Docs manifest with current release information")
	versionOverride := flag.String("version", "", "Override release name when publishing")
	outputDir := flag.String("out", "docs/releases", "Directory to store published docs snapshots")
	rootDir := flag.String("root", ".", "Repository root (contains docs/)")
	flag.Parse()

	absRoot, err := filepath.Abs(*rootDir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "resolve root: %v\n", err)
		os.Exit(1)
	}

	switch *mode {
	case "lint":
		if err := runLint(absRoot); err != nil {
			fmt.Fprintf(os.Stderr, "docs lint failed: %v\n", err)
			os.Exit(1)
		}
		fmt.Println("docs lint passed")
	case "publish":
		absManifest := absolutePath(absRoot, *manifestPath)
		absOutput := absolutePath(absRoot, *outputDir)
		if err := runPublish(absRoot, absManifest, *versionOverride, absOutput); err != nil {
			fmt.Fprintf(os.Stderr, "docs publish failed: %v\n", err)
			os.Exit(1)
		}
	default:
		fmt.Fprintf(os.Stderr, "unknown mode %q\n", *mode)
		os.Exit(1)
	}
}

func absolutePath(root, target string) string {
	if filepath.IsAbs(target) {
		return target
	}
	return filepath.Join(root, target)
}

func displayPath(root, abs string) string {
	if rel, err := filepath.Rel(root, abs); err == nil {
		return filepath.ToSlash(rel)
	}
	return filepath.ToSlash(abs)
}

func runLint(root string) error {
	targets, err := collectMarkdownTargets(root)
	if err != nil {
		return err
	}
	var lintErrs []lintError
	for _, file := range targets {
		fileErrs, err := lintFile(file)
		if err != nil {
			return err
		}
		lintErrs = append(lintErrs, fileErrs...)
	}
	if len(lintErrs) > 0 {
		for _, e := range lintErrs {
			fmt.Fprintln(os.Stderr, e.String())
		}
		return fmt.Errorf("found %d documentation errors", len(lintErrs))
	}
	return nil
}

func collectMarkdownTargets(root string) ([]docFile, error) {
	targets := []docFile{}
	knownFiles := []string{"README.md", "agent/README.md"}
	for _, file := range knownFiles {
		absPath := filepath.Join(root, file)
		if _, err := os.Stat(absPath); err == nil {
			targets = append(targets, docFile{Rel: filepath.ToSlash(file), Abs: absPath})
		}
	}
	docsRoot := filepath.Join(root, "docs")
	if _, err := os.Stat(docsRoot); err == nil {
		err := filepath.WalkDir(docsRoot, func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() {
				if path == docsRoot {
					return nil
				}
				if strings.HasPrefix(path, filepath.Join(docsRoot, "releases")) {
					return fs.SkipDir
				}
				return nil
			}
			if filepath.Ext(path) == ".md" {
				if rel, err := filepath.Rel(root, path); err == nil {
					targets = append(targets, docFile{Rel: filepath.ToSlash(rel), Abs: path})
				}
			}
			return nil
		})
		if err != nil {
			return nil, err
		}
	}
	return targets, nil
}

func lintFile(file docFile) ([]lintError, error) {
	data, err := os.ReadFile(file.Abs)
	if err != nil {
		return nil, err
	}
	var errs []lintError
	if headingErr := checkHeading(file.Rel, data); headingErr != nil {
		errs = append(errs, *headingErr)
	}
	errs = append(errs, checkLinks(file.Rel, filepath.Dir(file.Abs), data)...)
	return errs, nil
}

func checkHeading(rel string, data []byte) *lintError {
	scanner := bufio.NewScanner(bytes.NewReader(data))
	lineNum := 0
	for scanner.Scan() {
		lineNum++
		text := strings.TrimSpace(scanner.Text())
		if text == "" {
			continue
		}
		if strings.HasPrefix(text, "# ") {
			return nil
		}
		return &lintError{
			File:    rel,
			Line:    lineNum,
			Message: "missing level-1 heading at top of file",
		}
	}
	return &lintError{
		File:    rel,
		Line:    0,
		Message: "file is empty",
	}
}

var linkPattern = regexp.MustCompile(`\[[^\]]+\]\(([^)]+)\)`)

func checkLinks(rel, baseDir string, data []byte) []lintError {
	var errs []lintError
	scanner := bufio.NewScanner(bytes.NewReader(data))
	lineNum := 0
	for scanner.Scan() {
		lineNum++
		line := scanner.Text()
		for _, match := range linkPattern.FindAllStringSubmatch(line, -1) {
			if len(match) < 2 {
				continue
			}
			target := strings.TrimSpace(match[1])
			if target == "" {
				continue
			}
			if strings.HasPrefix(target, "#") {
				continue
			}
			if strings.Contains(target, "://") || strings.HasPrefix(target, "mailto:") {
				continue
			}
			if idx := strings.IndexRune(target, '#'); idx >= 0 {
				target = target[:idx]
			}
			target = strings.TrimSpace(target)
			if target == "" || strings.HasPrefix(target, "{") {
				continue
			}
			fullPath := filepath.Join(baseDir, target)
			if _, err := os.Stat(fullPath); err != nil {
				errs = append(errs, lintError{
					File:    rel,
					Line:    lineNum,
					Message: fmt.Sprintf("broken relative link %q", target),
				})
			}
		}
	}
	return errs
}

func runPublish(root, manifestPath, versionOverride, outputDir string) error {
	manifest, err := loadManifest(manifestPath)
	if err != nil {
		return err
	}
	releaseName := versionOverride
	if releaseName == "" {
		releaseName = manifest.Current
	}
	if strings.TrimSpace(releaseName) == "" {
		return errors.New("no release name provided (set manifest current or use -version)")
	}
	destDir := filepath.Join(outputDir, releaseName)
	if err := os.RemoveAll(destDir); err != nil {
		return err
	}
	if err := copyDocs(filepath.Join(root, "docs"), destDir); err != nil {
		return err
	}
	if err := writeZip(destDir, filepath.Join(outputDir, fmt.Sprintf("%s.zip", releaseName))); err != nil {
		return err
	}
	fmt.Printf("published docs snapshot %s at %s\n", releaseName, displayPath(root, destDir))
	return nil
}

func loadManifest(path string) (manifest, error) {
	var m manifest
	data, err := os.ReadFile(path)
	if err != nil {
		return m, err
	}
	if err := yaml.Unmarshal(data, &m); err != nil {
		return m, err
	}
	return m, nil
}

func copyDocs(src, dest string) error {
	return filepath.WalkDir(src, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(src, path)
		if err != nil {
			return err
		}
		if rel == "." {
			return os.MkdirAll(dest, 0o755)
		}
		if d.IsDir() {
			if strings.HasPrefix(rel, "releases") {
				return fs.SkipDir
			}
			return os.MkdirAll(filepath.Join(dest, rel), 0o755)
		}
		if strings.HasPrefix(rel, ".DS_Store") {
			return nil
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		target := filepath.Join(dest, rel)
		return os.WriteFile(target, data, 0o644)
	})
}

func writeZip(srcDir, zipPath string) error {
	if err := os.MkdirAll(filepath.Dir(zipPath), 0o755); err != nil {
		return err
	}
	tmpPath := zipPath + ".tmp"
	f, err := os.Create(tmpPath)
	if err != nil {
		return err
	}
	defer f.Close()

	zipWriter := zip.NewWriter(f)
	err = filepath.WalkDir(srcDir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		rel, err := filepath.Rel(srcDir, path)
		if err != nil {
			return err
		}
		file, err := os.Open(path)
		if err != nil {
			return err
		}
		defer file.Close()
		w, err := zipWriter.Create(rel)
		if err != nil {
			return err
		}
		if _, err := io.Copy(w, file); err != nil {
			return err
		}
		return nil
	})
	if err != nil {
		zipWriter.Close()
		return err
	}
	if err := zipWriter.Close(); err != nil {
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Rename(tmpPath, zipPath)
}
