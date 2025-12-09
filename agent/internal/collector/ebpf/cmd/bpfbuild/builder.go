package main

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
)

type buildOptions struct {
	source    string
	output    string
	clangPath string
	arch      string
	kernelDir string
	btfPath   string
	modules   []string
	extraC    []string
	dryRun    bool
}

func (o buildOptions) validate() error {
	if strings.TrimSpace(o.source) == "" {
		return errors.New("source path required")
	}
	if strings.TrimSpace(o.output) == "" {
		return errors.New("output path required")
	}
	if strings.TrimSpace(o.clangPath) == "" {
		return errors.New("clang path required")
	}
	if strings.TrimSpace(o.arch) == "" {
		o.arch = runtime.GOARCH
	}
	return nil
}

func (o buildOptions) clangArgs() []string {
	args := []string{"-O2", "-g", "-target", "bpf", "-c", filepath.Clean(o.source), "-o", filepath.Clean(o.output)}
	switch strings.ToLower(o.arch) {
	case "amd64", "x86_64":
		args = append(args, "-D__TARGET_ARCH_x86")
	case "arm64", "aarch64":
		args = append(args, "-D__TARGET_ARCH_arm64")
	default:
		args = append(args, "-D__TARGET_ARCH_x86")
	}
	if o.kernelDir != "" {
		args = append(args, "-I", filepath.Clean(o.kernelDir))
	}
	if o.btfPath != "" {
		args = append(args, fmt.Sprintf("-mllvm=-btf-info-dir=%s", filepath.Clean(o.btfPath)))
	}
	for _, mod := range o.modules {
		mod = strings.TrimSpace(mod)
		if mod == "" {
			continue
		}
		define := fmt.Sprintf("-DMODULE_%s=1", strings.ToUpper(strings.ReplaceAll(mod, "-", "_")))
		args = append(args, define)
	}
	if len(o.extraC) > 0 {
		args = append(args, o.extraC...)
	}
	return args
}

func runBuild(o buildOptions) error {
	if err := o.validate(); err != nil {
		return err
	}
	args := o.clangArgs()
	if o.dryRun {
		fmt.Printf("%s %s\n", o.clangPath, strings.Join(args, " "))
		return nil
	}
	cmd := exec.Command(o.clangPath, args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}
