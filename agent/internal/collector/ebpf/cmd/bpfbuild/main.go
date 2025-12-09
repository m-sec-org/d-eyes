package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

func main() {
	var (
		source    = flag.String("source", filepath.Clean("../programs/syscall.bpf.c"), "CO-RE C source file")
		output    = flag.String("out", filepath.Clean("../programs/syscall.bpf.o"), "output object path")
		clangPath = flag.String("clang", "clang", "clang binary used for BPF compilation")
		arch      = flag.String("arch", runtime.GOARCH, "target CPU architecture (amd64, arm64, ...)")
		kernelDir = flag.String("kernel", "", "kernel headers include directory (optional)")
		btfPath   = flag.String("btf", "", "explicit BTF file path, e.g. /sys/kernel/btf/vmlinux")
		modules   = flag.String("modules", "", "comma separated list of modules to enable (maps to -DMODULE_<NAME>=1 or category:<group>)")
		extraC    = flag.String("cflags", "", "additional clang CFLAGS")
		dryRun    = flag.Bool("dry-run", false, "print the clang command without executing")
	)
	flag.Parse()

	opts := buildOptions{
		source:    *source,
		output:    *output,
		clangPath: *clangPath,
		arch:      *arch,
		kernelDir: *kernelDir,
		btfPath:   *btfPath,
		dryRun:    *dryRun,
	}
	if strings.TrimSpace(*modules) != "" {
		opts.modules = strings.Split(*modules, ",")
	}
	if strings.TrimSpace(*extraC) != "" {
		opts.extraC = strings.Fields(*extraC)
	}
	if err := runBuild(opts); err != nil {
		fmt.Fprintf(os.Stderr, "build failed: %v\n", err)
		os.Exit(1)
	}
}
