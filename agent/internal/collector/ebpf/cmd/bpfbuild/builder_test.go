package main

import "testing"

func TestClangArgsIncludeModules(t *testing.T) {
	opts := buildOptions{
		source:    "src.c",
		output:    "out.o",
		clangPath: "clang",
		arch:      "amd64",
		modules:   []string{"process", "network"},
		dryRun:    true,
	}
	args := opts.clangArgs()
	found := false
	for _, arg := range args {
		if arg == "-DMODULE_PROCESS=1" {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected process module define, args=%v", args)
	}
}

func TestRunBuildDryRun(t *testing.T) {
	opts := buildOptions{
		source:    "src.c",
		output:    "out.o",
		clangPath: "clang",
		dryRun:    true,
	}
	if err := runBuild(opts); err != nil {
		t.Fatalf("dry-run should succeed: %v", err)
	}
}
