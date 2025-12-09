#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR=/home/liuhongtao
cd /agent/internal/collector/ebpf

MODULES=process,filesystem,network
GOFLAGS=

go run  ./cmd/bpfbuild   -dry-run   -modules    -source programs/syscall.bpf.c   -out programs/syscall.bpf.o >/dev/null
