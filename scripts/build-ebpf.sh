#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
pushd "$ROOT/agent/internal/collector/ebpf" >/dev/null

CLANG_BIN="${CLANG:-clang}"
OUT="${OUT:-programs/syscall.bpf.o}"
SRC="${SRC:-programs/syscall.bpf.c}"
MODULES="${MODULES:-process}"
KERNEL_INCLUDE="${KERNEL_INCLUDE:-}"
BTF_PATH="${BTF_PATH:-}"

RUN_OPTS=()
if [[ -n "$KERNEL_INCLUDE" ]]; then
  RUN_OPTS+=("-kernel" "$KERNEL_INCLUDE")
fi
if [[ -n "$BTF_PATH" ]]; then
  RUN_OPTS+=("-btf" "$BTF_PATH")
fi

go run ./cmd/bpfbuild \
  -clang "$CLANG_BIN" \
  -source "$SRC" \
  -out "$OUT" \
  -modules "$MODULES" \
  "${RUN_OPTS[@]}"

popd >/dev/null
