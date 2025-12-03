#!/usr/bin/env bash
set -euo pipefail

# smoke-ebpf-prereqs.sh 验证 eBPF Collector 在依赖缺失时的报错体验。
# 运行前请设置 DEYES_BIN 指向已编译的 d-eyes CLI（默认 ./d-eyes）。

CLI_BIN=${DEYES_BIN:-./d-eyes}
DURATION=${DEYES_SMOKE_DURATION:-3s}
SCENARIOS=${1:-all}

ensure_cli() {
	if command -v "${CLI_BIN}" >/dev/null 2>&1; then
		CLI_BIN=$(command -v "${CLI_BIN}")
	elif [[ ! -x "${CLI_BIN}" ]]; then
		echo "ERROR: 无法找到可执行的 d-eyes 二进制，请通过 DEYES_BIN 指定路径" >&2
		exit 1
	fi
}

run_collect_expect_fail() {
	local scenario=$1
	local cfg=$2
	local log=$3
	local expect=$4

	echo "[*] 场景: ${scenario}"
	if "${CLI_BIN}" --config "${cfg}" collect --collector diag-ebpf --duration "${DURATION}" >"${log}" 2>&1; then
		echo "ERROR: 预期 ${scenario} 失败，但命令成功返回" >&2
		exit 1
	fi
	if ! grep -qi "${expect}" "${log}"; then
		echo "ERROR: ${scenario} 日志未包含预期关键信息: ${expect}" >&2
		echo "----- 采集输出 -----" >&2
		cat "${log}" >&2
		echo "--------------------" >&2
		exit 1
	}
	grep -i "${expect}" -m1 "${log}"
	echo "[OK] ${scenario} 校验通过"
}

scenario_missing_clang() {
	local tmpdir
	tmpdir=$(mktemp -d)
	local cfg="${tmpdir}/config.yaml"
	local log="${tmpdir}/clang.log"
	cat >"${cfg}" <<'EOF'
collectors:
  - name: diag-ebpf
    kind: ebpf
    probes: ["sys_enter_execve"]
    settings:
      clang_path: /nonexistent/d-eyes-clang
EOF
	run_collect_expect_fail "clang 缺失" "${cfg}" "${log}" "clang not found"
	if [[ "${DEYES_SMOKE_KEEP_TMP:-0}" != "1" ]]; then
		rm -rf "${tmpdir}"
	else
		echo "[INFO] 临时文件保留在 ${tmpdir}"
	}
}

scenario_missing_btf() {
	local tmpdir
	tmpdir=$(mktemp -d)
	local cfg="${tmpdir}/config.yaml"
	local log="${tmpdir}/btf.log"
	cat >"${cfg}" <<'EOF'
collectors:
  - name: diag-ebpf
    kind: ebpf
    probes: ["sys_enter_execve"]
    settings:
      btf_path: /nonexistent/d-eyes-vmlinux
EOF
	run_collect_expect_fail "BTF 缺失" "${cfg}" "${log}" "kernel BTF file"
	if [[ "${DEYES_SMOKE_KEEP_TMP:-0}" != "1" ]]; then
		rm -rf "${tmpdir}"
	else
		echo "[INFO] 临时文件保留在 ${tmpdir}"
	}
}

main() {
	ensure_cli
	case "${SCENARIOS}" in
	all)
		scenario_missing_clang
		scenario_missing_btf
		;;
	clang)
		scenario_missing_clang
		;;
	btf)
		scenario_missing_btf
		;;
	*)
		echo "Usage: $0 [all|clang|btf]" >&2
		exit 1
		;;
	esac
	echo "[DONE] eBPF 依赖诊断完成"
}

main "$@"
