#!/usr/bin/env bash
set -euo pipefail

DURATION_SECONDS=60
PROBES=("sys_enter_execve" "sched_process_exit")
AGENT_BINARY="./bin/agent"
OUTPUT_PATH="./artifacts/ebpf-events.jsonl"
REPORT_PATH="./artifacts/ebpf-report.json"
MIN_EVENTS=300
MAX_AVG_LATENCY_MS=250
MAX_P99_LATENCY_MS=1500
ENFORCE_THRESHOLDS=1

usage() {
	cat <<EOF
Usage: $0 [options]

Options:
  --duration <seconds>            采集持续时间（默认 60）
  --probes <a,b,c>                逗号分隔的 eBPF 探针列表（默认 sys_enter_execve,sched_process_exit）
  --agent-binary <path>           指定已构建的 agent 二进制（默认 ./bin/agent）
  --output <path>                 JSONL 事件输出路径（默认 ./artifacts/ebpf-events.jsonl）
  --report <path>                 指标报告输出路径（默认 ./artifacts/ebpf-report.json）
  --min-events <count>            最小事件数阈值（默认 300）
  --max-avg-latency-ms <value>    平均延迟阈值（默认 250ms）
  --max-p99-latency-ms <value>    P99 延迟阈值（默认 1500ms）
  --no-enforce                    仅生成报告，不进行阈值校验
  -h, --help                      显示帮助
EOF
}

while [[ $# -gt 0 ]]; do
	case "$1" in
	--duration)
		DURATION_SECONDS="$2"
		shift 2
		;;
	--probes)
		IFS=',' read -r -a PROBES <<<"$2"
		shift 2
		;;
	--agent-binary)
		AGENT_BINARY="$2"
		shift 2
		;;
	--output)
		OUTPUT_PATH="$2"
		shift 2
		;;
	--report)
		REPORT_PATH="$2"
		shift 2
		;;
	--min-events)
		MIN_EVENTS="$2"
		shift 2
		;;
	--max-avg-latency-ms)
		MAX_AVG_LATENCY_MS="$2"
		shift 2
		;;
	--max-p99-latency-ms)
		MAX_P99_LATENCY_MS="$2"
		shift 2
		;;
	--no-enforce)
		ENFORCE_THRESHOLDS=0
		shift
		;;
	-h | --help)
		usage
		exit 0
		;;
	*)
		echo "Unknown option: $1" >&2
		usage
		exit 1
		;;
	esac
done

if [[ ! -x "$AGENT_BINARY" ]]; then
	echo "[INFO] Building agent binary at $AGENT_BINARY"
	mkdir -p "$(dirname "$AGENT_BINARY")"
	if ! command -v go >/dev/null 2>&1; then
		echo "Go toolchain is required to build the agent." >&2
		exit 1
	fi
	go_version=$(go version | awk '{print $3}')
	if [[ $go_version =~ go([0-9]+)\.([0-9]+) ]]; then
		major=${BASH_REMATCH[1]}
		minor=${BASH_REMATCH[2]}
		if (( major < 1 || (major == 1 && minor < 21) )); then
			echo "[WARN] go version $go_version detected; eBPF collector依赖 github.com/cilium/ebpf v0.20.x，建议 Go 1.21+。" >&2
		fi
	fi
	go build -o "$AGENT_BINARY" ./agent
fi

if [[ $EUID -ne 0 ]]; then
	echo "[WARN] eBPF 采集通常需要 root 或 CAP_BPF 权限，请确保具备相应权限。" >&2
fi

mkdir -p "$(dirname "$OUTPUT_PATH")" "$(dirname "$REPORT_PATH")"

CFG_FILE=$(mktemp)
trap 'rm -f "$CFG_FILE"' EXIT

cat >"$CFG_FILE" <<EOF
collectors:
  - name: ebpf-perf
    kind: ebpf
    probes:
$(for probe in "${PROBES[@]}"; do
	echo "      - ${probe}"
done)
    output:
      mode: stdout
EOF

echo "[INFO] Running eBPF collector for ${DURATION_SECONDS}s ..."
"$AGENT_BINARY" collect --config "$CFG_FILE" --collector "ebpf-perf" --duration "${DURATION_SECONDS}s" >"$OUTPUT_PATH"

export PERF_EVENT_FILE="$OUTPUT_PATH"
export PERF_REPORT_FILE="$REPORT_PATH"
export PERF_DURATION="$DURATION_SECONDS"

metrics=$(python3 <<'PY'
import json
import math
import os
from datetime import datetime, timezone
from pathlib import Path

events_path = Path(os.environ["PERF_EVENT_FILE"])
report_path = Path(os.environ["PERF_REPORT_FILE"])
duration = float(os.environ.get("PERF_DURATION", "0"))

count = 0
latencies = []

def parse_timestamp(value: str) -> int:
	try:
		dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
		return int(dt.timestamp() * 1_000_000_000)
	except ValueError:
		return 0

with events_path.open("r", encoding="utf-8") as handle:
	for raw in handle:
		line = raw.strip()
		if not line.startswith("{"):
			continue
		try:
			event = json.loads(line)
		except json.JSONDecodeError:
			continue
		count += 1
		payload = event.get("payload") or {}
		kernel_ts = payload.get("kernel_timestamp_ns")
		timestamp = event.get("timestamp")
		if kernel_ts is None or timestamp is None:
			continue
		ts_ns = parse_timestamp(timestamp)
		if ts_ns <= 0:
			continue
		try:
			kernel_ns = int(kernel_ts)
		except (ValueError, TypeError):
			continue
		latency_ms = (ts_ns - kernel_ns) / 1_000_000.0
		if latency_ms >= 0:
			latencies.append(latency_ms)

latencies.sort()
avg_latency = sum(latencies) / len(latencies) if latencies else 0.0
max_latency = latencies[-1] if latencies else 0.0
if latencies:
	p99_index = max(0, int(math.ceil(0.99 * len(latencies))) - 1)
	p99_latency = latencies[p99_index]
else:
	p99_latency = 0.0
throughput = (count / duration) if duration > 0 else 0.0

report = {
	"events": count,
	"duration_s": duration,
	"throughput_eps": round(throughput, 2),
	"avg_latency_ms": round(avg_latency, 2),
	"p99_latency_ms": round(p99_latency, 2),
	"max_latency_ms": round(max_latency, 2),
}
report_path.write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")

print(f"EVENT_COUNT={count}")
print(f"AVG_LATENCY_MS={avg_latency:.2f}")
print(f"P99_LATENCY_MS={p99_latency:.2f}")
PY
)

eval "$metrics"

echo "[INFO] Events: $EVENT_COUNT"
echo "[INFO] Avg latency: ${AVG_LATENCY_MS}ms"
echo "[INFO] P99 latency: ${P99_LATENCY_MS}ms"

violations=()
if (( EVENT_COUNT < MIN_EVENTS )); then
	violations+=("events $EVENT_COUNT < $MIN_EVENTS")
fi

python3 - <<PY || violations+=("avg latency ${AVG_LATENCY_MS}ms > ${MAX_AVG_LATENCY_MS}ms")
import sys
avg = float(sys.argv[1])
limit = float(sys.argv[2])
sys.exit(0 if avg <= limit else 1)
PY
"${AVG_LATENCY_MS}" "${MAX_AVG_LATENCY_MS}"

python3 - <<PY || violations+=("p99 latency ${P99_LATENCY_MS}ms > ${MAX_P99_LATENCY_MS}ms")
import sys
p99 = float(sys.argv[1])
limit = float(sys.argv[2])
sys.exit(0 if p99 <= limit else 1)
PY
"${P99_LATENCY_MS}" "${MAX_P99_LATENCY_MS}"

if (( ENFORCE_THRESHOLDS )) && (( ${#violations[@]} > 0 )); then
	echo "[ERROR] Threshold violations:" >&2
	for violation in "${violations[@]}"; do
		echo " - $violation" >&2
	done
	exit 1
fi

echo "[DONE] eBPF perf run complete. Report saved to $REPORT_PATH"
