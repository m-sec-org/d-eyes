#!/usr/bin/env bash
set -euo pipefail

LOG_FILE=${LOG_FILE:-/var/log/d-eyes/audit.log}
LOKI_ENDPOINT=${LOKI_ENDPOINT:-http://localhost:3100/loki/api/v1/push}
LOKI_LABELS=${LOKI_LABELS:-{job="d_eyes_audit"}}

if [[ ! -f "$LOG_FILE" ]]; then
  echo "log file $LOG_FILE not found" >&2
  exit 1
fi

echo "[logging] shipping $LOG_FILE to $LOKI_ENDPOINT"
tail -F "$LOG_FILE" | while read -r line; do
  ts=$(date +%s%N)
  payload=$(cat <<JSON
{
  "streams": [
    {
      "stream": $LOKI_LABELS,
      "values": [["$ts", "$line"]]
    }
  ]
}
JSON
)
  curl -s -X POST -H "Content-Type: application/json" -d "$payload" "$LOKI_ENDPOINT" >/dev/null || true
done
