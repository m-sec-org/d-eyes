#!/usr/bin/env bash
set -euo pipefail

API_BASE=${API_BASE:-http://localhost:8080/api/v1}
API_KEY=${API_KEY:-}
TASK_ID=${TASK_ID:-}

if [[ -z "$TASK_ID" ]]; then
  echo "TASK_ID 环境变量未设置" >&2
  exit 1
fi

echo "[trace] tracking task $TASK_ID via SSE"
headers=(-H "Accept: text/event-stream")
if [[ -n "$API_KEY" ]]; then
  headers+=(-H "X-API-Key: $API_KEY")
fi

curl -sN "${API_BASE}/tasks/stream" "${headers[@]}" | \
  while read -r line; do
    if [[ "$line" == data:* ]]; then
      payload=${line#data: }
      echo "$payload" | jq --arg task "$TASK_ID" 'select(.task_id == $task or .metadata.task_id == $task)' || true
    fi
  done
