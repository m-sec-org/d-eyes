#!/usr/bin/env bash
set -euo pipefail

NAMESPACE=${NAMESPACE:-d-eyes}
REVISION=${REVISION:-1}

echo "[rollback] rolling back deployment/d-eyes-server to revision ${REVISION}"
kubectl rollout undo deployment/d-eyes-server -n "${NAMESPACE}" --to-revision="${REVISION}"
kubectl rollout status deployment/d-eyes-server -n "${NAMESPACE}"
