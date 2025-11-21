#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT_DIR"

NAMESPACE=${NAMESPACE:-d-eyes}
IMAGE_TAG=${IMAGE_TAG:-}

if [[ -z "$IMAGE_TAG" ]]; then
  echo "IMAGE_TAG must be provided" >&2
  exit 1
fi

echo "[upgrade] set image to ${IMAGE_TAG}"
kubectl set image deployment/d-eyes-server d-eyes-server="${IMAGE_TAG}" -n "${NAMESPACE}"
kubectl rollout status deployment/d-eyes-server -n "${NAMESPACE}"
