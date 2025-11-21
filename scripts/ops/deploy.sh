#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT_DIR"

VERSION=${VERSION:-$(git rev-parse --short HEAD)}
NAMESPACE=${NAMESPACE:-d-eyes}
IMAGE_TAG=${IMAGE_TAG:-"registry.local/d-eyes/server:${VERSION}"}

echo "[deploy] building server image ${IMAGE_TAG}"
docker build -t "${IMAGE_TAG}" server

echo "[deploy] pushing image"
docker push "${IMAGE_TAG}"

echo "[deploy] updating k8s deployment (namespace=${NAMESPACE})"
kubectl set image deployment/d-eyes-server d-eyes-server="${IMAGE_TAG}" -n "${NAMESPACE}"
kubectl rollout status deployment/d-eyes-server -n "${NAMESPACE}"

echo "[deploy] verifying basic health"
kubectl get pods -n "${NAMESPACE}"
