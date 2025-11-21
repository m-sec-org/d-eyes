#!/usr/bin/env bash
set -euo pipefail

NAMESPACE=${NAMESPACE:-d-eyes}
IMAGE_CANARY=${IMAGE_CANARY:-}
IMAGE_STABLE=${IMAGE_STABLE:-}
CANARY_WEIGHT=${CANARY_WEIGHT:-20}

if [[ -z "$IMAGE_CANARY" || -z "$IMAGE_STABLE" ]]; then
  echo "IMAGE_CANARY and IMAGE_STABLE must be set" >&2
  exit 1
fi

echo "[gray] deploying canary (${CANARY_WEIGHT}%)"
cat <<YAML | kubectl apply -n "$NAMESPACE" -f -
apiVersion: apps/v1
kind: Deployment
metadata:
  name: d-eyes-server-canary
spec:
  replicas: 1
  selector:
    matchLabels:
      app: d-eyes-server
      role: canary
  template:
    metadata:
      labels:
        app: d-eyes-server
        role: canary
    spec:
      containers:
        - name: d-eyes-server
          image: ${IMAGE_CANARY}
          env:
            - name: ROLE
              value: canary
YAML

kubectl rollout status deployment/d-eyes-server-canary -n "$NAMESPACE"

echo "[gray] ensure stable deployment uses ${IMAGE_STABLE}"
kubectl set image deployment/d-eyes-server d-eyes-server="${IMAGE_STABLE}" -n "$NAMESPACE"
