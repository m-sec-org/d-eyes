#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

version_flag=""
if [[ $# -gt 0 ]]; then
  version_flag="$1"
fi

go run -C server ./tools/docs -mode=lint -root "$repo_root"
publish_cmd=(go run -C server ./tools/docs -mode=publish -root "$repo_root" -manifest "$repo_root/docs/version.yaml" -out "$repo_root/docs/releases")
if [[ -n "$version_flag" ]]; then
  publish_cmd+=(-version="$version_flag")
fi
"${publish_cmd[@]}"
