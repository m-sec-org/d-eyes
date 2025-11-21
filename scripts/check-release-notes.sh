#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

manifest_file="docs/version.yaml"
if [[ ! -f "$manifest_file" ]]; then
  echo "release manifest $manifest_file not found" >&2
  exit 1
fi

current_version="$(awk '/^current:/ {print $2; exit}' "$manifest_file")"
if [[ -z "${current_version}" ]]; then
  echo "failed to read current version from $manifest_file" >&2
  exit 1
fi

notes_file="docs/release-notes/${current_version}.md"
if [[ ! -f "$notes_file" ]]; then
  echo "release notes not found: $notes_file" >&2
  exit 1
fi

if ! grep -q "## ${current_version}" docs/changelog.md; then
  echo "changelog missing heading for ${current_version} (docs/changelog.md)" >&2
  exit 1
fi

echo "release notes and changelog ready for version ${current_version}"
