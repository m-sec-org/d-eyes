## 1. Coverage Baseline & Helpers
- [x] 1.1 Capture authoritative `go test ./... -cover` output and enumerate every package <100%.
- [x] 1.2 Build shared testing helpers (fake report manager, sandbox/controller fakes, temp config loader, asset scanner stub, telemetry captor) reusable by packages lacking seams.

## 2. Task & Config Packages
- [x] 2.1 Elevate `internal/tasks` (including `assets/reporters`, `progress`, `telemetry`, SBOM helpers) to 100% via table-driven tests.
- [x] 2.2 Add coverage for `pkg/config`, `pkg/logs`, `pkg/reporting`, ensuring CLI defaults, logging init, and manager behaviors are testable.

## 3. Detect & ThreatIntel Pipeline
- [x] 3.1 Complete coverage for `internal/detect` subpackages (rules manager, scoring, utils, yara bindings) using inline rule fixtures.
- [x] 3.2 Extend threat intel suites to cover connector errors, cache eviction, sandbox + TI integration, guaranteeing 100% statements.

## 4. SBOM / Assets / CLI Runtimes
- [x] 4.1 Write deterministic tests for `internal/sbom/*` and `internal/assets/utils/reporters`, including file walkers, manifest parsing, and progress reporting.
- [x] 4.2 Ensure CLI runtime (`cmd/agent`, `internal/app`, `internal/agent/runtime`) and remote daemon achieve 100% via fake runner factories and coverage hooks.

## 5. Enforcement & Docs
- [x] 5.1 Add Makefile/CI targets running `go test -coverpkg ./...` with a unified coverage profile; fail build if total <100%.
- [x] 5.2 Update README/CONTRIBUTING with new coverage command, plus badge/reporting instructions.
