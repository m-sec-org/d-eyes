# Proposal: add-agent-full-coverage

## Why
Recent coverage audit (`go test ./... -cover`, run 2025-11-15) shows many agent packages still lack deterministic tests: `internal/tasks` only 35.7%, `internal/detect` 5.9%, `internal/assets/reporters/utils`, `internal/sbom/*`, `internal/telemetry`, `pkg/config/logs/reporting` and several detect sub-packages remain at 0%. Without shared fake factories/hooks for these packages, regressions slip through and CLI/remote workflows cannot be validated end-to-end prior to release. Users explicitly require “补齐整个 agent 项目的测试用例覆盖度” so QA can enforce 100% statement coverage across CLI, remote daemon, tasks, threat intel, detect pipeline, sandbox, and SBOM tooling. We must define a structured effort to elevate coverage everywhere, ensuring each subsystem exposes deterministic seams and CI publishes unified coverage gates.

## What Changes
1. **Testing Infrastructure**: extend existing fake runner factories, reporting managers, sandbox controllers, and threat intel providers so that every package (tasks, detect, assets, sbom, telemetry, config) can run hermetic tests without real files/network. Provide shared helpers for fixture creation and temporary report roots.
2. **Package-Specific Suites**: add table-driven unit tests for all remaining untested packages (`internal/detect` residual modules, `internal/assets/reporters/utils`, `internal/sbom/*`, `internal/telemetry`, `pkg/config/logs/reporting`, etc.) to cover both success and failure paths, including CLI flag parsing, config fallback, sandbox approval logic, and YARA metadata flow.
3. **Coverage Enforcement**: document and wire a `go test -coverpkg` command spanning the entire agent module into CI/Makefile so PRs fail if coverage <100%, and surface a summary badge/report in README.
4. **Spec Update**: update Align Ops Console capability to include the new “agent-wide 100% coverage” requirement along with enforcement steps.

## Impact
- Improves reliability of CLI/remote workflows, reducing regressions in tasks/detect pipeline.
- Requires new helper packages and potential light refactors to expose seams; however no runtime behavior change is intended.
- CI will take longer due to broader coverage suite; mitigated via selective caching and parallel runs.

## Rollout / Open Questions
- Need agreement on acceptable execution time for full coverage (target <5 minutes on CI).
- Decide whether to allow platform-specific skips (e.g., Windows-only SBOM scanners) and how to mock OS features.
