## 1. Study Current Gaps
- [x] 1.1 Audit `agent/internal/tasks/*`, `agent/pkg/threatintel`, `agent/internal/sandbox`, and `agent/internal/detect` to map untested branches and side effects (files, network, sandbox).
- [x] 1.2 Identify dependency seams (mockable managers, fake filesystems, stub sandbox executors, synthetic YARA rules) to keep unit tests deterministic.

## 2. Task Runner Coverage
- [x] 2.1 Add targeted tests for `respond`, `inventory`, `supplychain`, `baseline`, and `bas` runners covering profile selection, config fallback, validation errors, policy enforcement, and notice generation.
- [x] 2.2 Provide fake `reporting.Manager`, sandbox manager, and threat-intel hooks so tests can assert risk accumulation and metadata emission without touching real environment.

## 3. ThreatIntel & Sandbox Modules
- [x] 3.1 Write table-driven tests for `pkg/threatintel` (cache TTL, indicator classification, error conditions) achieving 100% statements.
- [x] 3.2 Cover sandbox telemetry and stats encoding in `internal/tasks/bas.go` plus sandbox manager fallback paths, ensuring metadata is serialized correctly.

## 4. Detection Backend Tests
- [x] 4.1 Add unit tests for `internal/detect/backend` and `internal/detect/engine/goengine` (rule parsing, stats, metadata placeholders) using small inline YARA rules.
- [x] 4.2 Ensure YARA backend tests run in both success and failure modes (syntax error, unsupported feature) to cover error handling.

## 5. Coverage Enforcement
- [x] 5.1 Update README/CI instructions with a `go test -coverpkg` command spanning the newly tested packages so contributors keep coverage at 100%.
- [x] 5.2 Optionally wire the command into automation (Makefile/GitHub workflow) to block regressions.
