# Proposal: add-agent-core-coverage

## Summary
Augment the agent test suite beyond CLI scaffolding by covering the actual task runners (respond/inventory/supplychain/baseline/bas), ThreatIntel SDK, sandbox orchestration, and the Go YARA backend so that business logic—not just command wiring—achieves 100% statement coverage.

## Why
- The new CLI coverage change substitutes every runner with stubs, so core logic in `agent/internal/tasks/*`, `agent/pkg/threatintel`, `agent/internal/sandbox`, and `agent/internal/detect/*` still reports `? [no test files]`. Any regression in these modules would go unnoticed despite "100%" CLI coverage.
- Respond runner selects profile-specific modules, aggregates risk, and emits notices. Inventory runner parses networks/ports and enforces validation. Supplychain/baseline workflows parse files and enforce policy; none of this logic has automated verification.
- ThreatIntel manager, sandbox manager, and the Go-native YARA backend have no tests despite being critical for remote/CLI parity.
- To truly guarantee 100% coverage for agent functionality (as requested), we must write unit tests for these packages and wire additional mocks where needed.

## What Changes
1. **Task runner tests**: add `_test.go` files for respond, audit, inventory, supplychain, baseline, and bas modules using lightweight fixtures and dependency injection (mock manager, fake filesystem, stub sandbox).
2. **ThreatIntel SDK tests**: unit-test `pkg/threatintel/manager.go` for cache hits, heuristic classifications, and error handling.
3. **Sandbox/BAS telemetry**: test `internal/tasks/bas.go` sandbox stats encoding plus the sandbox manager fallback paths.
4. **YARA backend tests**: cover rule parsing, stats collection, metadata handling inside `internal/detect/backend` and `internal/detect/engine/goengine`.
5. **Coverage enforcement**: extend README/CI instructions with a `go test -coverpkg` command spanning these packages to ensure the new tests keep coverage at 100%.

## Impact
- Healthier regression net for agent business logic.
- Slightly longer `go test` time but still manageable; tests rely on fixtures rather than heavy scans.
- Enables contributors to catch regressions locally.

## Risks
- Need to mock filesystem/network carefully to avoid flakiness.
- Some modules (e.g., YARA) require synthetic rules and may produce large fixtures; must keep them minimal to avoid slowing CI.
