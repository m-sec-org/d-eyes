## 1. Context & Test Harness
- [x] 1.1 Review `internal/app.go`, `internal/agent/runtime.go`, and existing task runners to map CLI flag flows and shared config.
- [x] 1.2 Build a reusable CLI test helper that spawns `Runtime.Run` with custom config/env plus capture of stdout/stderr, ensuring global singletons reset between runs.

## 2. Command Coverage
- [x] 2.1 Add integration tests covering `respond`, `audit`, `inventory`, `supplychain`, `baseline`, and `bas` commands, asserting:
  - config fallback (targets/profile) warnings
  - JSON/quiet flag propagation
  - exit codes per scenario (success, missing args)
- [x] 2.2 Ensure remote CLI command is exercised, verifying it passes config through `RunRemote`.

## 3. Threat Intel & Sandbox Hooks
- [x] 3.1 Provide stubs/mocks for threat-intel manager and sandbox approvals so tests run offline.
- [x] 3.2 Verify CLI flags (`--ti-mode`, `--sandbox-approve`) update the underlying TaskRequest metadata.

## 4. Coverage Enforcement & Docs
- [x] 4.1 Update README or CONTRIBUTING with instructions for running the CLI coverage suite and confirming 100% coverage for CLI packages.
- [x] 4.2 Consider adding a `go test -coverpkg` check (or Makefile target) scoped to CLI-related packages to guard regression.
