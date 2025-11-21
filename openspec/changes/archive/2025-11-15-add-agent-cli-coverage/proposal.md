# Proposal: add-agent-cli-coverage

## Summary
Develop a deterministic CLI regression suite that drives `d-eyes` commands end-to-end (respond, audit, inventory, supplychain, baseline, bas, remote) to guarantee a sustained 100% statement coverage for the CLI layer and prevent deviations between flags, config fallbacks, and remote mode defaults.

## Why
- The current remote coverage change only protects the server-driven execution path; the local CLI entrypoints remain untested even though they fan in to the same task runners. A silent regression in CLI flag handling would break on-prem workflows without triggering server automation tests.
- Tasks such as respond/inventory rely on config fallback, notices, and threat-intel initialization. When users run `d-eyes respond ...` locally, we must ensure CLI wiring honors config defaults (`config.tasks.*`, `config.discovery.targets`) and produces the documented JSON/quiet outputs.
- We also need parity between CLI commands and the `remote` subcommand so that operators deploying the agent in air-gapped environments can rely on the CLI behavior; enforcing 100% coverage on the CLI entry layer is the safest gate.

## What Changes
1. Introduce test-friendly wiring around `internal.NewRuntime()` to capture CLI stdout/stderr while injecting temporary config files.
2. Build table-driven integration tests under `agent/internal/agent/cli_runtime_test.go` (or similar) that execute each user-facing command with representative flags, verifying JSON/quiet output, config fallback notices, sandbox approvals, and exit codes.
3. Ensure remote CLI command is also executed with stubbed `RunRemote` to assert config propagation (coexisting with daemon coverage work).
4. Add documentation describing how to run the CLI test suite to maintain 100% coverage.

## Impact
- No production behavior change; only test harness and documentation updates.
- Developer workflow gains an automated CLI regression suite, reducing manual QA load.
- Slight increase in test runtime (CLI integration tests) but still acceptable for CI.

## Risks
- Need to carefully stub heavy dependencies (YARA, network scans) to keep tests fast.
- Must ensure global singletons (config, quiet mode) are reset between tests to avoid cross-test interference.
