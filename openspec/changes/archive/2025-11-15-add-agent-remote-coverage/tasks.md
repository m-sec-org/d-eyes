## 1. Test-ready plumbing
- [x] 1.1 Introduce injectable interfaces around `remoteRunner` dependencies (remote client, result store, clocks, task runners) plus helper constructors so unit tests can supply fakes without touching production wiring (`agent/internal/agent/daemon.go`).
- [x] 1.2 Add a test-only API in `agent/internal` to override task runners and telemetry collectors, ensuring remote tests can observe metadata without invoking heavy scanners (`agent/internal/app.go`, `agent/internal/telemetry`).

## 2. Remote gRPC + TLS harness
- [x] 2.1 Implement an in-memory `serverpb.AgentServiceServer` fixture (bufconn) that drives Register / Heartbeat / PullTasks / ReportResult interactions for `remote.Client` tests (`agent/internal/agent/remote/client_test.go`).
- [x] 2.2 Provide helpers to create ephemeral CA/client cert PEMs under `t.TempDir()` so we cover both TLS success and failure branches in `dialOptions` / `buildTLSCredentials`.

## 3. Daemon coverage suite
- [x] 3.1 Write table-driven tests for `RunRemote`, `remoteRunner.run/runOnce/pollOnce`, and `processLease` covering: disabled config, metadata defaults, payload parsing, sandbox merging, unknown tasks, timeout propagation, success + error flows.
- [x] 3.2 Cover helpers (`reportFailure`, `flushPending`, `applyRemotePayload`, `extractFlagMap`, `anyToString/Bool/Duration`, `mergeSandboxConfig`) including edge cases such as nil payloads, reserved keys, conflicting sandbox directives.
- [x] 3.3 Ensure telemetry metadata attachment and cache replay paths are asserted by forcing the fake client/store to drop or accept outbound requests.
- [x] 3.4 Exercise the user-facing `d-eyes remote` CLI command end-to-end (via `internal.Runtime`) to ensure flags/env propagation and quiet/JSON defaults match remote expectations, preventing regressions in interactive usage.

## 4. Remote package coverage suite
- [x] 4.1 Unit-test `remote.FileStore` save/delete/pending behavior, including corrupt JSON files and concurrent writes.
- [x] 4.2 Exercise `remote.Client`: error cases (missing address, not connected, agent not registered) and happy path (Register → Heartbeat → PullTasks → ReportResult) using the bufconn server. Validate heartbeat telemetry contents and latency calculation.

## 5. Coverage automation & docs
- [x] 5.1 Add a documented `go test` command (Makefile target or README instructions) that enforces 100% coverage for the two packages, and wire it into CI/local guidance (e.g., `agent/README.md`).
