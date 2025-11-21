# Proposal: add-agent-remote-coverage

## Summary
Deliver a deterministic, fully automated test suite that exercises the remote agent control loop, its gRPC client, and the offline result cache until package coverage for `agent/internal/agent` and `agent/internal/agent/remote` reaches 100%.

## Why
- The remote pathway is the heart of the agent: it owns registration, heartbeat, task polling, execution and result replay (`agent/internal/agent/daemon.go:26-329`). Today only the helper `applyRemotePayload` is indirectly verified by `TestCLIAndRemoteContractAlignment` (`agent/internal/agent/daemon_test.go:23-155`), leaving the rest untested even though it drives production automation.
- Reliability depends on code that talks to infrastructure: `remote.Client` orchestrates Register / Heartbeat / PullTasks / ReportResult with TLS handshakes (`agent/internal/agent/remote/client.go:37-238`) and `remote.FileStore` implements the resilient replay buffer (`agent/internal/agent/remote/cache.go:14-134`). A regression there would break the spec requirement “Resilient Result Delivery,” yet we currently rely on ad-hoc manual testing.
- Achieving “coverage 100%” from the request requires seams that do not exist yet (e.g., `remoteRunner` hardcodes `*remote.Client`, `internal.TaskRunnerByName`, and real disk access). Without new dependency injection points we cannot unit-test failure loops, sandbox merges, or telemetry fan-out.

## What Changes
1. **Add test seams without changing runtime semantics.**
   - Introduce small interfaces (`remoteClient`, `resultStore`, `systemClock`) consumed by `remoteRunner` plus constructor helpers so tests can swap in fakes while the production path still instantiates real clients/stores (`agent/internal/agent/daemon.go:53-75`).
   - Provide a test-only helper in `internal` (e.g., `internal.OverrideTaskRunnerForTesting`) so remote-runner tests can register stub runners without executing real scanners (`agent/internal/app.go:274-321`).
   - Expose a narrow hook in `internal/telemetry` to override samplers/collectors so heartbeat tests can assert payload content referenced at `agent/internal/agent/remote/client.go:146-148` and `agent/internal/agent/daemon.go:134,256`.

2. **Build an in-memory gRPC harness.**
   - Spin up a `bufconn`-backed implementation of `serverpb.AgentServiceServer` inside tests to drive `remote.Client` through Register/Heartbeat/PullTasks/ReportResult without a real network stack.
   - Cover TLS branches by generating ephemeral CA/cert fixtures under `t.TempDir()` and asserting that `dialOptions` & `buildTLSCredentials` enforce the expected errors/success paths (`agent/internal/agent/remote/client.go:199-238`).

3. **Author comprehensive tests.**
   - `agent/internal/agent/daemon_test.go`: new suites for `RunRemote`, `remoteRunner.run`, `runOnce`, `pollOnce`, `processLease`, `reportFailure`, `flushPending`, `applyRemotePayload`, `extractFlagMap`, and type converters, including sandbox merge behavior and telemetry metadata stitching.
   - New `_test.go` files under `agent/internal/agent/remote/` that validate `FileStore` persistence / corruption tolerance, `Client` happy-path & error propagation, TLS helper behavior, and heartbeat latency tracking.
   - Use deterministic fake task runners plus fake telemetry collectors to assert end-to-end result caching + replay when gRPC pushes back or the network reconnects (`agent/internal/agent/daemon.go:265-327`).

4. **Enforce and document the 100% bar.**
   - Add a `make agent-cover` (or README snippet) that runs `go test ./agent/internal/agent/... -coverpkg=github.com/m-sec-org/d-eyes/agent/internal/agent,...,github.com/m-sec-org/d-eyes/agent/internal/agent/remote -cover` and fails if the aggregated coverage is below 100%.
   - Document in `agent/README.md` (or a new `docs/TESTING.md`) how to run the suite and interpret failures so contributors can reproduce the results locally.

## Out of Scope
- Changing how the server issues leases or stores results.
- Refactoring the task implementations themselves (respond, audit, etc.) beyond injecting stub-friendly hooks.
- Performance optimizations; the work is strictly for correctness and coverage.

## Impact / Risks
- **Runtime risk:** Minimal—the injection points keep default behavior identical but we must guard against accidental nil interfaces. Additional unit tests mitigate this by exercising the real constructors.
- **Test duration:** The gRPC harness will spin up servers per test; we will keep suites parallelizable and use short poll intervals to stay below a few seconds of runtime.
- **TLS fixtures:** Generating certificates inside tests adds crypto dependencies but avoids shipping static keys in the repo.

## Success Metrics
- `go test ./agent/internal/agent/... ./agent/internal/agent/remote/... -cover` reports 100% statement coverage for both packages.
- New tests deterministically fail when remote registration, heartbeat, payload merge, or result replay changes behavior.
- Spec requirements for agent reliability gain explicit automated verification (see accompanying delta).
