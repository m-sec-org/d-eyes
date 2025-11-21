# Proposal: refactor-agent-runner-injection

## Summary
Refactor D-Eyes task runners so their heavy dependencies (host summary, inventory scanners, SBOM collectors, BAS sandbox) are accessed via injectable interfaces. This enables deterministic unit tests while keeping D-Eyes usable both as a standalone CLI and as a server-managed agent.

## Background & Pain Points
- **Current runner design** (`agent/internal/tasks/respond.go`, `inventory.go`, `supplychain.go`, `baseline.go`, `bas.go`) directly invokes helper functions that hit the filesystem, network, sandbox runtime, and YARA engine without seams. Tests must either execute full scans (slow/flaky) or use CLI stubs that bypass business logic entirely.
- **CLI vs. Agent parity**: When D-Eyes runs as a CLI tool, we want the real modules. When remote agents execute tasks from the server, they should use the same interfaces. Injecting dependencies (via interfaces/factories) keeps behavior identical while allowing tests to provide lightweight fakes.
- **ThreatIntel/Sandbox/YARA**: Similar tight coupling exists in `pkg/threatintel`, `internal/sandbox`, and `internal/detect`. Without abstraction, we cannot simulate cache hits, sandbox approvals, or rule parsing in unit tests.

## Goals
1. Introduce interfaces and factories around each runner's heavy operations so that tests can substitute mocks while production code continues to use real implementations.
2. Ensure D-Eyes CLI and remote agent both rely on the same injectable components, preserving current behavior.
3. Provide clear extension points for future modules (e.g., new respond profiles) without breaking tests.

## Proposed Architecture Changes
### 1. Task Runner Dependency Injection
- **Respond Runner**: Create a `RespondModuleExecutor` interface with methods like `RunHostSummary`, `RunNetworkAnalysis`, `RunFileScan`. Provide a default implementation that wraps existing functions. Tests can inject a fake executor.
- **Inventory/Audit/Baseline/Supplychain**: Introduce `InventoryExecutor`, `AuditExecutor`, `BaselineLoader`, `SupplyChainCollector`, each responsible for I/O-heavy operations (filesystem walks, network scans, SBOM build). Runner structs will accept these interfaces (either via global factory or struct field) and default to current behavior.
- **BAS**: Wrap sandbox launching/logging in a `BASSandboxRunner` plus `ScenarioLoader`. Provide deterministic fake scenario data for tests.

Implementation pattern:
```go
type RespondRunner struct {
    executor RespondExecutor
}

func NewRespondRunner(exec RespondExecutor) *RespondRunner {
    if exec == nil {
        exec = defaultRespondExecutor{}
    }
    return &RespondRunner{executor: exec}
}

func (r *RespondRunner) Run(ctx context.Context, req TaskRequest) (TaskResult, error) {
    summary := r.executor.RunHostSummary(...)
    ...
}
```

### 2. ThreatIntel & Sandbox Hooks
- Wrap `pkg/threatintel.Manager` creation behind an interface (`ThreatIntelProvider`) so tests can supply fake verdicts.
- Expose a `SandboxController` interface for BAS and `tasks.bas` telemetry. Default implementation delegates to existing sandbox manager; tests inject in-memory controllers to verify telemetry serialization.

### 3. Detection Backend Abstraction
- Provide a `RuleEngineFactory` that returns the Go engine / backend, allowing tests to inject synthetic rule bundles or failure scenarios without reading real rule files.

### 4. CLI/Remote Integration
- Update `internal/app.go` and `internal/agent/daemon.go` to construct runners via new factories, ensuring both CLI and remote mode obtain the same default implementations.
- Expose optional environment variables or build tags for swapping implementations in integration tests (e.g., `D_EYES_TEST_EXECUTORS=stub`).

## Impact
- **Testing**: Once interfaces exist, we can add deterministic unit tests covering all branches (e.g., respond profile selection, inventory validation, baseline policy enforcement) without relying on real scans.
- **Runtime**: Default behavior remains unchanged; interfaces simply wrap existing logic. Performance impact is negligible (one extra indirection).
- **Extensibility**: Future modules can implement these interfaces to add capabilities without touching core runner flow.

## Risks & Mitigation
- **Complexity**: Introducing interfaces may add boilerplate. We'll keep defaults minimal and co-locate implementations with existing code.
- **Regression**: Refactor must maintain CLI/agent parity. We'll add integration tests (existing CLI suite + new runner tests) to catch deviations.

## Next Steps
1. Design interfaces and default executors per runner.
2. Update runners to accept injected dependencies (constructor or package-level factory).
3. Adjust CLI/runtime wiring to instantiate default executors.
4. Add unit tests using fakes, achieving 100% coverage per package.
