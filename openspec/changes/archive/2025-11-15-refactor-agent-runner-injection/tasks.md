## 1. Dependency Mapping
- [x] 1.1 Catalogue heavy operations inside `agent/internal/tasks/*`, `pkg/threatintel`, `internal/sandbox`, and `internal/detect`, and define interface boundaries for each runner.
- [x] 1.2 Propose constructor/factory patterns ensuring CLI + remote paths build the same default executors.

## 2. Runner Refactors
- [x] 2.1 Refactor respond runner to accept a pluggable module selector/executor (done via `RespondRunnerWithSelector`).
- [x] 2.2 Refactor inventory runner to use an injectable `inventoryExecutor` (done via `InventoryRunnerWithExecutor`).
- [x] 2.3 Introduce `SupplyChainCollector`, `BaselineLoader`, and BAS dependency interfaces (`ScenarioLoader`, `SandboxExecutor`, `TelemetryEncoder`) plus default implementations.
- [x] 2.4 Update remaining task runners (supplychain, baseline, BAS) to depend on these interfaces, maintaining existing behavior but enabling injection.

## 3. Core Services Abstraction
- [x] 3.1 Introduce `ThreatIntelProvider` and `SandboxController` interfaces; adapt TaskRequest initialization to use them.
- [x] 3.2 Abstract YARA backend via `RuleEngineFactory`, enabling synthetic rules in tests.

## 4. Wiring & Tests
- [x] 4.1 Update CLI runtime (`agent/internal/app.go`, `agent/internal/agent/runtime.go`) to instantiate runners via the new factories (RespondRunnerWithSelector, InventoryRunnerWithExecutor, SupplyChainRunnerWithCollector, BaselineRunnerWithExecutor, BASRunnerWithDeps).
- [x] 4.2 Update remote daemon (`agent/internal/agent/daemon.go`) wiring to leverage the same factories so CLI/remote share identical defaults.
- [x] 4.3 Add targeted unit tests exercising the injected runners/services using fake executors/providers.

## 5. Docs & Guidance
- [x] 5.1 Document the new injection points (developer guide / README section) explaining how to add custom executors or test doubles.
