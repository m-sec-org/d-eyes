# Proposal: refactor-core-services

## Summary
Introduce injectable interfaces for ThreatIntel (e.g., `ThreatIntelProvider`), sandbox control (`SandboxController`), and the YARA rule engine (`RuleEngineFactory`) so task runners can swap implementations for testing, remote execution, or future backends.

## Why
- `agent/pkg/threatintel/manager.go` currently creates managers directly, preventing tests from substituting fake verdict providers or caching layers.
- `agent/internal/sandbox` exposes concrete managers only; BAS and future features cannot inject alternative sandbox executors.
- `agent/internal/detect/backend` and `engine/goengine` load rules without a factory, hindering synthetic rule testing.
- Without these abstractions, the refactor-agent-runner-injection change cannot complete its core services milestone.

## What Changes
1. Define `threatintel.Provider` interface plus default manager-based implementation; update `TaskRequest.initThreatIntel` to use a provider factory.
2. Add `sandbox.Controller` interface representing sandbox run/cancel operations; default implementation wraps existing manager.
3. Create `detect.RuleEngineFactory` interface allowing tests to inject synthetic rule sets; default factory builds the current Go engine.
4. Update runners/config initialization to accept these factories, ensuring CLI and remote paths still use default behavior while tests can inject fakes.

## Risks
- Must ensure backwards compatibility for existing runners and CLI usage.
- Needs thorough testing to confirm no regressions in sandbox/threatintel workflows.
