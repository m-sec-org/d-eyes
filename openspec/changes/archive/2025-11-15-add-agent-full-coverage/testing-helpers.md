## Testing Helper Strategy

### Reporting & File Helpers
- Provide a shared `NewTestReportManager(t *testing.T)` that wraps `reporting.NewManager` with a temp directory and auto-cleanup.
- Add helper to create fake `reporting.OutputRecord`s without hitting disk.

### Sandbox & ThreatIntel Hooks
- Expose `internal/testing/fakes` package with:
  - Fake sandbox controller implementing `sandbox.Controller` returning canned results.
  - Fake telemetry encoder capturing metadata.
  - Fake threat intel provider implementing `tasks.threatIntelManagerProvider` (wraps existing `fakeTIProvider`).

### CLI Runner Factory
- Expand `customRunnerFactory` (from agent tests) into reusable helper so CLI/remote tests can swap runners easily.

### Asset/SBOM Fixtures
- Provide functions to scaffold temporary manifest trees (package.json, go.mod, requirements.txt) for SBOM tests.
- Build fake asset scan result generator returning host/port info.

### Coverage Command
- Baseline command recorded: `cd agent && go test ./... -coverprofile=/tmp/agent-all.out`.
- Coverage profile stored temporarily for diffing before gating.
