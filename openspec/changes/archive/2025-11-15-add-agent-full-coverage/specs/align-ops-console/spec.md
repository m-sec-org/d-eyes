## MODIFIED Requirements
### Requirement: Testing & Coverage Governance
Ops Console program MUST ensure the Agent codebase maintains 100% statement coverage across CLI, remote daemon, tasks, detect pipeline, sandbox, SBOM, and supporting packages.

#### Scenario: Coverage Gate in CI
- **GIVEN** contributors push to any branch
- **WHEN** CI runs `go test -coverpkg` over all Agent packages
- **THEN** the pipeline fails unless total coverage equals 100% with artifacts published for review.

#### Scenario: Documented Coverage Command
- **GIVEN** developers read the Agent README / contributing guide
- **WHEN** they follow the documented coverage command
- **THEN** running it locally reproduces the CI checks, ensuring regressions are caught before PR submission.
