## Coverage Baseline (2025-11-15)
Command: `cd agent && go test ./... -coverprofile=/tmp/agent-all.out`

### Packages >= 70%
- internal/agent (66.2%) – near target but still needs CLI wiring tests for Help/version.
- internal/agent/remote (78.5%) – already >70%.
- internal/benchmark (89.1%), config (97.4%), reporter (89.8%).
- internal/detect/backend (92.6%), goengine/metadata (94.7%).
- pkg/color/logo (100%), pkg/threatintel (63.9% but will be addressed in Phase 3).

### Packages <70% (must be addressed)
1. **internal/tasks (35.7%)**
   - gaps: respond module fallbacks, policy enforcement, metadata merge, SBOM helpers, telemetry.
   - plan: add tests under `internal/tasks/*_test.go` covering flag parsing, report outputs, sandbox approval, telemetry encoders.
2. **internal/detect (5.9%) + subpackages**
   - `internal/detect/engine` (0%), `rules` (0%), `scoring` (0%), `utils` (0%), `yara` (0%).
   - add fixtures for YARA parsing, scoring heuristics, rule manager behaviors.
3. **internal/assets**
   - reporters/utils packages currently 0%.
   - add fake writers/progress reporters covering CSV/JSON output and helper utilities.
4. **internal/sbom (0%)**
   - includes java/python walkers, manifest parsing, CLI command integration.
   - build tests with temp directories + small manifest fixtures.
5. **internal/telemetry, internal/progress (0%)**
   - need tests for telemetry encoders, BlockedActions provider overrides, progress manager behavior.
6. **pkg/config/logs/reporting (0%)**
   - cover default merge, env overrides, logging init, report manager file creation.
7. **CLI wrappers**
   - module `github.com/m-sec-org/d-eyes/agent` & `cmd/agent` show 0% (thin wrappers). Add smoke tests invoking `main`/`Runtime` with test args.

### Coverage Helper Infrastructure
- Provide reusable fake ReportManager, sandbox controller factory, threat intel provider (existing ones need centralization).
- Utility for capturing coverage baseline stored at `/tmp/agent-all.out` for reference.
