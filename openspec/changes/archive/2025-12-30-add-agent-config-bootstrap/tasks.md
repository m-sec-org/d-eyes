## 1. Default Config Bootstrap
- [x] 1.1 Add a config writer in `agent/pkg/config` that renders `config.Default()` to YAML in a stable, user-editable shape.
- [x] 1.2 Implement `EnsureDefaultConfig(path)` that creates parent dirs, writes atomically, and preserves existing files.
- [x] 1.3 Integrate bootstrap into CLI startup (`agent/internal/app.go`) only when the default config path is selected.

## 2. Tests
- [x] 2.1 Unit test bootstrap creates `config.yaml` on first run (temp HOME) and the generated file round-trips to the same effective defaults.
- [x] 2.2 Unit test existing config is not overwritten.
- [x] 2.3 Add a best-effort regression test for concurrent starts (no partial/corrupt config produced).

## 3. Docs
- [x] 3.1 Update `agent/README.md` to mention first-run auto-generation and how to override via `--config` / `D_EYES_CONFIG`.
