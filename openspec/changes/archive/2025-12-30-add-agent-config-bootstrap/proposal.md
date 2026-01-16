## Why
- 当前 Agent 默认会加载 `~/.d-eyes/config.yaml`（`agent/internal/app.go:159` → `defaultConfigPath()`），但当文件不存在时会静默回落到内置默认值（`agent/pkg/config/config.go:411`），导致用户首次运行看不到可编辑的配置模板。
- `agent/README.md` 已声明默认配置文件路径为 `~/.d-eyes/config.yaml`（`agent/README.md:104`），实际首次运行不生成文件，会造成“配置丢失/未生效”的困惑。
- 远程模式（`d-eyes remote`）与本地 CLI 共用同一配置加载链路，提供一致的首次运行体验可降低部署与排障成本。

## What Changes
- Agent 在未显式指定 `--config`/`D_EYES_CONFIG` 且使用默认路径时，如果 `~/.d-eyes/config.yaml` 不存在，则自动创建 `~/.d-eyes/` 并写入默认配置 `config.yaml`。
- 写入行为必须幂等：若文件已存在则不覆盖；生成文件应采用安全权限（POSIX 下目录 `0700`、文件 `0600`）并尽量使用原子写入避免半写文件。
- 更新文档说明自动生成行为，并给出用户如何自定义/重置配置的指引。

## Impact
- Affected specs: `agent-server-foundation`
- Affected code: `agent/internal/app.go`, `agent/pkg/config`
- 新增/调整启动路径的单元测试与 CLI 回归测试，保证并发/重复运行下不会覆盖用户配置。

## Open Questions
- 若用户通过 `--config` 指向一个不存在的自定义路径，是否也应自动生成，还是保持现有的“回落默认值”行为？
- 已确认：允许 `d-eyes --help`/`version` 在默认配置缺失时触发自动生成，以保证首次运行即可获得可编辑模板；如需避免写入可显式指定 `--config` 或设置 `D_EYES_CONFIG`。
