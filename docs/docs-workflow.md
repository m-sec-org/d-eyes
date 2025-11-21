# Docs-as-Code 工作流

该流程用于统一管理 D-Eyes 文档的版本、校验与发布，确保 Stage4 的插件 / Playbook / 运维 / BAS 指南能够随代码一起演进。

## 1. 目录结构

```
docs/
├── version.yaml          # 文档版本清单（current + releases）
├── releases/             # 由工具生成的快照（stage4、vX.Y 等）
├── docs-workflow.md      # 本说明
└── *.md                  # 日常维护的 Markdown 文档
```

- `version.yaml.current` 表示下一次发布使用的版本标识，可设置为 `stage4-rc1` / `v0.5.0` 等。
- `docs/releases/<version>/` 由 `scripts/docs-release.sh` 生成，供发布流水线与外部站点同步。

## 2. CI 校验（docs lint & link check）

运行：

```bash
scripts/docs-lint.sh
```

校验内容：

1. 每个 Markdown 文件的首个非空行必须是 `# Title` 级别标题。
2. 所有相对链接（例如 `docs/task-template-api.md`）必须指向存在的文件，避免 404。
3. 支持附加文件参数，例如 `scripts/docs-lint.sh -manifest=custom.yaml`。

> 建议在 CI 中添加 `scripts/docs-lint.sh` 步骤，以保证 PR 合入前即可发现缺失标题或断链。

## 3. 自动发布 / 版本快照

```bash
# 生成当前 version.yaml 中 current 指向的快照
scripts/docs-release.sh

# 或指定版本号
scripts/docs-release.sh v4.0.0
```

执行流程：

1. 自动执行一次 `docs lint`，确保输出快照可用。
2. 根据 `version.yaml` 复制 `docs/` 下的 Markdown 与静态资源（排除 `docs/releases/*`）。
3. 输出至 `docs/releases/<version>/`，并在同级生成 `<version>.zip` 归档，可供对象存储 / 文档站点使用。

将 `scripts/docs-release.sh` 集成到发布流水线后，可在打 tag 或合并 release 分支时自动生成最新文档包。

## 4. 版本历史维护

- 更新 `version.yaml` 的 `current` 字段，即可切换下一次发布的目标。
- （可选）在 `releases` 列表中追加 `name` + `notes` 描述，便于追踪阶段性交付物。
- 历史快照可直接推送至 Docs 仓库或对象存储，无需额外的转换工具。
- 发布说明：基于 `docs/release-notes-template.md` 生成 `docs/release-notes/<version>.md`，并运行 `scripts/check-release-notes.sh`，它会确保 `docs/changelog.md` 与 `version.yaml` 同步。

## 5. 最佳实践

- 文档变更与代码同一个 PR 提交，保证 CI lint 覆盖。
- 大型文档（指南 / 手册）建议在文件头部添加版本说明，便于审阅。
- 快照生成后，可将 `docs/releases/<version>.zip` 提交到发布流水线（例如 GitHub Release 附件 / 内部制品库）。

通过以上流程，Docs-as-Code 可与 Stage4 其它能力一样进入标准化的版本与发布节奏。
