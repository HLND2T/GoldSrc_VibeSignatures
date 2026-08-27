# Generated-output PR 默认分支前移兼容迁移计划

状态：待实施

日期：2026-08-27（Asia/Singapore）

优先级：P0

GoldSrc 规划基线：`main@98e7247502f1e5c8e30481295d67712b6db5282d`

CS2 参考提交：`d32596b9b5f97c281817517f044bbf45c9b16602` `fix(release): allow base advancement in output PR validation`

## 1. 目标

允许 generated-output PR 创建后默认分支继续前进，而不会仅因当前 PR base SHA 不再等于 release manifest 的 `source_sha` 被误判为 stale。

迁移后的验证必须继续绑定 immutable source identity：

- output head 必须是单父提交；
- output head 的唯一父提交必须等于 manifest `source_sha`；
- manifest `source_sha` 必须是当前 PR base SHA 的祖先；
- changed-path allowlist 必须基于 `source_sha..head_sha` 计算；
- manifest、branch version 与 tracked output hashes 仍必须全部匹配。

本计划迁移的是验证语义，不直接复制 CS2 的单 GAMEVER、branch build-id 或 tracked manifest 结构。

## 2. 当前问题

`release_workflow_lib.promotion.verify_output_pr()` 当前执行以下绑定：

```text
manifest.source_sha == PR base SHA
diff PR-base..output-head
```

这会把默认分支上任何先于 output PR 合并的提交都视为 stale，即使：

- output commit 仍直接基于原始 `source_sha`；
- 当前 PR base 是该 `source_sha` 的线性后代；
- output commit 只包含允许的 generated outputs；
- manifest 与 tracked output hashes 完整有效。

GoldSrc 的 merge-time `verify_promotion()` 已经使用“source 是 merge base parent 的祖先”模型，因此 lightweight output PR verifier 与 promotion verifier 当前存在语义不一致。

`.github/workflows/validate-generated-output-pr.yml` 对 output head 使用 `fetch-depth: 0`，并显式 fetch PR base/head，具备执行 parent 与 ancestor 校验所需的 Git history，不需要修改 checkout 策略。

## 3. 决策边界

### 3.1 接受的 base advancement

只要当前 PR base 是 manifest `source_sha` 的后代，就允许 default branch advancement。output PR 发布的内容身份仍由 exact `source_sha` 决定，不要求它始终等于验证时的最新 default-branch HEAD。

若 base 与 output head 存在 Git 冲突，GitHub mergeability/branch policy 继续阻止合并；verifier 不自行执行 rebase 或把 base merge进 immutable output head。

### 3.2 必须拒绝

- PR base 与 manifest `source_sha` 无祖先关系；
- output head 有零个或多个父提交；
- output head 唯一父提交不是 manifest `source_sha`；
- branch version 与 manifest version 不一致；
- `source_sha..head_sha` 包含 allowlist 外路径；
- required release manifest 未变化；
- tracked output bytes、inventory 或 manifest hash 不匹配；
- fork repository 或非受信任 bot identity。

### 3.3 非目标

- 不改变 output branch 格式 `gamesymbols/build/<version>`；
- 不把 CS2 的 `<gamever>/<build-id>` branch identity 移入 GoldSrc；
- 不改变 manifest schema、release staging schema 或 promotion marker schema；
- 不自动关闭、重建、rebase 或 supersede output PR；
- 不放宽 changed-path allowlist、tracked hash 或 repository/author trust boundary；
- 不改变 `verify_promotion()` 的 two-parent merge contract。

## 4. 实施方案

### 4.1 先补失败测试

新增 `tests/test_release_workflow_guards.py`，使用临时 Git repository 或精确 mock 覆盖 `verify_output_pr()`。优先使用临时 repository 验证真实 parent/ancestor/diff 语义，mock 只用于难以构造的错误路径。

测试先表达当前缺口：当 `base_sha` 是 `source_sha` 的后代时，现有实现错误抛出 stale；迁移后该用例必须通过。

### 4.2 调整 `verify_output_pr()`

修改 `release_workflow_lib/promotion.py`：

1. 将 `head_sha` 规范化为 `require_sha()` 的返回值；
2. 先读取并验证 tracked manifest；
3. 保留 `manifest["version"] == parse_output_branch(branch)`；
4. 移除 `manifest["source_sha"] == base_sha` 等值要求；
5. 读取 `git rev-list --parents -n 1 <head_sha>`；
6. 要求 output head 恰有一个父提交且该父提交等于 manifest `source_sha`；
7. 复用现有 `_is_ancestor(source_sha, base_sha)`，要求当前 base 从 source 演进而来；
8. 使用 `git diff --name-only <source_sha> <head_sha> --` 生成 output-only path 集合；
9. 按 GoldSrc manifest 中的全部 `gamevers` 与 `version` 调用现有 `validate_output_paths()`；
10. 保留 `verify_tracked_outputs()` 作为最终内容校验。

不得新建第二套 ancestor helper，也不得把 shell command 拼成字符串。

### 4.3 CLI 与 workflow 核对

`release_workflow_lib/cli.py` 的参数已经提供 `base_sha` 与 `head_sha`，预计不需要 CLI schema 变更。

`.github/workflows/validate-generated-output-pr.yml` 已提供完整 history，预计不需要 workflow 变更。实施时仍需核对：

- trusted validation tooling 继续来自 PR base；
- output workspace 仍检出 exact head；
- `git fetch` 后 `source_sha` 对象可由 output head parent 链解析；
- verifier 不执行 output head 中修改过的工具代码。

### 4.4 同步架构文档

实施 PR 必须更新 `docs/plans/architecture-followup-migration.md` 中与本决策冲突的旧约束，至少包括：

- 7.3 中“base drift 必须 replacement build/PR”的绝对要求；
- 7.6 中“source_sha 必须等于 pre-merge base”的绝对要求；
- 最终验收标准中对 unrelated/relevant drift 的旧分类。

新表述必须以 exact source identity、direct-parent output head、ancestor base 与 output-only diff 为准，不能让两份计划同时定义相反的 release contract。

## 5. 测试矩阵

至少覆盖：

1. `base_sha == source_sha`：保持通过；
2. base 在 source 后增加无关提交：通过；
3. base 在 source 后增加 release 相关提交但仍无 Git 冲突：verifier按 exact source identity 通过；
4. base 不是 source 后代：失败；
5. output head 父提交不是 source：失败；
6. output head 为 merge commit：失败；
7. output-only diff 含 allowlist 外路径：失败；
8. base advancement 自身包含 allowlist 外路径，但 output-only diff 合法：不把 base changes 误算入 output PR；
9. branch version 与 manifest version 不一致：失败；
10. tracked output hash/inventory 被篡改：失败；
11. invalid base/head SHA：失败；
12. fork repository 或非 bot author：保持失败。

断言使用 expected 在前、actual 在后；错误测试应匹配稳定的 contract reason，不锁定完整 Git stderr。

## 6. 验证命令

定向验证：

```text
uv run python -m unittest tests.test_release_workflow_guards
uv run python -m unittest tests.test_release_workflow
uv run python tests/run_test_suite.py release-integration -b --durations 30
```

完成前质量门禁：

```text
uv run python format_repo_files.py --check
uv run python tests/run_test_suite.py unit -b --durations 30
uv run python tests/run_test_suite.py repository-contract -b --durations 30
uv run python tests/run_test_suite.py all -b --durations 30
```

若 `release-integration` suite 名称或覆盖范围在实施时变化，使用仓库当时的等价 release suite，并在交付中记录实际命令与结果。

## 7. 风险与缓解

### 风险：把 default-branch changes 误认为 output changes

缓解：changed paths 必须从 `source_sha..head_sha` 计算，不能使用 `base_sha..head_sha`。

### 风险：旧 output head 被重新提交或 merge base

缓解：强制 output head 单父且唯一父提交等于 source，不允许 rebase、merge 或额外人工 commit。

### 风险：source 不再是当前 main 历史的一部分

缓解：`_is_ancestor(source_sha, base_sha)` fail-closed。

### 风险：旧架构文档继续指导 replacement-only 流程

缓解：实现 PR 同步修订冲突章节，并在 release operator 文档说明新的 ancestor contract。

## 8. 实施顺序

1. 添加失败测试与临时 Git fixture；
2. 修改 `verify_output_pr()`；
3. 运行定向测试；
4. 核对 CLI/workflow 无需变更；
5. 更新冲突架构文档与 CI/CD 文档；
6. 运行仓库质量门禁；
7. 在 protected test repository 演练 output PR 创建后 main 前移再验证/合并。

## 9. 验收标准

- output PR 不再仅因 default branch 前移而 stale；
- output head 仍直接绑定 manifest `source_sha`；
- 当前 PR base 必须是 source 后代；
- path allowlist 只审计 output commit 自身变化；
- manifest identity 与 tracked hashes 没有放宽；
- `verify_output_pr()` 与 `verify_promotion()` 的 ancestor 语义一致；
- conflicting architecture text 已同步修订；
- 定向测试、release integration 与仓库质量门禁均有真实通过证据；
- protected test repository 的 base-advancement 演练有 run/PR/SHA 记录。
