---
title: gamesymbol PR validation candidate 基线复用
type: note
permalink: goldsrc-vibesignatures/notes/gamesymbol-pr-validation-candidate-基线复用
tags:
- workflow
- pr-validation
- gamesymbol
- materialize
- candidate
- ida
- ci
---

# gamesymbol PR validation candidate 基线复用

## Overview

`gamesymbol-pr-validation.yml` 只以 merge Git tree 中的 `bin_artifacts` blobs 作为 YAML 基线。未受影响 artifact 会
materialize 到 checkout 外 rebuild root；受影响节点的输出不复制，并由 IDA 强制重跑。验证从不读取 tracked
`gamesymbols/` snapshot，也不向 `bin/` 或 repository-root generated-output 目录写 YAML。

## Trigger

需要判断 PR 校验如何复用 artifact、如何避免 checkout 自比较，或修改 `gamesymbol_snapshot_lib/pr_cli.py`、
`gamesymbol_snapshot_lib/pr_validation.py`、`gamesymbol_pr_validation.py` 时。

## 数据流

1. 可信 base tooling 从 base/head/merge Git tree 生成 bound plan，绑定 merge SHA、config/bin identity、formal artifact
   inventory、selected nodes 与 invalidated paths。
2. `materialize` 从 merge Git blobs 读取 expected artifact；除 invalidated outputs 外，逐字节复制到 checkout 外的
   rebuild root。Artifact A/M/D/R/C 与 downstream closure 都由 planner 计算。
3. self-hosted route 对 selected nodes 使用 `force_execution=True`，在 restored strict warm IDB 上重建；未选择节点只
   保留步骤 2 的 merge blobs。
4. `compare` 从 merge Git blobs 重建完整 expected inventory，再与 external root 的 formal inventory 和 bytes 比较。
5. Candidate/snapshot/gamedata 只在临时 staging 内重建以验证下游 contract，不作为 Git baseline，也不写回仓库。

## 关键不变量

- expected 来自 exact merge Git blobs；actual 来自独立 external root，二者不能互相覆盖。
- invalidated outputs 不 materialize，selected nodes 必须实际执行，避免 existing-output skip。
- 完整 inventory 比较会发现缺失、额外、rename/case collision 与单字节 drift。
- fork 无法修改可信 planner 后获得 self-hosted authority；需要 protected runner 的 fork fail closed。
- `bin_artifacts` 是唯一 Git YAML truth；`bin/` 只提供 binary/IDA state。

## Verification

覆盖 artifact-only PR、A/M/D/R/C ownership、下游闭包、空计划拒绝、bound manifest tamper、external-root safety、
selected-node execution，以及 full inventory/byte drift。

## Artifact drift diagnostics（issue #88）

- 触发信号：isolated rebuild 失败，runner log 只有 inventory/contract mismatch，缺少字段级证据。
- 根因：inventory 已含 size/sha256，普通内容漂移在后续逐字节比较前被拒绝；required missing、undeclared extra、非规范 YAML 又会更早被严格契约拒绝。
- 正确做法：`artifact_diagnostics.py` 为 PR `compare_rebuilt_artifacts` 与 release `compare_repository_artifact_root` 共用原始 bytes 诊断。inventory mismatch 和提前契约失败都补充排序的 missing/extra/changed、size/sha256 与 unified diff；每文件最多 40 行、最多 5 个 changed 文件详情，超限显式省略。诊断失败保留原始拒绝，不改变校验结果。
- 基线：PR expected 始终读取 bound merge_sha Git blobs；release 保留 tracked checkout bytes 的原有语义并明确标识，不能称作函数内读取的 exact Git blobs。
- 边界：原始 YAML 安全枚举拒绝链接/reparse point、非平坦路径与大小写碰撞；非 UTF-8 或仅换行漂移保留字节事实。PR workflow 使用 trusted base validator，新诊断须进入 base 后才用于后续 PR 的该校验。
- 验证方式：`tests.test_artifact_diagnostics`、`tests.test_gamesymbol_pr_validation`、`tests.test_bin_artifact_contract` 覆盖真实 canonical 字段漂移、混合 missing/extra/changed、非规范字节、checkout 改写、截断及诊断失败。真实 release dry run / IDA 结果须单独报告。
- 适用范围：只增强上述两条失败诊断路径，不修改 artifact schema、成功条件或 workflow 信任边界。（release gate 的成功条件后续已在「Release gate 的 anchor drift 容忍」中放宽；PR 路径不变。）

## Release gate 的 anchor drift 容忍（PR #217 follow-up）

- 触发信号：`gamesymbol-pr-validation.yml` 已容忍 anchor-only drift，但 `release-build.yml` 的 artifacts validation 仍会在 LLM_DECOMPILE 重跑选中另一条 rule-conformant reference instruction 时失败在 `bin_artifact_contract.py --actual-root`。
- 根因：容忍只接在 PR 路径（`gamesymbol_snapshot_lib/pr_cli.py::_accepted_anchor_drift`）；release 走 `bin_artifact_contract.py::compare_repository_artifact_root`，按 `(path, size, sha256)` 逐字节比较，从不引用 `anchor_drift`。
- 正确做法：把 inventory 级判定上提为 `gamesymbol_snapshot_lib/anchor_drift.py::accepted_anchor_drift`，PR 与 release 共用。release gate 仅在「payload key 集合一致、`gv_name` 不变、`gv_va`/`gv_rva` 不变、`anchor_is_coherent(actual)` 成立」时放行并打印 accepted drift，其余一律 fail closed。
- 发布物来源：snapshot 内嵌每个符号 YAML 的完整 payload（`codec.py::build_snapshot_document` 的 `files`），anchor 字段会进 snapshot。一旦放行 drift，rebuild root 与 tracked 不再逐字节相等，因此 `RELEASE_ARTIFACT_ROOT` 在 rebuild 模式也指向 tracked `bin_artifacts`：rebuild 只作可重建性证据，发布的 snapshot/JSON 始终派生自已提交的 Git truth，manifest 的 `artifact_inventory_sha256` 与 snapshot 来源保持一致。
- 为何不会在别处再失败：`check_snapshot_contract` 把 snapshot 自己的 files 写入临时目录再 round-trip，`validate_snapshot_contract` 只比对文件路径与 config digest，都不读取磁盘上 tracked artifact 的内容，故 snapshot 的 anchor 漂移不会在 bundle build/verify 阶段额外触发失败。
- 验证方式：`tests.test_bin_artifact_contract` 覆盖 anchor-only 放行并打印、address drift 仍拒绝、非 anchor/不连贯 payload fail closed；`tests.test_gamesymbol_pr_validation` 覆盖共用判定后的 PR 路径。真实 release dry run 与 IDA 结果须单独报告。
- 边界：不改变 PR 路径的成功条件，不改 artifact schema；release gate 仍拒绝缺失、额外、非规范字节与 address drift。

## PR validation failure artifacts

- hosted / self-hosted 的 validation step 失败时，workflow 上传 external rebuild root 中已有的 `**/*.yaml`，保留 tag/module 相对路径；部分重建失败也保留现有 YAML，没有文件时仅警告。
- Artifact 名称为 `gamesymbol-rebuilt-hosted-<run_id>-<run_attempt>` 或 `gamesymbol-rebuilt-self-hosted-<run_id>-<run_attempt>`，不包含 binary / IDA state；原有 validation failure 继续阻止门禁通过。
- 排查时同时下载该 run 的 `gamesymbol-plan-<run_id>`，以 plan 绑定的 merge SHA 中的 Git blobs 作为 expected，与上传的 rebuilt YAML 比较；不能用当前 main 或当前工作副本替代该基线。
- 上传步骤随 PR workflow 更新即可用于新的 run，不依赖新版诊断代码先进入 trusted base validator；旧 run 的重新执行不会自动采用修改后的 workflow。

## 相关

- [[gamesymbol PR validation routing 任务分流]] — hosted / self-hosted / fork 门控与 planner 影响分类来源。
- [[ci-cd-and-repository-contract]] — CI、submodule 与仓库契约总览。

## Artifact retirement and producer replacement（PR #150 follow-up）

- 触发信号：删除旧符号配置、finder 与 artifact 后，plan 报 `Deleted or renamed artifact is no longer declared by the merge contract`。PR #150 的 `NET_DrawRect` → `Draw_FillRGBABuf` 迁移触发此问题。
- 根因：`_artifact_owner_seeds` 把 base 路径和旧 owner 必须继续存在于 merge 当成不变量，禁止了正常退役或 producer 更名。
- 正确做法：旧路径先验证属于 base 正式契约；仅 D/R 的旧路径可从 merge 契约退役，且不得残留 required/optional analysis input。保留路径与新路径按 merge owner 调度并扩展下游闭包；退役触发 snapshot/gamedata 重建，不调度已移除节点。
- 安全边界：`build_plan` 仍校验完整 merge inventory；删除 artifact 却保留声明、移除声明却遗留 artifact、未知旧路径、新路径未声明、M/C 冒充退役均不获豁免。整个 tag 消失或 merge 契约为空仍沿用原拒绝规则。
- 验证方式：`tests/test_gamesymbol_pr_validation.py` 使用临时 Git 仓库覆盖删除、真实 R100、更名 finder、materialize/compare；纯 planner 测试覆盖残留输入与 producer 替换的下游闭包。修改可信 planner 后，必须另用目标 PR 的 base/head/merge 重放 `gamesymbol_pr_validation.py plan`；单元测试和 repository-contract 通过不能替代此检查。
- 部署顺序：修复须先进入 base；再更新依赖 PR 的分支以触发新运行。仅修改 PR 内 planner 或重跑使用旧 base 的 run，不会启用新规则。

- 实测（2026-09-19）：修复后的 planner 对 PR #150 原失败输入 `base=43180a6`、`head=54c613b`、`merge=f996be2` 重放成功（exit 0）；仅选择 Sven 8948/10257 的 W/L 四个 `find-Draw_FillRGBABuf` 节点和四个同名输出，两条旧 Windows artifact 标为 retired，两版本均要求 snapshot/gamedata 重建。该证据验证计划生成，不代表后续 self-hosted IDA job 已运行。
