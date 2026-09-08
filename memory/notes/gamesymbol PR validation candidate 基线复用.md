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
- 适用范围：只增强上述两条失败诊断路径，不修改 artifact schema、成功条件或 workflow 信任边界。

## PR validation failure artifacts

- hosted / self-hosted 的 validation step 失败时，workflow 上传 external rebuild root 中已有的 `**/*.yaml`，保留 tag/module 相对路径；部分重建失败也保留现有 YAML，没有文件时仅警告。
- Artifact 名称为 `gamesymbol-rebuilt-hosted-<run_id>-<run_attempt>` 或 `gamesymbol-rebuilt-self-hosted-<run_id>-<run_attempt>`，不包含 binary / IDA state；原有 validation failure 继续阻止门禁通过。
- 排查时同时下载该 run 的 `gamesymbol-plan-<run_id>`，以 plan 绑定的 merge SHA 中的 Git blobs 作为 expected，与上传的 rebuilt YAML 比较；不能用当前 main 或当前工作副本替代该基线。
- 上传步骤随 PR workflow 更新即可用于新的 run，不依赖新版诊断代码先进入 trusted base validator；旧 run 的重新执行不会自动采用修改后的 workflow。

## 相关

- [[gamesymbol PR validation routing 任务分流]] — hosted / self-hosted / fork 门控与 planner 影响分类来源。
- [[ci-cd-and-repository-contract]] — CI、submodule 与仓库契约总览。
