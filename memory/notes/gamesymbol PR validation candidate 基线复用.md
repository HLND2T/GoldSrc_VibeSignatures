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
