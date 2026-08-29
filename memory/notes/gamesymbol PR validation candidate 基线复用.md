---
title: gamesymbol PR validation candidate 基线复用
type: note
permalink: goldsrc-vibesignatures/notes/gamesymbol-pr-validation-candidate-基线复用
tags:
- workflow
- pr-validation
- gamesymbol
- snapshot
- materialize
- candidate
- ida
- ci
---

# gamesymbol PR validation candidate 基线复用

## Overview

`gamesymbol-pr-validation.yml` 不以"整包复用现有 `gamesymbols/<tag>.yaml`"或"全量重分析"为目标，而是**分节点**区分处理：未受 PR 影响的节点复用 base 快照内容，受影响节点由 IDA 重新分析，再合成一个临时 candidate 重新打包做校验。产物从不写回已提交的 `gamesymbols/`。

## Trigger

需要判断"PR 校验 workflow 是否会复用已有的 symbol yaml / 是否跳过分析"，或改动 `gamesymbol_pr_validation.py` / `gamesymbol_candidate.py` / `materialize.py` 时。

## 决策：复用但只是可信基线

回答"会复用已有 symbol yaml 吗？"——**会，但分两层、且不是最终产物**：

- **未受影响节点**：base 快照已提交的 `gamesymbols/<tag>.yaml` 内容被**原样拷入** `bin/<tag>/` 分析树作为基线。
- **受影响节点**（plan 里的 `analysis_nodes`）：由 `ida_analyze_bin.py` 强制重跑、覆盖基线。
- **最终 candidate**：从 `bin` 树重新 `pack_snapshot`，结果存入 `$RUNNER_TEMP`，只用于 `guard`/`mark` 自洽性校验，不写回仓库。

## 数据流（analyze-self-hosted 主路径）

1. `plan` 生成 bound plan.json（含 tags / analysis_nodes / invalidated_paths / mode / base_sha）。
2. `materialize`：读 `base_sha` 的 `gamesymbols/<tag>.yaml`（带 bound digest 校验），`materialize_baseline` 先 `_clear_analysis_yaml` 清空 `bin/<tag>/`，再把**除 invalidated_paths 之外**的 base files 拷入；`mode=full-rebuild` 则不拷（`base=None`）。
   - 出处：`pr_cli.py` `materialize_from_plan` 读 `repo.read(base_sha, "gamesymbols/<tag>.yaml")`；`materialize_baseline` 在 `materialize.py`。
3. `ida_analyze_bin.py -node <analysis_nodes...>`：`force_execution=True` 只重跑选中节点，重新生成这些 symbol yaml。
4. `gamesymbol_candidate.py build`：`pack_snapshot` → `collect_actual_files` 读**全部** `bin` 树 yaml（基线 + 新分析）打包成候选。仅在 `build_candidate_snapshot` 读已提交 `gamesymbols/<tag>.yaml` 以继承 `last_publish_time` 这一个字段。

## 两条路径差异

- **analyze-self-hosted**（有 analysis_nodes）：materialize(增量基线) → ida 重分析节点 → build。
- **validate-hosted**（snapshot/gamedata 重建，无 analysis_nodes）：materialize(拷基线，无失效点) → **不跑 IDA** → build。对已有 yaml 复用度最高，本质是"把基线重新打包一遍做一致性校验"。

## 关键不变量

- base 快照绑定 `base_sha` 且逐条 digest 校验（`base_snapshot:<tag>` / `base_config:<tag>` / `base_metadata:<tag>`），防 PR 篡改基线。
- `invalidated_paths` 恰好等于选中 `analysis_nodes` 的 outputs（`pr_validation.py` 计算），保证"基线拷入"与"重新分析"不重叠。
- candidate 输出被禁止使用 tracked `gamesymbols/` 命名空间（`candidate.py` 校验），只能写入 staging 目录。
- 该 job 用 `database_policy=restored_strict`、无保存回写，保证 warm IDB 世代保持中性（见 [Immutable warm IDB cache generations](goldsrc-vibesignatures/notes/immutable-warm-idb-cache-generations)）。

## Verification

从 bound plan 的 `base_sha` 能取到与 base 分支一致的快照；`materialize` 后 `bin/<tag>/` 里非 invalidated 文件与 base 逐字节一致；跑完 `ida_analyze` 后仅选中节点文件指纹变化；`build` 产物 candidate 与 `gamesymbols/<tag>.yaml` 不同（是新打包结果，非原文件复制）。
