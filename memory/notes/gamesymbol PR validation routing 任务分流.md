---
title: gamesymbol PR validation routing 任务分流
type: note
permalink: goldsrc-vibesignatures/notes/gamesymbol-pr-validation-routing-任务分流
tags:
- workflow
- pr-validation
- ci
- routing
- impact-planning
- gamesymbol
---

# gamesymbol PR validation routing 任务分流

## Overview

`gamesymbol-pr-validation.yml` 的分流是**确定性影响规划**，不是 ML/LLM 分类器：唯一 route 来源是 `plan` job 产出的 bound `plan.json`，`Route validation jobs` step 用 `jq` 把它归纳成 4 个布尔量，门控四条泳道；`pr-validate` 再反向断言每个 job 的 result 必须等于该路由状态下应有的值——**路由本身被断言**。

## Trigger

需要判断某类改动会走 hosted 还是 self-hosted、fork 为什么 fail closed、某个 tag/node 为什么被选中、或修改
`.github/workflows/gamesymbol-pr-validation.yml`、`gamesymbol_snapshot_lib/pr_validation.py`、
`gamesymbol_snapshot_lib/impact_registry.py`、`gamesymbol-impact.yaml` 时。

## 分流门控（唯一 route 来源）

- `plan` job：双 checkout（PR merge commit + `base.sha` 的 trusted base planner），再以 blobless clone 把 bin 子模块的 base/merge 对象取到 `RUNNER_TEMP/bin-objects`，用 `uv run --project .trusted-planner python gamesymbol_pr_validation.py plan` 生成 `plan.json`（`schema_version=4`、`cache_mode=warm`、`plan_sha256` 绑定；失败 job 重跑复用同 run_id 的 plan artifact）。
- `Route validation jobs`（`jq` over `plan.json`，对 `.tags[]` 做 `any`）：
  - `has_actions` = 任一 tag 有 (`analysis_nodes` 非空 或 `snapshot_rebuild` 或 `gamedata_rebuild`)
  - `has_analysis` = 任一 tag 的 `analysis_nodes` 非空
  - `has_hosted` = 任一 tag 满足 `analysis_nodes` 为空 且 (`snapshot_rebuild` 或 `gamedata_rebuild`)
  - `same_repository` = PR head repo 等于本仓库
- `plan_sha256` 随 outputs 传给 `warmup-idb`，consumer 侧校验 cache selection evidence 与 producer output 一致。

## 四条泳道

| 泳道 | 条件 | 行为 |
| --- | --- | --- |
| `validate-hosted` | `has_hosted` | GitHub-hosted，无 IDA：逐 tag（仅 `analysis_nodes==0` 且需 rebuild）materialize → compare → candidate build/guard → gamedata build/guard → mark |
| `warmup-idb` | `has_analysis && same_repository` | 可复用 producer，产出 exact warm IDB selection |
| `analyze-self-hosted` | `plan.success && has_analysis && same_repository && warmup-idb.success` | `[self-hosted, windows, x64]`，`force_execution` 重建 selected nodes；consumer 从不 warm/save |
| `fork-analysis-blocked` | `has_analysis && !same_repository` | `exit 1` fail closed（fork 不得用可信自托管 runner） |
| `pr-validate` | `always()` | 聚合断言：hosted = `success`/`skipped`；analysis + warmup = `success`/`skipped`；fork = `failure`/`skipped`；4 个布尔量必须是合法 `true`/`false` |

## 影响分类（planner 内部，规则匹配）

`plan_tag_impact`（`gamesymbol_snapshot_lib/pr_validation.py:249-343`）的 seed 来源：

1. 变更的 `bin_artifacts/<tag>/` 路径 → `contract.owners_by_path` 反查 owner 节点。
2. analysis 源文件（`ida_analyze_util.py`、`ida_preprocessor_scripts/**`）→ `SourceIndex.owners()`；**全局**要求每个变更 analysis 源至少有一个 consumer，否则 plan 失败（`pr_cli.py:354-356`）。
3. `.claude/skills/<skill>/**` → `skill_name` 命中的节点。
4. `gamesymbol-impact.yaml` 注册表规则 → `scope: all|platform|category|skill`。
5. config 指纹变化（`node.fingerprint` / `config_sha256`）→ 节点级 seed。
6. bin 的 (module, platform) 变更 → 该模块/平台下的节点。

随后沿 `analysis_plan.edges` 做 downstream closure；`snapshot_rebuild` / `gamedata_rebuild` = seeds 非空 || config 变化 || 对应 domain 文件变化（`_snapshot_domain_changed` / `_gamedata_domain_changed`）。

## 分类维度现状（关键边界）

- **能力已具备**：节点自带 category（`analysis_planner.py:28` `SYMBOL_CATEGORIES = func/gv/vfunc/vtable/patch/struct/structmember`）、`platform`、`skill_name`；注册表支持 `scope: platform/category/skill`（`impact_registry.py:15,88-96`）。
- **实际未启用**：`gamesymbol-impact.yaml` 只有一条 `scope: all` 规则（覆盖 planner/executor/tooling 共享文件），**没有任何 platform/category/skill 规则在用** → 今天不存在按符号类别分流。
- 因此当前分流依据是**路径类别 + 契约指纹 + 二进制身份**，不是符号分类器。若要按类别收窄 self-hosted IDA 范围，需要新增 registry 规则（而不是改 planner 代码）。

## 粒度与常见混淆

- 门控是 **tag 粗粒度** `any(...)`：任一 tag 命中，整个 job 就跑；per-tag / per-node 粒度只存在于 job 内部（`analysis-selection.json` + 循环）。
- `analysis_batch.py:90 classify_tag_plan` 是 **job 内** parallel/serial DAG 调度分类（见 [[full-analysis-concurrency]]），**不是** PR 分流。

## Verification

- `tests/test_gamesymbol_pr_validation.py` 覆盖 plan/route/aggregate 断言；`pr-validate` 的聚合 step 本身即路由断言的运行时证据。
- 本 note 结论来自 2026-09-08 阅读 workflow 与 planner 源码，未执行真实 PR 运行。

## 相关

[[ci-cd-and-repository-contract]]、[[gamesymbol PR validation candidate 基线复用]]、[[Immutable warm IDB cache generations]]、[[self-hosted-runner-and-governance]]、[[full-analysis-concurrency]]
