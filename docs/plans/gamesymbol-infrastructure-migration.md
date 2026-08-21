# GoldSrc gamesymbols 基础设施迁移方案

状态：已实施

日期：2026-08-19

实施记录：

- Baseline snapshots 已在 `dev` 提交为 `1fb1ac6 feat(gamesymbols): publish baseline snapshots`；
- Incremental PR validation infrastructure 已按本文 GoldSrc 分叉实现，包含 runtime contract、impact planner、selective materialize、selected-node analyzer 与三分流 workflow；
- 首次引入 workflow 时，目标 base 分支尚无 trusted planner，按 5.2 的 bootstrap 约束使用既有 CI 与手工完整门禁验证；合入后，后续 PR 才由 base commit planner 执行可信 planning。
- 后续 binary identity 迁移已用 schema 6 取代 snapshot `binaries.*.*.path`：分析身份只由 `module_<platform>` 与 hash 锁定，depot 获取位置改为相对 `download.yaml.basepath` 的 `depot_<platform>`。下文 schema 5 / `path_*` 描述保留为 baseline 建立时的历史契约，不再描述当前 writer。
- PR review 修复补齐了 metadata-only snapshot rebuild、Agent runner 配置与依赖锁文件 impact，并在 self-hosted 分析前后清理 `bin` submodule 的 ignored YAML/IDA 状态；Windows runner steps 固定使用 `pwsh`。

CS2 workflow 对齐基线：`D:/CS2_VibeSignatures` `main@0a4d75fb495c71543fa011a4cab1fb5518b5ee97`

对齐方式：能力迁移，不是 CS2 源码或 workflow 同步。施工时禁止把 `D:/CS2_VibeSignatures` 的
`gamesymbol_snapshot_lib/pr_validation.py`、`pr_cli.py`、`analysis_sources.py`、
`.github/workflows/pr-self-runner.yml` 当作 drop-in。该基线是单 tag、restore + invalidate +
全量 analyzer 的 runner 门禁；GoldSrc 需要多 tag、submodule 二进制、`{gamever}` reference 与
selected-node 执行。下文凡写“CS2 基线”均指上述 commit，不跟踪 CS2 后续提交。

## 1. 背景

本项目并非从零开始迁移 CS2 的 `gamesymbols` 实现。GoldSrc 当前已经具备以下能力：

- schema 5 canonical snapshot；
- config digest 与 analysis output contract；
- PE32/I386、ELF32/I386 binary validation 与多种 hash metadata；
- immutable symbol candidate、session、guard 与 atomic publish；
- snapshot-backed `SymbolStore`；
- strict gamedata candidate contract；
- `analysis_planner` 生成的 module/platform/skill artifact DAG；
- snapshot restore、verify 与 contract check；
- Pages 的 versioned symbol snapshot 展示。

当前主要问题不是缺少 snapshot 基础能力，而是：

1. tracked canonical snapshot 覆盖不足。`gamesymbols/svencoop-10257.yaml` 只有两个 artifacts，且已与当前 config digest 失配（snapshot 内二进制 `path` 仍是 `Sven-Coop/...`，config 已是 `Sven-Coop-10257/...`）；
2. 其他已有真实 YAML 的 tags 尚未发布 tracked snapshots；
3. 六个旧 Half-Life tags（`hl-3248` 至 `hl-6153`）config 没有 `path_*`，`binary_targets` 为空，pack 出的 schema 5 snapshot 不会锁定二进制身份；
4. PR validation 尚不能根据 config、preprocessor、reference、skill、binary 与 snapshot delta 精确计算 artifact/skill 级失效闭包；
5. 尚无受信任的 incremental restore、selected-node execution 与 actual/expected PR snapshot gate。

本方案采用“能力迁移而非代码同步”：以 CS2 为成熟能力参考，选择性迁移通用机制，同时保持 GoldSrc 已有的 x86、`<family>-<build>` tag、4-byte vtable slot、binary blob 解密、flat artifact path 与严格 config contract 语义。

### 1.1 与 CS2 基线的分叉（施工禁抄清单）

CS2 基线**实际落地**的是更小的 runner 门禁，不是本方案的 hosted planner 架构。GoldSrc 实现必须按本表分叉，而不是按 CS2 文件对齐：

| 主题 | CS2 基线（`0a4d75fb`） | GoldSrc 本方案 |
| --- | --- | --- |
| 验证范围 | `download.yaml` 最后一项 tag | `configs/config.yaml` 声明的全部适用 tags，逐 tag 独立事务 |
| Workflow | 单一 self-hosted `pr-self-runner.yml` | hosted planning、hosted snapshot/gamedata gate、self-hosted IDA 分流 |
| 增量方式 | `restore` 整份 base，再 `invalidate` 删 YAML，然后全量 `ida_analyze_bin.py`，靠 `EXISTING_OUTPUTS` 跳过 | selective materialize（失效路径不落盘）+ `-node` 只启动受影响二进制 |
| `-node` | 不存在 | GoldSrc 新增 CLI；不得从 CS2 analyzer 抄参数 |
| 二进制来源 | 从 `PERSISTED_WORKSPACE/bin/<GAMEVER>` robocopy 进工作区 | Git `bin` submodule 提供 PE32/ELF32；planning 只读 gitlink/`ls-tree` |
| YAML 来源 | persisted bin 中的 YAML + restore | PR 工作区 YAML 只来自 snapshot materialize，不以 persisted YAML 为分析输入 |
| IDB | 从 persisted bin 额外拷贝 `*.i64` 以跳过 IDA 初分析 | 禁止拷贝或回写 `.i64`/`.id0`；不得抄 CS2 那段 i64 robocopy |
| Registry | 硬编码 `BROAD_ANALYSIS_FILES`（如 `.claude/agents/sig-finder.md`） | 根目录 `gamesymbol-impact.yaml`；这是 GoldSrc 新增，不是 CS2 文件迁移 |
| Trusted planner | 无独立 base-commit planner 可执行文件 | 稳态 planning 使用 **base** commit 的 planner；merge planner 不能自我放行 |
| 未映射 preprocessor | **broad rebuild** 全部 HEAD nodes | 分析源映射失败必须 fail-closed 或 broad rebuild，不得静默跳过 |
| Reference 路径 | `references/<module>/Foo.{platform}.yaml`，matcher 只替换 `{platform}` / `{module_name}` | `references/{gamever}/<module>/Foo.{platform}.yaml`，加上 canonical `hl-10210` 回退 |
| Finder import | 多数同样 `from ida_analyze_util import ...`；CS2 import graph 只跟踪 `ida_preprocessor_scripts.*` | 必须按 GoldSrc 实际 import 建模；禁止原样复制 CS2 `analysis_sources.py` |
| Owner 模型 | 同一 artifact 允许多个 owner | 每个 required/optional YAML artifact 恰好一个 producer |
| Fake LLM | workflow 把 `CS2VIBE_LLM_FAKE_AS` 从 secrets 注入 | `GSVIBE_LLM_FAKE_AS` 必须未设置或为空；禁止抄 CS2 的 secret 透传 |
| 零 symbol tag | 无对应模型（单 release tag） | `cstrike-*` 可无 snapshot；空 `formal_paths` 且无 tracked snapshot 时是 no-op |

当前工作区对照（Baseline 开工前事实，不是施工猜测）：

- 10 个非空 tags 的 required YAML 均已存在于本地 `bin/<tag>/`，无 undeclared extra YAML。
- `cstrike-8684` / `cstrike-10210`：`nodes=0`，`formal_paths` 为空，有 `path_*` 与二进制，无 snapshot。
- `hl-3248`–`hl-6153`：不在 `download.yaml` 中，config 无 `path_*`，`binary_targets=[]`；`bin` submodule 已跟踪 `hw.dll`，其中 `hl-3248`/`3266`/`3329`/`3647` 还跟踪了派生的 `hw.decrypt.dll`。
- `.gitignore` 含 `gamesymbols/*.yaml`；现有 `svencoop-10257.yaml` 是已跟踪例外，新 snapshot 必须 `git add -f`。
- `tests/test_repository_contract.py` 的 `test_published_sven_snapshot_matches_goldsrc_contract` 锁死 `file_count == 2` 且只有 `R_RenderView`。
- Pages e2e 取 index 排序后的 `versions[0]`；加入 10 个 snapshot 后该项会变成 `cof-5936`，不再是 `svencoop-10257`。

## 2. 目标

### 2.1 第一阶段目标

以当前 `bin` 工作区中的分析 YAML 为可信输入事实，建立 contract-valid baseline snapshots。第一阶段的“真实 symbols”定义为：

> 已由当前 GoldSrc config、artifact schema、**非空 binary metadata**、canonical serialization、immutable candidate 与 gamedata guard 锁定的 trusted symbols，但不声称本阶段重新通过 IDA/runtime 独立验证其语义正确性。

第一阶段直接打包现有 YAML，不重新运行 IDA。发布前必须先补齐每个非空 tag 的 `module_<platform>` + `path_<platform>`，使 snapshot 锁定真实 PE32/ELF32 hash。禁止发布 `binaries: {}` 的“合同完整”快照。旧 Half-Life tags 不在 `download.yaml` 中，其 `path_*` 只服务 snapshot 身份，不要求为此扩张 depot 下载。

### 2.2 最终基础设施目标

- 服务仓库当前声明的所有 GoldSrc families：Half-Life、Counter-Strike、Sven Co-op 与 Cry of Fear；
- 以 config 声明的平台为完整性边界：声明的平台必须具备全部 required artifacts，未声明的平台不构成缺失；
- `gamesymbols` 保持广义分析产物边界，而不是传统 linker symbol table；
- 支持 `func`、`gv`、`vfunc`、`vtable`、`patch`、`structmember` 等 category-specific artifacts；纯容器型 `struct` 不单独要求 artifact；
- 每个 tag 是独立 candidate/session/hash/publication transaction；
- PR 作者提交预期 snapshot，CI 只读重建 actual candidate 并严格比较；
- 首版即支持 artifact/skill 级 ownership、失效 seed 与下游闭包；
- 只有真正受影响的分析节点才运行 IDA（GoldSrc 新增 `-node`；不是 CS2 的全量 analyzer + skip）；
- base snapshot 不可信时，显式回退为 clean full rebuild，而不是使用不可信 payload。

## 3. 非目标

Baseline PR 与 Infrastructure PR 明确不包含：

- 为 Counter-Strike 生成首批 symbols；
- 新增 gamedata generator 或迁移 `gamedata_candidate verify-tracked`；
- CS2 的 C++ ABI、HL2SDK 或 layout gate；
- release artifact/binary staging、tag、GitHub Release、binary promotion 或 generated-output bot PR；
- snapshot schema 5 升级；
- Source2 RTTI、64-bit pointer/vtable 或其他 Source2 专属语义；
- PR workflow 中的 old-version YAML relocation；
- 持久化或回写 IDB/`.i64` cache；
- CI 自动修改、commit、push 或 publish tracked snapshots；
- 迁移 CS2 `/create-pr` 的 symbols-pipeline/plain-PR 分类器与本地交付编排；
- 改变普通本地全量分析的默认行为，新增的 `-node` 参数除外；
- 把 CS2 的 `download.yaml[-1].tag` 当作本仓库的验证范围；
- 把 `PERSISTED_WORKSPACE/bin` 当作二进制或 YAML 的分析真相来源；
- 从 persisted workspace 拷贝 `*.i64` / `.id0` 或其他 IDA database；
- 透传 `GSVIBE_LLM_FAKE_AS`（或 CS2 的 `CS2VIBE_LLM_FAKE_AS`）secret；
- 复制 CS2 `analysis_sources.py` 的 `{platform}`/`{module_name}` matcher，或只跟踪 `ida_preprocessor_scripts.*` 的 import 图；
- 复制 CS2 允许多 owner 的 `owners_by_path` 语义；
- 把 CS2 `pr-self-runner.yml` 的单 job / 单 GAMEVER / robocopy persisted bin 流程改名后当作 GoldSrc workflow。

## 4. 内容与真实性边界

Canonical snapshot 保存所有 config 声明的、可复现定位游戏内部对象所需的分析 metadata：

- `func`：function identity、VA/RVA、size 与 relocatable signature；
- `gv`：global identity、VA/RVA、access signature 与 instruction displacement metadata；
- `vfunc`：vtable identity、4-byte slot offset/index 及相关定位信息；
- `vtable`：vtable address、entries 与 ABI-specific metadata；
- `patch`：patch site signature、displacement 与 replacement bytes；
- `structmember`：member offset、size 与 relocation signature；
- `struct`：配置组织容器，不单独发布 YAML。

未来新增或更新 artifacts 时，仍必须经过 analyzer/runtime validator。只有本次一次性 baseline bootstrap 采用“直接信任当前 YAML 并锁定 contract”的例外。

## 5. 分阶段交付

### 5.1 PR 1：Baseline snapshots

#### 范围

同一个 Baseline PR 提交以下 10 个非空且 contract-complete tags：

```text
hl-3248
hl-3266
hl-3329
hl-3647
hl-4554
hl-6153
hl-8684
hl-10210
svencoop-10257
cof-5936
```

当前 `cstrike-8684` 与 `cstrike-10210` 的 `formal_paths` 为空，不生成空 snapshot。零 symbol tag 可以保留在 `configs/config.yaml`；首次增加分析节点或 symbol contract 时，必须在同一 PR 中提交完整 baseline snapshot。

#### Baseline 前置：二进制身份

10 个非空 tags 在 pack 之前必须：

- 每个声明平台都有 `module_<platform>` 与 `path_<platform>`；
- `load_contract().binary_targets` 非空，且与将写入 snapshot 的 `binaries` 一致；
- snapshot 对每个 binary target 记录 schema 5 要求的 sha256/md5/crc32/crc64/size；
- `path_*` 指向配置的源二进制（旧 HL 的 Metahook blob 是 `hw.dll`），**不是** `hw.decrypt.dll`。

`hl-3248`–`hl-6153` 今日缺少 `path_*`。若不先补这项就 pack，会把没有二进制 hash 的 snapshot 冻成后续 PR gate 的 trusted base。旧 tags 不在 `download.yaml` 中，补 `path_*` 不必同时改 depot 清单；`test_download_and_config_tags_match` 只约束 `download.yaml` 里的 tags。

#### 事务模型

- 一个 PR 原子提交全部 10 个 snapshots；
- 内部仍执行 10 个独立 candidate/session/gamedata guard transactions；
- 任一 tag 失败时，不提交不完整批次；
- 旧的 `gamesymbols/svencoop-10257.yaml` 在同一 tag 下原位替换，Git 历史保留旧覆盖范围；
- 不建立聚合 `all-games.yaml`。

#### 每个 tag 的验收

1. `gamesymbol_candidate build`；
2. empty-inventory gamedata candidate `build + guard`；
3. symbol candidate `mark -step gamedata`；
4. publish 到 `gamesymbols/<tag>.yaml`；
5. 对已发布 snapshot 执行 `check-contract` 与 `verify`；
6. 在隔离、无 YAML、包含相同真实 binaries 的临时 bindir 中 restore，并确认 byte-stable round trip；
7. 全部 tags 成功后运行 repository formatting、unit、repository-contract 与 full suites。

Baseline PR 不运行 IDA，不新增一次性生产 CLI。可以使用临时编排脚本或逐 tag 命令。仓库提交：

- 10 个 `gamesymbols/<tag>.yaml`（根 `.gitignore` 忽略该 glob，必须 `git add -f`）；
- 为旧 HL tags 补齐 `path_*` 的 config 变更；
- 必要文档与被 snapshot 内容锁死的测试/Pages 契约。

至少必须同步修改：

- `tests/test_repository_contract.py` 的 `test_published_sven_snapshot_matches_goldsrc_contract`（不得再锁 `file_count == 2` / 仅 `R_RenderView`）；
- 若 Pages e2e 或 `verify:gamesymbols` 对 `versions[0]` / 非空 `binaries` 有隐含假设，一并按新 index 更新。

空 gamedata inventory 只用于 candidate guard，不创建或提交 `gamedata/<tag>/` 空目录。

### 5.2 PR 2：Incremental PR validation infrastructure

Infrastructure PR 在 baseline snapshots 已合入后实施。它迁移的是 CS2 的**门禁能力**（trusted base、失效闭包、actual/expected 只读比较、untrusted full rebuild），不是 CS2 的单文件实现。

下列条目是 GoldSrc **新增或必须重写**，禁止从 CS2 对应文件改名拷贝：

- runtime `SnapshotContract` analysis graph/index（fingerprint 独立于 `PlanNode`，见 6.1）；
- artifact ownership 与唯一 producer contract（严于 CS2 多 owner）；
- GoldSrc `{gamever}` + canonical fallback 的 reference consumers；
- GoldSrc 实际 import 图（`ida_analyze_util`、preprocessor 同目录 helper、prompt）；
- root-level `gamesymbol-impact.yaml`（CS2 没有此文件）；
- `bin` submodule gitlink/`ls-tree` invalidation（不是 robocopy persisted bin）；
- selective materialize（不是 CS2 的 restore + unlink）；
- `ida_analyze_bin.py -node`（CS2 无此参数）；
- hosted/self-hosted workflow 分流（CS2 是单一 self-hosted job）；
- no-IDB-persistence runner contract（CS2 会拷 `*.i64`）。

下列可在 GoldSrc 语义下重写后保留：

- base/merge config semantic diff；
- snapshot delta invalidation；
- untrusted-base full rebuild fallback；
- GitHub Actions default checkout、`fetch-depth: 0`、merge ref；
- same-repo / fork 边界与 concurrency cancel-in-progress。

YAML staging / merge-only promotion / closed finalizer **不是** GoldSrc PR 正确性的刚需（见 13.6）。第一版可以只做 materialize + compare；若仍做 promotion，其范围仅限 runner accepted YAML workspace。

现有 `.github/workflows/ci.yaml` 继续作为 formatting/unit/repository-contract/full/pages 门禁。新 gamesymbol workflow 是附加，不替换 `ci.yaml`。fork PR 仍走现有 hosted tests，不进 self-hosted IDA。

产品交付仍是一个 Infrastructure PR。实现上允许在同一目标下按下列顺序堆叠，以免 bootstrap、planner 与 runner 契约缠在一次 review：

1. runtime contract + impact planner + registry + 单测（无 GitHub workflow）；
2. `-node` + selective materialize + analyzer 契约测试；
3. workflow 分流；promotion 可再延后。

首次引入 workflow 的提交因 base 分支尚无 trusted planner，作为一次性 infrastructure bootstrap，使用现有 CI 与手工完整 contract/tests 验证。合入后，后续 PR 才由 base planner 决定 impact。

## 6. Runtime contract 与 ownership

### 6.1 `SnapshotContract` 扩展

在不修改 persisted snapshot schema 的前提下，扩展内存中的 `SnapshotContract`：

```python
@dataclass(frozen=True)
class SnapshotContract:
    # 现有 persisted-contract inputs
    game_version: str
    game_root: Path
    config_digest_version: int
    config_sha256: str
    analysis_output_contract_version: int
    required_paths: frozenset[str]
    optional_paths: frozenset[str]
    binary_targets: dict[tuple[str, str], BinaryTarget]

    # 新增 runtime-only analysis index
    analysis_plan: ExecutionPlan
    nodes: dict[str, SkillNode]
    owners_by_path: dict[str, frozenset[str]]
```

`SkillNode` 至少包含：`node_id`、`logical_key=(module, skill, platform)`、inputs/outputs、prerequisites、以及按 7.3 计算的 `fingerprint`。它可以从 `ExecutionPlan` 派生，但 fingerprint 不得 `asdict(PlanNode)` 后直接哈希。

`load_contract()` 当前已经调用 `build_execution_plan()` 做校验，但会丢弃返回的 plan。新实现保留该 plan，并构建独立的 `SkillNode` index 与 `owners_by_path`。

不得把整个 `ExecutionPlan` / `PlanNode` 当作 fingerprint。GoldSrc `PlanNode` 含 `max_retries` 与 `order`；7.3 明确这两项不能使 analysis node 失效。CS2 基线使用单独的 `SkillNode.fingerprint` 与 `logical_key=(module, skill, platform)`；GoldSrc 采用同等物，但 node ID 仍用 6.2 的 `<module>:<platform>:<skill>`，**不要**抄 CS2 的 `stage_index:skill_index:...` 形式（GoldSrc 每个 module 名只出现一次，不使用 CS2 的重复 stage）。

`owners_by_path` 每个 path 的 owner 集合在 GoldSrc 中必须是恰好一个 node。CS2 测试允许同一 `Common.windows.yaml` 有两个 owner；该语义不迁入。

以下内容保持不变：

- snapshot schema 5 与 canonical YAML bytes；
- config digest algorithm；
- artifact YAML schema；
- candidate hash content；
- snapshot migration requirements；
- `pack`、`restore` 与 `SymbolStore` 的既有语义。

### 6.2 稳定 node identity

继续使用 GoldSrc 当前稳定 node ID：

```text
<module>:<platform>:<skill>
```

node ID 不包含 config list index，因此单纯重新排序不会改变 identity。

### 6.3 唯一 producer 门禁

除不生成文件的 `struct` 外，每个 required/optional artifact 必须恰好由一个 analysis node 输出：

- zero owner：planning/config contract failure，包括 config `symbols` 声明了 artifact 但没有任何 skill output 生产它；
- multiple owners：planning/config contract failure；
- 大小写不同但 Windows filesystem 会冲突的 paths：planning failure。

当前 `build_execution_plan()` 只拒绝 duplicate producer，不把“symbol 无 producer”判成 zero-owner。本门禁是新的 planner 契约，必须有测试；不能只写在 `SnapshotContract` 注释里。

## 7. Impact discovery

### 7.1 自动推导

能从 code/config 可靠推导的 ownership 不重复写入 registry：

- config 中的 skill → required/optional outputs；
- artifact path → owner node；
- expected inputs 与 prerequisites → DAG edges；
- preprocessor 文件名与 **GoldSrc** Python import graph（见下）；
- preprocessor 声明的 reference YAML consumers，含 `{gamever}` 与 canonical fallback；
- `ida_preprocessor_scripts/prompt/**` 作为全部 LLM_DECOMPILE 消费者的 seed；
- `.claude/skills/<skill>/**` → 同名 skill nodes；无同名 node 时视为无分析影响；
- base/merge snapshot delta → artifact owners；
- `bin` submodule 中 **config 声明的** `module_<platform>` 文件 delta → tag/module/platform nodes。

`.claude/skills/` 是分析 Agent skill 的唯一权威来源。`.codex/` 与 `.opencode/` 只是 runner/runtime 配置；若某项配置确实改变分析结果，必须通过 registry 显式登记。不要抄 CS2 硬编码的 `.opencode/agents/sig-finder.md`。

GoldSrc reference 与 import 不得使用 CS2 `analysis_sources.py`：

- GoldSrc 路径模板是 `references/{gamever}/<module>/<func>.{platform}.yaml`。运行时先解析当前 tag 的 `{gamever}`，文件缺失再回退 `GSVIBE_REFERENCE_GAMEVER`（默认 `hl-10210`）。改 `references/hl-10210/engine/SV_SendServerinfo.windows.yaml` 必须失效所有回退到该文件的 tags/nodes，而不仅是 `hl-10210`。
- CS2 matcher 只替换 `{platform}` / `{module_name}`，且路径是 `references/<module>/Foo.{platform}.yaml`。原样复制会把 GoldSrc reference 变更判成无消费者。
- GoldSrc finder 几乎都是 `from ida_analyze_util import preprocess_common_skill`。CS2 import 图只收集 `ida_preprocessor_scripts.*`，对 GoldSrc 看不见共享 helper。planner 必须覆盖：同目录 helper（如 `_indirect_vcall_target_common.py`）、`ida_analyze_util.py`（同时在 registry）、以及 `prompt/call_llm_decompile.md`。

### 7.2 Base 与 merge 双图

对 rename/delete/copy 等变化，同时分析 base 与 merge tree：

- source ownership 取 base/merge 映射节点并集；
- registry 取 base/merge 两份规则的 seed nodes 并集；
- 再在 merge DAG 上计算下游闭包；
- 删除旧 preprocessor/reference/skill 时，仍能通过 base graph 找到原消费者。

路径分两类，禁止把 CS2 的“未映射 preprocessor = broad rebuild”和旧稿的“全部未映射 = silent”混成一种策略：

- **非分析路径**（`docs/**`、`pages/**`、普通 tests、`process_reporter*` / `process_scheduler*`、与分析结果无关的 skill）：无法映射到节点时静默视为无影响。
- **分析源路径**（`ida_preprocessor_scripts/**` 含 `.py`、reference YAML、`prompt/**`；以及 registry 声明的路径）：必须映射到明确 seed。映射失败时 **fail-closed 或对该 tag 做 broad rebuild**，不得静默跳过。HEAD 上存在无消费者的 active reference 是 contract error（CS2 对 orphan HEAD reference 已是错误；GoldSrc 保留并加上 `{gamever}` 解析）。

### 7.3 Config semantic diff

config 变更不等于全 tag 失效。planner 对 base/merge config 做结构化 diff。

Node fingerprint 包含：

- module、platform、skill；
- binary target；
- required/optional inputs 与 outputs；
- prerequisites；
- `skip_if_exists`；
- aliases；
- 其他会传入分析器并影响结果的 skill 参数。

Node fingerprint 不包含：

- `description`；
- config list position；
- `max_retries`；
- UI/reporting metadata。

这些 operational/display-only 字段不会使 analysis nodes 失效，但完整 config digest 变化时仍可能要求 `snapshot_rebuild`。fingerprint 写在 `SkillNode` 上；实现时对照 CS2 的 fingerprint 字段列表可以参考，但必须按本节包含/排除规则重写，并加上 GoldSrc 的 `aliases` 与 binary `module_<platform>` 文件名。

### 7.4 Binary submodule diff

`bin` 是 Git submodule，只跟踪真实游戏二进制，不跟踪 YAML（`bin/.gitignore` 忽略 `*.yaml`）。分析缓存与 IDB 也不是 seed。

- gitlink 未变化：不产生 binary invalidation；
- gitlink 变化：比较 base/merge submodule commits 的 file trees，只把 **config 声明的** `bin/<tag>/<module>/<module_<platform>>` 当作 seed；
- `*.decrypt.*`（例如已 commit 的 `hl-3248/engine/hw.decrypt.dll`）是 Metahook blob 的派生 PE，不是独立 binary seed，不进 snapshot `binaries`，不进 staging；
- blob 源文件（通常是 `hw.dll`）的 add/modify/delete/rename 才映射到该 tag/module/platform 的全部 nodes；
- binary target、source path 或源二进制 bytes 改变时，失效该 module/platform 的全部 nodes，再计算跨模块下游闭包；
- binary 被删除但 merge config 仍声明使用时，contract failure；
- 不尝试在 binary SHA-256 不同的情况下启发式复用旧 signatures；
- 不要把目录里每个文件都当 seed，否则 decrypt 输出或误 commit 的缓存会误触发全量 engine 节点。

### 7.5 Snapshot delta

即使 PR 只修改 tracked snapshot，也必须验证真实分析：

- 比较 base/merge snapshot 的 `files` payload；
- delta artifact 映射到 owner nodes；
- owner 与下游闭包必须重跑；
- 只修改 `last_publish_time` 不触发节点，也不影响 actual/expected comparison。

### 7.6 Optional outputs

节点失效时，删除它拥有的全部 required 与 optional outputs：

- required outputs 重跑后必须存在；
- optional outputs 可以存在或缺失；
- 最终状态以 actual candidate 与 merge snapshot 的严格比较为准；
- 不允许旧 optional artifact 因残留文件被误认为本次输出。

## 8. Root impact registry

### 8.1 文件与 schema

registry 位于仓库根目录：

```text
gamesymbol-impact.yaml
```

采用有限、可 schema-validate 的声明，不允许 Python expressions：

```yaml
schema_version: 1
rules:
  - paths:
      - ida_analyze_util.py
    scope: all
    reason: Shared artifact generation and normalization semantics
```

每条规则支持：

- `paths`：repo-relative POSIX exact paths 或受限 globs；
- `scope`：`all`、`platform`、`category`、`skill`；
- `platforms`、`categories`、`skills`：与 scope 对应的有限集合；
- `tags`：可选，默认所有适用 tags；
- `reason`：必填非空文本。

registry parser 必须拒绝 absolute paths、`..`、backslash、空 path、无效 scope、未知 platform/category 与不合法 glob。

### 8.2 初始 core registry

首版将以下明确影响 analysis generation/validation semantics 的共享模块映射为 `scope: all`：

```yaml
rules:
  - paths:
      - analysis_config.py
      - analysis_planner.py
      - analysis_output_contract.py
      - binary_format.py
      - trusted_yaml.py
      - ida_analyze_bin.py
      - ida_analyze_util.py
      - ida_skill_preprocessor.py
      - ida_mcp_session.py
      - ida_llm_utils.py
      - ida_llm_decompile.py
      - agent_runner.py
      - decrypt_blob.py
      - ida_preprocessor_scripts/prompt/call_llm_decompile.md
    scope: all
    reason: Shared analysis execution, binary validation, blob decryption, artifact normalization, or model fallback semantics
```

`gamesymbol-impact.yaml` 是 GoldSrc 新增文件。CS2 基线没有等价 registry，只有 `BROAD_ANALYSIS_FILES`。不要把 CS2 那两个 `sig-finder.md` 路径抄进 GoldSrc 初始规则。

以下文件默认不映射到 analysis nodes：

- `process_reporter*.py`、`process_scheduler*.py`：观测与调度；
- `gamesymbol_snapshot_lib/**`、candidate/store：snapshot/candidate domain；
- gamedata generator/contract：gamedata domain；
- `docs/**`、`pages/**` 与普通 tests。

新增的 trusted planner、source index、registry parser、PR validation CLI 与 selective materializer 模块自身，也必须加入 `scope: all` 规则。Agent runner 直接读取的共享 prompt/settings、MCP 配置，以及 `pyproject.toml` / `uv.lock` 依赖环境同样属于分析输入。具体路径在实现时随模块落位一起固定，不能依赖文件名前缀猜测。

若未来证明某文件会改变 symbol generation semantics，再新增明确 registry rule。

## 9. Canonical impact plan

### 9.1 分层 actions

每个 tag 的 plan 区分：

```text
analysis_nodes
snapshot_rebuild
gamedata_rebuild
```

示例：

- preprocessor/skill/binary change：执行三层相关 actions；
- config `description` 或 `max_retries` change：analysis nodes 为空，但 config digest 变化时重新 pack snapshot；
- snapshot/candidate library change：重新 build/guard/compare，不运行 IDA；
- generator change：只重建 gamedata；
- 纯文档 change：三层均为空。

当前没有 generator 时，`gamedata_rebuild` 只运行 empty inventory candidate gate，不产生 tracked output。

零 symbol tag（当前 `cstrike-8684`、`cstrike-10210`）的状态机：

- `formal_paths` 为空且没有 tracked snapshot：即使 registry `scope: all` 或共享文件变更，该 tag 也是 no-op，不跑 IDA，不要求 expected snapshot，不走 untrusted full rebuild；
- PR 第一次为该 tag 增加 skill/symbol/`formal_paths`：必须在同一 PR 提交完整 snapshot，否则 fail-closed；
- 不得为了“config digest 也变了”而给空 inventory 发布空 snapshot。

### 9.2 Plan binding

planning job 输出 canonical JSON，至少包含：

- plan schema version；
- PR base SHA、branch head SHA、merge SHA；
- base/merge `bin` submodule commits；
- affected tags；
- per-tag mode：`incremental` 或 `full-rebuild`；
- selected node IDs 与 invalidated artifact paths；
- `snapshot_rebuild`、`gamedata_rebuild`；
- reasons 与 fallback reason；
- base/merge config、registry、snapshot digests。

consumer job checkout merge tree 后必须重新核对 SHA/digests，并验证 plan 中 node/path 存在于 merge contract。任一 binding 不一致即失败，不使用 stale plan。

### 9.3 Trusted planner

稳态 PR planning 使用 base commit 中的 trusted planner executable，读取 base 与 merge tree 的数据。merge tree 中刚修改的 planner 不能决定自己是否需要 self-hosted execution。

planner 及其 registry/parser 模块通过 base registry 映射为 `scope: all`；修改这些文件会选择全部现有 nodes。若新 schema 无法被 base planner 理解，planning 明确失败或进入受控 infrastructure migration，而不是运行 merge planner 自我放行。

## 10. Selective baseline materialization

普通 `gamesymbol_snapshot.py restore` 保持“完整恢复且可 round-trip 重建 snapshot”的现有语义，不增加通用 `--exclude`。

不要实现 CS2 的“restore 全量 + `invalidate` unlink 失效 YAML + 全量 analyzer”。那套依赖 persisted bin 里已经有 YAML，并用 skip 做增量。GoldSrc PR 工作区的 YAML 只允许来自下面的 selective materialization；禁止先 robocopy `PERSISTED_WORKSPACE/bin` 再当分析输入。

新的 PR validation CLI 提供专用 selective materialization：

1. 从 Git base revision 读取 base snapshot、base config 与 base `bin` gitlink；
2. 验证 base snapshot canonical/config/binary metadata contract；
3. 计算 base/merge binary、config、source、registry 与 snapshot impact；
4. 在 merge execution workspace 中只写入：

```text
base snapshot paths
∩ merge contract paths
- invalidated artifact paths
```

5. invalidated artifacts 从一开始就不落盘；
6. materializer 对每个 path 执行 canonical payload、path escape、symlink/reparse-point 与 real-tree checks；
7. materialization 不声称 merge workspace 能重建 base snapshot，它只是增量执行准备步骤。

若一个 binary 变化，必须排除该 module/platform 的全部 outputs，以及 DAG 下游依赖 nodes 的 outputs，而不仅是名称看起来属于该 binary 的 YAML。

## 11. Untrusted-base fallback

base snapshot 缺失或不可信时，不使用任何 base YAML：

```text
trusted base
  -> selective materialize
  -> selected-node incremental execution

missing/untrusted base
  -> clean merge workspace
  -> restore nothing
  -> select every merge node for the tag
  -> full rebuild
```

full rebuild 必须：

- plan 中明确记录 `mode: full-rebuild` 与具体 reason；
- 清除现有全部 analysis YAML；
- 执行 merge contract 的全部 nodes；
- 构建 actual candidate 并严格比较 merge snapshot；
- 不自动修改或提交 expected snapshot；
- 不把旧 base 重新标记为可信。

明确新增 tag 天然选择全部新 nodes。删除 tag 不运行 IDA，但必须同步删除 config、`configs/config.yaml` index item 与 tracked snapshot。tag rename 按“删除旧 tag + 新增新 tag”处理。

## 12. Selected-node analyzer execution

### 12.1 CLI

CS2 基线没有 `-node`。GoldSrc 因 10 个 tags、多模块二进制，不能为未选中模块启动 IDA，因此新增可重复参数：

```text
-node <module:platform:skill>
```

未传 `-node` 时，普通本地分析行为保持不变。`-node` 与现有 `-skill` / `-modules` / `-platform` / `-allgamever` 同时出现时 **硬失败**，不求交、不覆盖。PR workflow 只使用 `-gamever` + 重复 `-node` + `-oldgamever none`，不传 `-skill`/`-modules`。

`-node` 不改变 scheduler 默认路径；scheduler 与普通 `-allgamever` 禁止注入 `-node`。selected-node 运行仍构建完整 merge DAG，但 Process reporter 只为 selected nodes 及其必要的 binary lifecycle 发出 task；不得为了 reporter 形状去执行未选中节点。

### 12.2 执行语义

- analyzer 始终先构建完整 merge DAG；
- 所有 requested node IDs 必须存在；
- 只验证、启动并执行 selected nodes 涉及的 binaries/IDA lifecycles；
- selected nodes 按完整 DAG 的拓扑顺序执行；
- analyzer 不自行扩展 selection；impact planner 负责下游闭包；
- 未选中的上游 inputs 必须已由 selective materialization 提供；
- required input 不存在且不会由 selected producer 生成时，直接失败；
- selected nodes 强制绕过 `EXISTING_OUTPUTS` 与 `skip_if_exists`；
- runner 在执行前仍删除 selected nodes 的 owned outputs。

PR workflow 固定传入：

```text
-oldgamever none
```

因此 PR validation 不读取其他 game version 的 YAML，不建立跨 tag old-version relocation DAG。普通本地分析仍可保留自动 old-version selection；发布前必须在相同 PR 模式下重新验证。

## 13. PR workflow architecture

### 13.1 Trigger 与 trust boundary

- workflow 监听 `opened`、`synchronize`、`reopened`、`ready_for_review` 与 `closed`；
- 非 `closed` 事件运行 planning/validation，`closed` 事件只运行 finalizer；
- 同仓库 PR 一律启动轻量 planning job；
- fork PR 不进入 self-hosted runner；
- fork PR 仍可运行安全的 hosted formatting/unit tests；
- planning 没有 actions 时明确输出 `no affected game-symbol actions` 并成功结束；
- 不依赖 GitHub static `paths` filter 判断真实 ownership。

验证对象是 GitHub PR merge commit，而不是孤立 branch head。plan 同时绑定 base SHA、branch head SHA 与 merge SHA。

GoldSrc 仓库 allowlist 写本仓库的 GitHub full name，不要抄 CS2 的 `HLND2T/CS2_VibeSignatures` / `hzqst/CS2_VibeSignatures`。本仓库当前没有 bump-download / gamesymbols bot PR，不必复制 CS2 那两段 bot 排除；以后若增加，再单独设计。

### 13.2 Hosted planning job

GitHub-hosted runner 使用 base trusted planner，只执行：

- Git diff 与 rename/copy status parsing；
- base/merge config schema 与 semantic diff；
- Python AST/import/reference consumer analysis；
- Agent skill path ownership；
- base/merge registry parsing；
- submodule tree diff；
- snapshot delta；
- DAG closure 与 canonical plan generation。

planning 不执行 PR preprocessors、skills 或 IDA code。planning **不 checkout** `bin` 子模块的大二进制；只读取 base/merge gitlink 并用 `git ls-tree` 比较声明的 `module_<platform>` 路径。若 `GoldSrc_VibeSignatures_bin` 需要凭证，凭证只用于能读 tree 对象，不把 blob checkout 进 hosted planning workspace。

### 13.3 Hosted validation job

若 `analysis_nodes` 为空，但存在 `snapshot_rebuild` 或 `gamedata_rebuild`，在 GitHub-hosted job：

- checkout merge commit 与精确 `bin` submodule（此 job 需要真实 PE32/ELF32 才能计算 schema 5 hash；与 planning 的 ls-tree-only 不同）；
- selective materialize 或 clean full-rebuild preparation；
- build/guard/compare symbol candidate；
- 执行 empty gamedata candidate gate；
- 不占用 self-hosted IDA runner。

`bin` 子模块若为 private，hosted validation 必须使用最小权限 token。不要改用 CS2 的 persisted-bin robocopy 来“避免 checkout submodule”。

### 13.4 Windows self-hosted analysis job

只有存在 `analysis_nodes` 时才进入 Windows self-hosted runner：

- GitHub Environment 使用受信任的 Windows self-hosted 环境（名称可与 CS2 一样叫 `win64`，但 secrets、路径与变量必须是 `GSVIBE_*`）；
- secrets 通过 environment variables 注入；
- 典型变量包括 `GSVIBE_AGENT`、`GSVIBE_AGENT_MODEL`、`GSVIBE_LLM_APIKEY`、`GSVIBE_LLM_BASEURL`、`GSVIBE_LLM_EFFORT`、`GSVIBE_LLM_MODEL`、可选受控 temperature；`PERSISTED_WORKSPACE` 仅当启用 YAML promotion 时才需要；
- **禁止**像 CS2 workflow 那样写入 `GSVIBE_LLM_FAKE_AS: ${{ secrets.GSVIBE_LLM_FAKE_AS }}`。该变量必须未设置或为空，不允许 fake response；
- 只有 selected node 明确需要时才使用 LLM/Agent；
- LLM/Agent failure 使 validation 失败；
- 日志不得输出 API key；
- actual candidate 与 expected snapshot strict compare 是最终门禁。

### 13.5 Concurrency 与 workspace

- validation job 使用 `actions/checkout` 在默认 `$GITHUB_WORKSPACE` 检出 PR merge ref，`fetch-depth: 0`，不手工创建或维护 per-PR repository workspace；
- workflow concurrency group 按 repository + PR number 隔离，`cancel-in-progress: true`；
- self-hosted IDA runner pool 保持单执行容量，因此不同 PR 在 runner 层排队，同一 PR 的新 commit 取消旧 run；
- 一个 job 按 `configs/config.yaml` 顺序逐 tag 执行，跳过第 9.1 节的零 symbol no-op tags；
- 某 tag 失败后立即停止后续 tags；
- self-hosted job timeout 必须显式设置，并按“`scope: all` 打到全部非空 tags”估算最坏墙钟时间；默认 6 小时不够时提高 timeout，而不是改成 GitHub matrix 并行多个 IDA jobs；
- cleanup 只终止当前 job 启动的 workers，并删除 candidate、session 与其他当前 run 临时产物；default checkout 不会递归清除 submodule ignored files，因此 workflow 必须在分析前后对已验证为 `$GITHUB_WORKSPACE/bin` 的 submodule 执行 clean；
- 工作区二进制来自 checkout 的 `bin` submodule，不要先从 `PERSISTED_WORKSPACE` 覆盖 `bin/`。

### 13.6 YAML staging、merge promotion 与 closed finalizer

CS2 的 staging/promotion 服务于“persisted bin 同时保存二进制和 YAML，下一次 PR 从那里 robocopy”。GoldSrc 二进制已在 git submodule，PR YAML 来自 snapshot materialize。因此本小节 **不是** actual/expected 比较的正确性条件，只是 self-hosted runner 上 accepted YAML workspace 的可选同步。

第一版 Infrastructure 可以不做 promotion：validation 成功即可，closed finalizer 只清理 staging（若未创建则为 no-op）。若实现 promotion，必须遵守：

- `.i64`、`.id0` 与其他 IDA database/cache 只存在于当前 validation run，不复制到 `PERSISTED_WORKSPACE`，也不得残留到 self-hosted runner 的下一次 checkout；不得抄 CS2 把 `*.i64` 拷进工作区的步骤；
- 只有整个 PR validation 成功，且所有受影响 tags 都完成 actual/expected comparison 与对应 candidate gates 后，才允许 staging；
- staging 只包含本次实际执行 analysis nodes 的 tags 下完整 `bin/<tag>/**/*.yaml` 状态，不包含 binaries、IDA databases、candidate/session 或其他临时文件；
- staging root 固定为 `PERSISTED_WORKSPACE/pr-yaml-staging/<PR>/<run_id>-<run_attempt>/`，保留 `bin/<tag>/...` 相对布局，并记录 PR number、base/head/merge SHA、run ID/attempt、tag inventory 与 plan digest；
- `snapshot_rebuild`/`gamedata_rebuild`-only 或 no-op plan 不要求 YAML staging；closed finalizer 必须使用 bound plan 区分“无需 promotion”与“应有 staging 但缺失”；
- closed finalizer 仅接受同仓库 PR，运行在独立的受保护 cleanup environment，只读取完成 promotion 所需的 `PERSISTED_WORKSPACE` secret，不注入 IDA/LLM secrets；
- PR `closed` 且已合并时，finalizer 按数值选择与最终 head/merge SHA 绑定的最新成功 staging，将其中各 tag 的完整 YAML 状态 promote 到 `PERSISTED_WORKSPACE/bin/<tag>/`；
- merged PR 若 plan 要求 YAML promotion，但不存在匹配 staging、manifest 绑定不一致或 inventory 不完整，finalizer hard fail，不复用更旧或其他 PR 的产物；
- PR 未合并时不 promotion 并删除该 PR staging；merged PR 仅在 promotion 完整成功后删除 staging；hard failure 保留 staging 供诊断或重试；
- promotion 只更新 runner 的 accepted YAML workspace，不修改 Git tree、不调用 `gamesymbol_candidate publish`，也不改变 tracked snapshot 仍是 canonical baseline 的事实；
- promotion 应在 per-tag lock 下完成完整目录替换，避免旧 optional YAML 残留；多 tag PR 只消费同一个成功 run 的 staging，不混用不同 runs。

## 14. Candidate 与 comparison contract

- PR 作者负责提交 `gamesymbols/<tag>.yaml`；
- CI actual candidate 只在临时目录构建；
- CI 不调用 tracked publication；
- 若启用 closed finalizer，它对 `PERSISTED_WORKSPACE/bin/<tag>/` 的 YAML promotion 只是 runner accepted-workspace 更新，不属于 tracked publication，也不是下一轮 PR 的分析输入；
- comparison 只忽略 `last_publish_time`；
- schema version、config digest、output contract version、binary metadata、artifact inventory 与每个 artifact payload 必须完全相等；
- canonical serialization 消除 YAML formatting-only differences；
- expected merge snapshot 只能作为 comparison target，不能作为分析输入或用于补齐缺失 artifacts。

当前没有 tracked gamedata，因此 Infrastructure PR 不迁移 `verify-tracked`。引入首个真实 generator 时，再同时设计 tracked gamedata contract 与 Git-tree verification。

## 15. 测试策略

Infrastructure PR 采用 Level 2/TDD，至少覆盖：

- base/merge config semantic diff；
- node fingerprint included/excluded fields；
- unique producer、zero-owner symbol、以及 CS2 多 owner 语义被拒绝；
- node fingerprint 不含 `max_retries` / `order` / config list position；
- preprocessor import/reference consumers：`{gamever}` 当前 tag、canonical `hl-10210` fallback、orphan HEAD reference error；
- `ida_analyze_util` / 同目录 helper / `prompt/call_llm_decompile.md` 变更会 seed，而不是 silent；
- `.claude/skills/<skill>` ownership；无同名 node 时无影响；
- base/merge registry union；
- invalid registry paths/scopes/globs；
- 非分析路径 unmapped → silent no-impact；分析源 unmapped → fail-closed 或 broad rebuild；
- `bin` submodule commit/path diff 只认 `module_<platform>`；`*.decrypt.*` 不是 seed；
- snapshot delta → owner nodes；
- required/optional output invalidation；
- add/delete/rename tags；零 symbol tag 在 `scope: all` 下仍 no-op，直到同 PR 提交 snapshot；
- `-node` 与 `-skill`/`-modules`/`-platform`/`-allgamever` 组合硬失败；
- trusted incremental 与 untrusted full-rebuild modes；
- selective materialize path escape、link/reparse-point、undeclared/stale output protection；
- `-node` unknown ID、force execution、missing input 与 topological order；
- `-oldgamever none` workflow contract；
- plan SHA/digest binding；
- hosted/self-hosted/no-op routing；
- self-hosted same-repository trust boundary；
- workflow 不 publish、不 commit、不 push；
- default checkout merge ref、full-history 与 no-custom-PR-workspace contract；
- 若实现 staging/promotion：validation-success-only YAML staging、complete tag inventory、manifest SHA/plan digest/run binding、merged promotion、unmerged cleanup、missing/stale staging hard failure、no-promotion plan、64-bit run ID 排序、multi-tag 不混用 runs；
- 若不实现 promotion：workflow 测试必须证明不依赖 persisted YAML/i64，且 closed 事件不失败；
- workflow 不得出现 CS2 的 `*.i64` robocopy、`download.yaml[-1]` GAMEVER 选择、或 `LLM_FAKE_AS` secret 透传；
- `.i64`/IDA database 不进入 staging、promotion 或其他 persisted cache。

完成前运行仓库规定的 formatting、unit、repository-contract 与 full suites；无法运行任何关键验证时，不得声称完成或可合并。

## 16. 验收标准

### 16.1 Baseline PR

- 10 个非空 tags 各自拥有 schema 5、contract-valid、byte-stable snapshot；
- 每个 snapshot 的 `binaries` 非空，覆盖该 tag config 声明的全部 `path_*` 平台，hash 来自 `module_<platform>` 源文件而不是 `*.decrypt.*`；
- `hl-3248`–`hl-6153` 已补 `path_*`；
- `svencoop-10257` 不再产生 config digest mismatch，且 repository-contract 不再锁 `file_count == 2`；
- 新 snapshot 已 `git add -f`，不被根 `.gitignore` 的 `gamesymbols/*.yaml` 漏提交；
- Counter-Strike 不产生空 snapshot；
- Pages `verify:gamesymbols` 与 e2e 在新 index（`versions[0]` 将为 `cof-5936`）上通过；
- 每个 tag 有独立 candidate/session/gamedata guard 证据；
- 不运行 IDA；
- 所有 repository quality gates 通过。

### 16.2 Infrastructure PR

- base trusted planner 能对 merge tree 生成 canonical bound plan；
- preprocessor/reference/skill/config/binary/snapshot changes 能精确映射到 nodes 与下游 artifacts；
- 改 `references/hl-10210/...` 会使回退到该 canonical 文件的其他 tags 失效；CS2 风格的 `{platform}`-only matcher 测试必须失败；
- 分析源映射失败不会 silent skip；
- selected-node execution 只启动受影响 binaries，且不与 `-skill`/`-modules` 混用；
- selective materialization 不恢复 invalidated artifacts，也不从 persisted bin 预填 YAML；
- 零 symbol tag 在共享文件变更下保持 no-op；
- untrusted base 明确 full rebuild；
- actual candidate strict match merge snapshot；
- same-repo/self-hosted/secrets/concurrency boundary 生效；`GSVIBE_LLM_FAKE_AS` 未注入；
- default checkout 不依赖自定义 per-PR repository workspace，也不 robocopy CS2 式 persisted bin/i64；
- 若实现 promotion：只有完整成功的 analysis run 才 staging YAML，且只有合并后的匹配 run 才 promotion；failed、cancelled、partial 或 unmerged PR 不污染 accepted YAML workspace；
- `.i64` 与其他 IDA databases 不持久化；
- CI 不修改、commit、push 或 publish Git tracked outputs；
- 全部新增与现有测试通过。

## 17. 后续 Coverage 阶段

基础设施迁移完成不等同于所有 family 的 symbol coverage 完成。

Infrastructure PR 合入后开启独立 Coverage 阶段：

1. 为 `cstrike-8684` 声明并生成首批真实 symbols；
2. 为 `cstrike-10210` 声明并生成对应 symbols；
3. 每个 tag 使用已落地的 PR gate、candidate 与 snapshot contract；
4. 未来引入真实 downstream generator 时，再迁移 `verify-tracked` gamedata gate。

## 18. 已接受的主要权衡

- 非分析路径未映射时静默无影响，优先减少文档/测试误触发；分析源未映射则 fail-closed 或 broad rebuild，优先避免 GoldSrc `{gamever}` / `ida_analyze_util` import 图漏验。这比旧稿“全部 silent”更接近 CS2 preprocessor 行为，但 reference/import 实现仍必须是 GoldSrc 自己的；
- base snapshot 不可信时 full rebuild，优先正确性与可恢复性；代价是 10 个 tags 串行时墙钟时间与模型非确定性增加，必须用显式 job timeout 兜住；
- PR 禁用 old-version relocation，优先 tag 隔离与可复现性；代价是失去旧 YAML relocation fast path；
- expected snapshot 由 PR 作者维护，CI 只读验证；代价是作者必须显式提交产物；
- 用 `-node` 代替 CS2 的“全量 analyzer + EXISTING_OUTPUTS”；优先避免为未受影响模块启动 IDA，代价是新增 CLI 与 reporter 子集契约；
- YAML promotion 降为可选 runner 同步，不作为 PR 正确性条件；优先承认 GoldSrc 二进制已在 submodule、YAML 来自 snapshot。若做 promotion，仍只在完整验证成功且 PR 合并后写入 accepted workspace；
- 不持久化 `.i64`/IDA databases，也 **不** 抄 CS2 把 persisted `*.i64` 拷进工作区；优先避免跨 PR 的陈旧或可变数据库污染，代价是 cache miss 时需要重新生成 IDA database；
- 暂不迁移 `/create-pr` 分类器；在 GoldSrc 尚无该 skill 时先完成 CI workflow contract，后续再单独设计 author-side delivery lifecycle；
- 不追求 CS2 目录级或文件级同步。施工对照物是本文件，不是 `D:/CS2_VibeSignatures` 里的同名 Python/YAML/workflow。
