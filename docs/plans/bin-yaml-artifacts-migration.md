# 分析 YAML Git 托管与 Release 派生产物迁移计划

状态：实施中

日期：2026-08-31

优先级：P1

基线：`main@daf54ea`

## 实施记录

- 2026-08-31：完成步骤 1–7，`bin_artifacts` 已成为 Git truth，并已接入隔离的 release bundle
  build、GitHub-hosted verify 和 protected publish jobs。
- 2026-08-31：步骤 8 的真实 non-publishing Actions run
  `33377379614` 已通过 hosted preflight，但仓库没有注册的 self-hosted runner，因而停在
  `warmup-idb` 排队；该 run 已请求取消，未产生 Actions Artifact、tag 或 Release。runner 恢复后必须重新执行并通过
  build → upload → hosted verify，方可满足最终验收。
- 2026-08-31：步骤 9 的 GitHub 远端 drain 审计未发现 open PR 或
  `gamesymbols/build/*` remote branch。私有 `PERSISTED_WORKSPACE` 因 runner 缺失不可访问；新流程禁止恢复旧
  staging state，legacy state 的 inventory/backup/cleanup 延后到 runner 恢复后的步骤 11 门禁执行。
- 2026-08-31：完成步骤 10–11 的仓库改造。Git versioned outputs、generated-output PR/promotion 状态机和旧
  snapshot baseline materializer 已删除；Agent fallback 通过 invocation artifact contract 使用精确的
  `bin_artifacts` 路径。新增 `cleanup-legacy-accepted-yaml`，在 per-gamever lock 下先验证 binary-only
  materialization，再创建 canonical exact-hash backup，支持 verified `.incoming` 与 partial deletion 幂等恢复。
  私有 `PERSISTED_WORKSPACE` 的实际 inventory/cleanup 仍因 runner 缺失无法执行，runner 恢复后必须使用同一
  cutover identity 执行该运维门禁。
- 2026-08-31：完成步骤 12 的独立 code review 与本地全量验证。review 后进一步将 hosted verifier 收紧为固定
  Release asset allowlist，并安全枚举、解包 `.7z` 后逐文件对照可信 Git/bundle bytes；manifest 额外绑定
  source/run/bin gitlink、generator、IDA runtime 和 warm-cache selection evidence。accepted-bin 增加 persisted
  root link/overlap 与 durable backup inventory 校验，PR planner 对删除/空 contract fail closed，snapshot CLI
  只接受显式 legacy snapshot，Pages 只部署已发布 Release 且由 publish job 显式 dispatch。Python unit 为
  455 tests，repository contract 为 14 tests，`all` 为 473 tests（4 个环境性 skip）；Pages 为 53 tests、5 个
  E2E，Windows absolute input build、formatter、`actionlint` 和 `git diff --check` 均通过。由于仓库仍无
  self-hosted runner，release dry run 的 build/hosted verify 和私有 persisted cleanup 尚无通过证据，因此计划
  状态继续保持“实施中”，PR 不得宣称最终外部验收完成。

## 1. 目标

把当前位于 `bin/**/*.yaml` 的 per-symbol 分析产物迁到主仓库可跟踪的
`bin_artifacts/<gamever>/<module>/`，并将其确立为分析结果的唯一 Git truth。

迁移完成后：

1. `bin/` 只承载二进制和可重建的 IDA/BinSync 临时状态；
2. `bin_artifacts/` 是其他分析脚本读取、写入和依赖解析的唯一 YAML 根；
3. source PR 必须证明“merge commit 提交的 `bin_artifacts` == 同一 merge commit 在可信环境中的重跑结果”；
4. `gamesymbols/`、`gamedata/`、`release-manifests/` 不再保存版本化 Git 输出；
5. `gamesymbols`、metadata、gamedata、archive 和 release manifest 仅在 release build 中派生；
6. GitHub Actions Artifact 只作为 build → verify/publish 的传输介质；
7. GitHub Release 是公开发布载体，release tag 直接指向产生资产的 source SHA；
8. 取消 generated-output PR 和独立 promote workflow，在 `release-build.yml` 内保留隔离的
   `publish-release` job 作为最终发布门禁。

## 2. 非目标

- 不迁移 `bin/<gamever>/<module>/<binary>`；`bin` 仍是 git submodule。
- 不把 `bin_artifacts` 纳入 warm IDB cache identity；IDB cache 仍只是可重建的性能层。
- 不改变 `ida_preprocessor_scripts/references/` 的所有权；reference YAML 包含人工语义注释，继续由 Git 托管。
- 不在本次顺便重命名所有 finder 的 `new_binary_dir` 参数；先保持 ABI，内部语义改成 artifact module dir。
- 不保留 `gamesymbols` 作为 PR baseline、oldgamever baseline 或 accepted-bin truth。
- 不允许同版本 Release 内容覆盖；内容变化必须使用新版本号。

## 3. 背景与硬约束

### 3.1 `bin/` 是 submodule

- 主仓库只跟踪 `bin` 的 gitlink SHA。
- `bin/.gitignore` 忽略 `*.yaml`、IDA database 和 BinSync 文件。
- 主仓库无法安全地把 `bin/**/*.yaml` 作为普通文件提交。

当前基线下共有 273 个 per-symbol YAML，需要保持相对路径不变地迁移：

```text
bin/<gamever>/<module>/<artifact>.yaml
  ->
bin_artifacts/<gamever>/<module>/<artifact>.yaml
```

### 3.2 当前 `bindir` 是混合根

当前 snapshot/candidate/store 契约中的一个 `game_root` 同时用于：

- 从 `bin/<gamever>` 扫描 per-symbol YAML；
- 从 `bin/<gamever>` 定位二进制并计算 metadata；
- restore/materialize 时清理、重建 YAML；
- PR validation 和 release republish 时恢复或删除 YAML。

因此本任务不是只修改 `ida_analyze_bin.py` 的目录平移，而是一次 binary root / artifact root 的契约拆分。

## 4. 目标信任模型

| 层级 | 内容 | 是否 truth | 生命周期 |
|---|---|---:|---|
| Git source truth | configs、finder/generator、`bin` gitlink、`bin_artifacts`、reference YAML | 是 | 随 source commit |
| PR rebuild workspace | 从 merge Git blobs materialize 的 baseline + 重跑输出 | 否 | 单次 CI |
| Warm IDB / accepted-bin | 中性 IDB、binary/side-file cache | 否 | 可删除、可重建 |
| Release bundle | gamesymbols、metadata、gamedata、archives、manifest、checksums | 候选 | 单次 workflow |
| Actions Artifact | 完整 release bundle | 否，仅传输 | Actions retention |
| Draft GitHub Release | 已上传但尚未公开的候选资产 | 发布 staging | 可恢复 |
| Published GitHub Release | 对外分发资产 | 是，发布层面 | 永久且不可覆盖 |

### 4.1 PR 数据流

```text
merge commit Git blobs
  ├─ source/config/bin gitlink
  └─ bin_artifacts/**                 # 只读 expected
            │
            ▼
trusted planner 计算 affected nodes / invalidated outputs
            │
            ▼
$RUNNER_TEMP/rebuilt-bin-artifacts   # 可写 actual
  ├─ 复制未失效的 merge artifacts
  └─ selected-node 强制重跑
            │
            ▼
exact inventory + Git blob byte comparison
```

### 4.2 Release 数据流

```text
preflight(source SHA + bin gitlink + version)
    -> warmup-idb
    -> build-release-bundle (self-hosted, contents: read)
    -> upload Actions Artifact
    -> verify-release-bundle (GitHub-hosted, contents: read)
    -> publish-release (GitHub-hosted, protected environment, contents: write)
    -> draft -> published GitHub Release
```

self-hosted build job 不得拥有创建 tag、Release、push branch 或修改仓库内容的凭证。

## 5. 核心设计决策

### 5.1 `bin_artifacts` 是 source-owned

- 普通 source PR 可以新增、修改和删除 contract 内的 artifacts。
- 每个 artifact 必须映射到 formal artifact contract 和唯一 producer node。
- artifact-only PR 也必须触发对应 node 和 downstream closure。
- 未知 tag、module、filename、额外路径或无法映射的 rename 必须 fail closed。
- `bin_artifacts` 不属于 release-owned path；不存在 output PR 代替用户更新它。

### 5.2 binary root 与 artifact root 全面解耦

统一语义：

```text
binary_root        = bin
binary_game_root   = bin/<gamever>
artifact_root      = bin_artifacts
artifact_game_root = bin_artifacts/<gamever>
artifact_module_dir
                   = bin_artifacts/<gamever>/<module>
```

所有二进制 identity/hash/loader 操作只接受 binary root；所有 per-symbol YAML 的读、写、删除、restore、materialize、
inventory、dependency lookup 只接受 artifact root。

### 5.3 `gamesymbols` 与 `gamedata` 是纯派生发布物

- repository contract 不要求工作树存在 `gamesymbols/`、`gamedata/`、`release-manifests/` 的版本化实例。
- snapshot 工具从 `bin_artifacts` 读取 YAML、从 `bin` 读取 binary metadata，输出到显式 staging 目录。
- gamedata 从同一次 build 的 gamesymbol candidate 生成。
- release manifest 是 release bundle 内的 canonical JSON asset，不写回 Git。
- 开发期脚本不得把 `gamesymbols` 当作 baseline 或分析输入。

### 5.4 Actions Artifact 只是传输层

- Actions Artifact 的名称绑定 `run_id/run_attempt/version/source_sha`。
- bundle 内有自身 manifest 和 checksum，下载后必须完整复验。
- 任何 release 恢复不得把 Actions Artifact 当长期 truth；可恢复 staging 使用 draft GitHub Release。

### 5.5 Release 版本不可覆盖

- tag 必须直接指向 immutable source SHA。
- tag 已存在时必须恰好指向该 source SHA，否则失败。
- published Release 已存在时：
  - manifest/hash 完全一致可视为幂等成功；
  - 任一内容不同则失败，禁止 `--clobber`、移动 tag 或覆盖资产。
- 当前 `mode=republish` 改为“恢复同一 source/build 的未发布 draft”；内容变化必须发布新版本。

### 5.6 accepted-bin 降级为 binary-only cache

- `PERSISTED_WORKSPACE/bin` 只允许 binary 和明确允许的 side files。
- per-symbol YAML、snapshot、gamedata、release manifest 不得进入 accepted-bin。
- accepted-bin 更新不参与 Release 正确性，可在发布成功后 best-effort 刷新。
- cache 刷新失败不回滚已发布 Release；后续可从 `bin` submodule 重建。

## 6. Formal artifact contract

### 6.1 Inventory 来源

不要用“config 中 symbols 的 basename 集合”自行拼 inventory。复用：

- `load_config()`；
- `build_execution_plan()`；
- `expected_symbol_artifacts()`；
- `build_artifact_ownership_index()`。

formal paths 包含：

- symbol artifacts；
- `expected_input` / `expected_output`；
- `optional_input` / `optional_output`；
- 按 module/platform 展开的 canonical relative paths。

### 6.2 Required / optional 策略

- required artifact 缺失：失败；
- optional artifact：仅在 producer 实际生成时进入 inventory；
- extra/stale YAML：失败；
- contract 根下的未知普通文件、未知嵌套目录：失败；
- Windows casefold 冲突：失败；
- 每个 formal output 必须有且只有一个 producer。

### 6.3 路径与编码安全

- artifact root、gamever、module、文件及已存在祖先不得是 symlink/reparse point；
- 所有 relative path 必须经过 contained-path 校验；
- 禁止 absolute path、`..`、反斜杠、空段和非 canonical spelling；
- `.gitattributes` 增加 `/bin_artifacts/**/*.yaml text eol=lf`；
- expected 以 Git blob bytes 为准，不依赖 Windows checkout 换行；
- YAML writer 保持 UTF-8、LF、稳定 key order 和 canonical signature；
- 在同一 pinned 环境的两个 fresh artifact roots 上重跑，inventory 与 bytes 必须完全相同。

## 7. 代码改造范围

### 7.1 `ida_analyze_bin.py`

- 新增 `ARTIFACTS_DIR = "bin_artifacts"`。
- `analyze()` 和 CLI 新增 `artifactdir` / `-artifactdir`。
- `_outputs`、existing-output skip、artifact type map、required/optional inputs、selected-input validation 全部改走 artifact root。
- `run_analysis_pipeline`、`_execute_analysis_node`、`_execute_selected_nodes` 显式接收 artifact root。
- `new_binary_dir` 暂时传 `artifact_module_dir`。
- `old_yaml_map` 改走 old artifact root。
- `validate_runtime_artifacts` 的 current-module 分类根改成 artifact module dir，防止 live-address validation 静默跳过。
- 二进制路径继续由 `get_binary_path(bindir, ...)` 和 process plan 的 `binary_path` 提供。
- 为 release/CI 提供明确的 fresh rebuild / force-all 语义，不能依赖默认 existing-output skip。

### 7.2 `ida_analyze_util.py`、skill ABI 与 finders

- `ida_analyze_util.py` 的依赖读取、vtable lookup、LLM template 反推可保持逻辑不变；
- 保持 `<gamever>/<module>` 层级，使 `Path(new_binary_dir).parent.name` 仍是 gamever；
- `ida_skill_preprocessor.py` 与 finder 的 `new_binary_dir` 参数名本次保持兼容；
- finder 内直接 `Path(new_binary_dir)` 的读取自然切到 artifact module dir；
- writer 的 `expected_outputs` 由上游生成在 artifact root。

### 7.3 Snapshot / candidate / store 双根化

以下组件必须改，不能继续把 `bindir` 当混合根：

- `gamesymbol_snapshot_lib/config.py`：
  `SnapshotContract.game_root` 拆为 `binary_game_root` / `artifact_game_root`；
- `gamesymbol_snapshot_lib/operations.py`：
  `collect_actual_files` 走 artifact root，`collect_binary_metadata` 走 binary root；
- `pack_snapshot` / `verify_snapshot` / `check_snapshot_contract`：
  同时接收 binary root 与 artifact root；
- `restore_snapshot`：
  退出正常 PR/release correctness 路径，只保留显式兼容/迁移用途，且只能写 artifact root；
- `gamesymbol_snapshot_lib/materialize.py`：
  只操作隔离 artifact workspace，绝不清理 checkout 中的 tracked expected；
- `gamesymbol_snapshot_lib/candidate.py`、`gamesymbol_candidate.py`：
  CLI 增加 `-artifactdir`；
- `gamesymbol_store.py`：
  directory store 扫描 `bin_artifacts/<gamever>`。

### 7.4 外部读取点

- `generate_reference_yaml.py::build_existing_yaml_path` 改读 `bin_artifacts`；
- reference generator 的 binary identity 推断仍从 `bin/<gamever>/<module>/<binary>` 获取；
- 搜索并迁移所有 `bin/**/*.yaml`、`rglob("*.yaml")`、restore/delete/materialize 的隐式读取点；
- `idb_cache*.py`、`copy_depot_bin.py`、`download_depot.py` 保持 binary-root 语义。

### 7.5 Repository contract

新增或拆分出 tracked artifact contract，负责：

- 按所有 configured gamevers 建立 formal artifact inventory；
- 校验 required/optional、canonical YAML、路径安全和 ownership；
- 拒绝 `bin/**/*.yaml` 被当作 source truth；
- 拒绝 Git 跟踪的版本化 `gamesymbols/`、`gamedata/`、`release-manifests/` 输出；
- 为每个 gamever 返回排序后的 `path + size + sha256` Git blob inventory digest。

原 `generated_output_contract.py` 不再校验工作树中的已提交 gamesymbols/gamedata，可：

1. 拆成 `bin_artifact_contract.py` 和 `release_bundle_contract.py`；或
2. 保留模块名但重定义为显式的 repository/release 两种子命令。

优先选择职责拆分，避免继续使用“generated output 已提交到 Git”的旧语义。

## 8. PR validation 重构

### 8.1 Trusted planner

当前 plan job 从 PR merge commit 执行 planner。迁移后应：

- 在独立目录 checkout base/default-branch 的可信 planner 和 lockfile；
- 把 base/head/merge Git tree 只作为数据读取；
- `persist-credentials: false`；
- submodule URL 和分析 runner 配置来自可信 base；
- bound plan 绑定完整 source SHA、merge SHA、bin gitlink 和 artifact manifest。

### 8.2 Plan schema

升级 bound plan schema，至少包含：

- base/head/merge SHA；
- base/merge bin gitlink SHA；
- 每个 tag 的 base/merge config digest；
- base/merge artifact inventory digest；
- affected nodes；
- invalidated formal paths；
- snapshot/gamedata release-impact 标志如仍被其他验证需要；
- plan canonical digest。

artifact changed path 处理：

- A/M：使用 merge ownership；
- D：使用 base ownership，并验证 merge contract 是否仍声明；
- R/C：同时校验 old/new path；
- unknown/extra path：失败；
- artifact owner 加入 seeds 后计算 downstream closure。

### 8.3 隔离重跑

对每个受影响 tag：

1. 从 merge Git tree 导出完整 expected artifact manifest 和 blobs；
2. 创建 `$RUNNER_TEMP/rebuilt-bin-artifacts/<tag>`；
3. 复制除 invalidated outputs 外的 merge artifacts；
4. 恢复 exact warm IDB selection；
5. selected-node 强制执行，输出只写临时 artifact root；
6. 验证所有 selected nodes 确实执行，禁止 existing-output skip；
7. 校验 actual formal inventory；
8. 对完整 inventory 做 Git blob byte comparison；
9. checkout 中的 tracked `bin_artifacts` 在 job 前后 hash 必须不变。

故意提交一字节错误、缺文件、额外文件、错误 rename 都必须使 required check 失败。

### 8.4 Fork 策略

- fork PR 不得使用 self-hosted IDA runner、LLM secrets 或 persisted workspace；
- trusted planner 仍必须识别其 artifact/source 影响；
- 需要分析的 fork PR fail closed，并提示 maintainer 镜像到 same-repository branch；
- fork 修改 planner 使计划为空不得绕过 required check。

## 9. Release bundle 与 manifest

### 9.1 Bundle layout

build job 在 `$RUNNER_TEMP` 生成一个完整且封闭的目录，例如：

```text
release-bundle/
  gamesymbols/
    <gamever>.yaml
    <gamever>.metadata.yaml
  gamedata/
    <gamever>/...
  archives/
    gamedata-<gamever>.7z
    gamebin-<gamever>.7z
  release-manifest-<version>.json
  SHA256SUMS-<version>.txt
```

`gamedata-<gamever>.7z` 至少包含：

- `configs/<gamever>.yaml`；
- `bin_artifacts/<gamever>`；
- gamesymbol snapshot 和 metadata；
- `gamedata/<gamever>`；
- 如保持现有消费者兼容所需的 binary 内容。

`gamebin-<gamever>.7z` 保持 binary-only。

### 9.2 Release manifest schema

`release-manifest-<version>.json` 是 canonical JSON，至少绑定：

- schema version；
- release version；
- build ID / workflow run URL；
- source SHA；
- source commit subject；
- `bin` gitlink SHA；
- configured gamever inventory；
- 每个 gamever 的 artifact inventory digest；
- analysis config digest；
- snapshot/metadata digest；
- gamedata manifest/inventory digest；
- generator contract digest；
- IDA kernel/runtime identity；
- warm IDB cache selection digest；
- 每个 payload asset 的 path、size、SHA-256。

manifest 不记录自身 digest，避免自引用。`SHA256SUMS` 包含所有 payload assets 和 manifest，但不包含自身。

### 9.3 Bundle verifier

GitHub-hosted verifier 必须：

- checkout exact source SHA，确认仍可达 default branch；
- 验证 `bin` gitlink；
- 从 Git object 重算 `bin_artifacts` inventory；
- 校验 bundle 只有 allowlisted canonical paths；
- 重新运行 snapshot/gamedata/release bundle contracts；
- 重算所有 payload hash 和 `SHA256SUMS`；
- 验证 manifest bytes canonical；
- 将验证过的 bundle原样交给 publish job，禁止 publish job重新生成内容。

## 10. `release-build.yml` 重构

### 10.1 `preflight`（GitHub-hosted）

- 仅允许 allowlisted repository；
- source SHA 默认取当前 `origin/main`，且必须可达 default branch；
- 解析 version，检查 tag/Release/draft 状态；
- 同 repository/version concurrency，`cancel-in-progress: false`；
- 输出 source SHA、bin gitlink、version 和恢复模式；
- 内容变化不允许 same-version republish。

### 10.2 `warmup-idb`

- 保留现有 immutable cache generation 模型；
- selection 绑定 source SHA、bin gitlink、runtime；
- 不加入 artifact hash，避免把分析 truth 混入中性 IDB cache identity。

### 10.3 `build-release-bundle`（self-hosted）

- `permissions: contents: read`；
- private submodule 只使用最小 read token；
- 移除 `HLND2T_GH_TOKEN`、`gh auth setup-git` 和任何 push/release 权限；
- checkout exact source SHA 和 bin gitlink；
- 在 fresh temp artifact root 全量重跑并与 Git `bin_artifacts` 比较；
- 从验证后的 artifact tree 生成 snapshot、metadata、gamedata、archives、manifest、checksums；
- 本地执行完整 bundle contract；
- 上传唯一 Actions Artifact；
- 清理仅限本 job 创建的临时状态。

### 10.4 `verify-release-bundle`（GitHub-hosted）

- `permissions: contents: read, actions: read`；
- 下载 build job 的 exact Actions Artifact；
- 使用 `9.3` 的 verifier完整复验；
- 上传/转交“已验证 bundle”时绑定 digest，publish job 不得接受其他 artifact；
- 不持有 `contents: write`。

### 10.5 `publish-release`（GitHub-hosted）

- 依赖 verifier 成功；
- 使用独立受保护的 `release` environment，配置 required reviewers；
- job-level `permissions: contents: write`，其余 job保持只读；
- tag absent：创建指向 source SHA 的 tag；
- tag present：必须已指向 source SHA；
- 创建或恢复相同 identity 的 draft Release；
- 上传 assets 时禁止 `--clobber`：
  - 不存在则上传；
  - 已存在则下载/读取 remote digest，必须完全一致；
- 上传后再次验证远端 asset name/size/hash；
- 最后执行 draft → published；
- published Release 已完全一致则幂等成功，否则失败。

该 job 是新的语义 promotion gate，但不再需要独立 workflow 或 output PR merge。

### 10.6 发布失败恢复

- tag 已创建、draft 未完成：同 identity 重跑恢复；
- 部分 asset 已上传：相同 hash 复用，不同 hash 失败；
- draft identity 与 source/version/manifest 不同：失败，不覆盖；
- publish 前失败：保留 draft 供恢复；
- publish 后 cache 刷新失败：Release 保持成功，单独重建 cache；
- 禁止通过更换 build ID 绕过已存在 draft 的 identity 检查。

## 11. 删除与降级的旧机制

完成 cutover 后删除或重构：

- generated-output branch `gamesymbols/build/*`；
- generated-output PR 创建和验证；
- `.github/workflows/validate-generated-output-pr.yml`；
- `.github/workflows/promote-release-after-output-merge.yml`；
- abandon/cleanup staged-release workflows；
- output PR route、output branch parser、release-owned path allowlist；
- PR index、READY、PROMOTION_STARTED、PROMOTION_COMPLETE；
- private `release-staging/<version>/<build_id>` correctness 状态机；
- stage/finalize/verify-promotion/promote-bin/reconstruct/finalize-promotion 命令；
- Git tracked `gamesymbols/**`、`gamedata/**`、`release-manifests/**` 版本化实例；
- accepted-bin YAML reuse、old snapshot hydrate、republish YAML invalidation。

可保留并重用：

- canonical hashing/inventory helpers；
- version/source SHA/repository validation；
- manifest canonical JSON helpers（改成 Release asset schema）；
- warm IDB selection/restore；
- binary-only accepted-bin helper（作为 cache）；
- snapshot/gamedata candidate builders与 guards。

同步更新：

- `.claude/skills/trigger-release-build`：去掉内容型 republish，说明 draft resume/new-version 规则；
- README/docs/Basic Memory 中的 output PR、promotion、accepted-bin YAML 描述；
- branch protection required checks；
- GitHub environment/permissions 文档。

## 12. 数据迁移与 cutover

### 12.1 切换前门禁

在合并 cutover 前：

1. 冻结新的 release dispatch；
2. 完成、恢复或明确 abandon 所有 READY/PROMOTION_STARTED/output PR；
3. 确认没有 remote `gamesymbols/build/*` 活跃分支；
4. 备份 `PERSISTED_WORKSPACE/bin` 和未完成 stage 的 manifest/inventory；
5. 跑一次旧发布链 dry run，保留最后基线证据。

### 12.2 273 个 YAML 的一次性迁移

迁移工具或受控脚本必须：

1. 枚举 `bin/**/*.yaml`；
2. 计算相对路径、size、SHA-256；
3. 验证路径属于 formal artifact contract；
4. 拒绝 extra/stale/case collision/link；
5. 复制到 `bin_artifacts/**`；
6. 重新计算 destination inventory；
7. 要求 source/destination path + bytes 完全一致；
8. 将 `bin_artifacts` 加入 Git，并添加 LF attributes；
9. 不删除 `bin/.gitignore` 的 `*.yaml`。

### 12.3 原子 cutover

在同一 cutover 变更中：

- 启用所有 reader/writer 的 artifact root；
- 启用 repository artifact contract 和 PR byte comparison；
- 启用新 release build jobs；
- 删除 tracked versioned gamesymbols/gamedata/release manifests；
- 删除 generated-output PR / promote workflows；
- 禁止正常流程再从 `bin` 或 snapshot restore YAML。

不得出现“新 writer 写 `bin_artifacts`，旧 candidate 仍读 `bin`”的中间可合并状态。

### 12.4 Legacy persisted state

- 新 materializer 必须立即忽略 persisted `*.yaml`；
- 在 per-gamever accepted-bin lock 下对 legacy YAML 做 inventory 和备份；
- 新 binary-only cache 经过验证后再清理 legacy YAML；
- 未完成旧 stage 按 `12.1` 先处理，不能用新 schema强行恢复。

### 12.5 Rollback

rollback 不是只 revert workflow：

- Git 历史中的最后一版 gamesymbols/gamedata/release manifest 可恢复；
- 提供显式 `bin_artifacts -> bin` compatibility hydrate 工具供旧代码回退；
- 恢复旧 accepted-bin include 规则前，先校验 hydrate 后 YAML 与 Git artifacts hash 一致；
- 已发布的新模型 Release 不删除、不覆盖；
- 任何已开始的新 draft 必须先完成或按 identity 规则删除，再恢复旧 dispatch。

## 13. 测试策略与质量门禁

该任务改变共享路径契约、PR 安全边界和发布状态机，采用 Level 2（TDD）+ Level 3 review +
Level 4 completion verification。

### 13.1 单元/合同测试

必须覆盖：

- binary root / artifact root 完全分离；
- pack/verify/restore/candidate/store 从正确根读取；
- restore 不修改 binary；
- analyzer write/read/skip/oldgamever/runtime classifier；
- required/optional/extra/stale/case collision；
- symlink/reparse/path traversal；
- artifact changed path A/M/D/R/C → owner/downstream；
- artifact-only PR 不能产生空计划；
- bound artifact manifest tamper；
- checkout expected 不被 materialize/rebuild 覆盖；
- selected nodes 全部实际执行；
- full inventory 和一字节 drift；
- fork 修改 planner/plan 不能绕过；
- release bundle allowlist、manifest canonical、asset tamper；
- tag/draft/published idempotency 和 mismatch refusal；
- accepted-bin 不包含、不 materialize YAML；
- IDB cache selection 不受 artifact content 影响。

重点测试模块：

- `tests/test_analysis_planner.py`；
- `tests/test_snapshot_candidate.py`；
- `tests/test_gamesymbol_pr_validation.py`；
- `tests/test_generated_output_contract_validator.py`（重构后改名/拆分）；
- `tests/test_release_workflow.py`；
- `tests/test_release_workflow_guards.py`；
- `tests/test_generate_reference_yaml.py`；
- `tests/test_idb_cache.py`。

测试断言 Python 契约和行为，不通过测试锁定 workflow/YAML/文档文本。

### 13.2 集成验证

- 在两个 fresh artifact roots 对全部 gamever 连跑两次，要求 byte inventory 完全一致；
- 对迁移前 `bin/**/*.yaml` 和迁移后 `bin_artifacts/**/*.yaml` 做 273 文件 exact hash map；
- source PR 模拟：正确 artifact 通过，错误/缺失/额外 artifact 失败；
- release dry run：build → upload → hosted verify，不创建 tag/Release；
- sandbox version：创建 draft、验证远端 assets、publish，再验证幂等重跑；
- 验证 self-hosted job 没有 contents write、PAT 和 Release 权限；
- 验证 tag 目标等于 source SHA；
- 验证 Git 不再跟踪版本化 gamesymbols/gamedata/release manifests。

### 13.3 完成前命令

按仓库当时可用命令执行并如实记录：

```powershell
uv run python -m unittest -v tests.test_analysis_planner
uv run python -m unittest -v tests.test_snapshot_candidate
uv run python -m unittest -v tests.test_gamesymbol_pr_validation
uv run python -m unittest -v tests.test_generate_reference_yaml
uv run python -m unittest -v tests.test_release_workflow
uv run python -m unittest -v tests.test_release_workflow_guards
uv run python tests/run_test_suite.py unit -b --durations 30
uv run python tests/run_test_suite.py repository-contract -b --durations 30
uv run python tests/run_test_suite.py all -b --durations 30
git diff --check
```

workflow 另做仓库支持的 YAML/action validation；关键 release dry run 无法执行时不得声明迁移完成。

## 14. 实施顺序

1. 先补双根契约测试和 formal artifact inventory helper；
2. 改 analyzer、snapshot/candidate/store/reference reader 的双根 API；
3. 用受控工具迁移 273 个 YAML，并完成 exact hash 验证；
4. 接入 repository artifact contract；
5. 重构 trusted PR planner 和隔离 byte comparison；
6. 新增 release bundle builder/verifier/manifest schema；
7. 在 `release-build.yml` 增加 hosted verify 和 protected publish jobs；
8. dry run 新链路，验证权限、bundle 和 draft 恢复；
9. 执行旧 stage/output PR drain；
10. 原子删除 Git versioned outputs、generated-output PR 和独立 promote 机制；
11. 清理 legacy accepted-bin YAML，更新文档/skill/Memory；
12. 运行全量验证并进行独立 code review。

## 15. 验收标准

以下条件全部满足才可声明完成：

- `git ls-files bin_artifacts` 覆盖所有 formal artifacts；
- `bin_artifacts` 是分析 YAML 的唯一正常读写根；
- `bin/**/*.yaml` 不再参与 correctness；
- Git 不再跟踪版本化 `gamesymbols/`、`gamedata/`、`release-manifests/`；
- artifact-only/source PR 都能正确计算 affected nodes；
- CI 在隔离目录重跑，并对 Git blobs 做完整 inventory + byte comparison；
- fork 无法接触 self-hosted runner/secrets，也无法用空计划绕过；
- release bundle 可从 source SHA + bin gitlink + `bin_artifacts` 重建；
- self-hosted build job 没有发布权限；
- hosted verifier 对 bundle 完整复验；
- `publish-release` 是 `release-build.yml` 中唯一 contents-write job，受 protected environment 约束；
- tag 指向 source SHA，Release manifest 和 SHA256SUMS 作为 assets 发布；
- published Release 不允许覆盖；
- 不存在 generated-output PR、output branch 或独立 promote workflow；
- accepted-bin/IDB cache 明确是 binary/cache 层且不含分析 YAML truth；
- 新发布资产可仅凭 tag、release manifest 和 checksums 验证来源与完整性；
- 全量测试、repository contract、release dry run 和 `git diff --check` 均有真实通过证据。

## 16. 主要风险

1. **双根漏改**：candidate/restore/store 任一路径继续读 `bin` 会形成隐蔽第二真相源。
2. **自比较绕过**：在 checkout 原地重跑会发生 existing-output skip 或覆盖 expected。
3. **planner 信任倒置**：执行 PR 自己的 planner 可能让 fork 通过伪造空计划绕过。
4. **发布权限泄漏**：self-hosted runner 持有 PAT/contents write 会破坏 build/publish 隔离。
5. **非确定性**：IDA/LLM/PyYAML/runtime 漂移会导致合法 PR 无法 byte-match。
6. **历史 stage 不兼容**：旧 READY/PROMOTION_STARTED 无法直接套用新 manifest/schema。
7. **同版本覆盖**：保留旧 republish/`--clobber` 会破坏 Release不可变性。
8. **Actions retention 误用**：Actions Artifact 不能作为长期恢复 truth。
9. **archive 内容回归**：迁移后未显式加入 `bin_artifacts` 会让发布包静默丢失 per-symbol YAML。
10. **下游兼容**：依赖仓库内 `gamesymbols/gamedata` 的消费者需要改为开发期读 artifacts、发布期下载 Release。
