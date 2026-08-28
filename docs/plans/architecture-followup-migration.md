# GoldSrc 后续架构能力迁移方案

状态：PR 1-7 仓库实现与本地验证已完成；Release Phase 2 production activation 在外部门禁完成前保持 blocked；可选 PR 8 未实施

日期：2026-08-23（Asia/Singapore）

后续契约更新（2026-08-28）：release output 现允许发布 empty-symbol tag。此类 tag 在首次发布前仍可保持
config-only；一旦发布 snapshot，就必须同时发布 canonical metadata companion 与仅含空 inventory manifest 的
gamedata。下文关于 `cstrike-10210` / `cstrike-8684` 不生成发布产物的描述仅保留为原迁移阶段的历史设计。

GoldSrc 对齐基线：`https://github.com/HLND2T/GoldSrc_VibeSignatures` `main@e094c5af1044be26441ada79b8665b97bb685357`，tree `797de06a3289b25700f7db190678e5ff80f81604`，`bin` gitlink `65c8337f0ec37c73a7b20e43009204bd8f308e14`

CS2 参考基线：`https://github.com/HLND2T/CS2_VibeSignatures.git` `main@67b3238b13abc331c1df8da12cbf358aecf951bd`，tree `a7ffaba0b36e6a667af32a8fbffc4a170d97f935`

## 实施结果（2026-08-24）

本轮已按第 8 节拆分完成 PR 1-7 的仓库实现，并分别提交到 `dev`：

- PR 1：`9d14f90` `feat(ci): add stable pr validation gate`
- PR 2：`4e73e80` `feat(gamesymbols): add immutable alias metadata`
- PR 3：`88d92b9` `feat(gamedata): track canonical output manifests`
- PR 4：`8a5e279` `feat(release): add shadow content provenance`
- PR 5：`712ec73` `feat(ida): add immutable warm database cache`
- PR 6：`707e3e3` `feat(ci): integrate warm idb cache modes`
- PR 7：`38e13c4` `feat(release): add generated-output promotion`
- 后续 CI 简化：source PR planner 改为在默认 merge checkout 中原地执行；bound plan 与 selected-node 路由保持不变，终态 `pr-validate` 使用纯 shell 聚合 source job 结果。

仓库级验证结果：

- `uv run python format_repo_files.py --check` 通过；
- `unit` 运行 375 项并通过；
- `repository-contract` 运行 15 项并通过；
- `all` 运行 394 项并通过，其中 4 项因本地无 Redis 或真实 IDA 环境按设计跳过；
- Pages Vitest 16 个文件、49 项测试通过，ESLint、production build 和 10 个 Gamesymbol 资产验证通过；
- Playwright Chromium E2E 5 项通过。

以下真实环境验收尚未执行，因此步骤 6 只完成仓库实现与模拟测试，步骤 7 production activation 仍为 blocked：

- branch protection/ruleset、merge-commit-only、up-to-date required check、protected tags、`win64` Environment 与 PAT 权限/identity 的 captured evidence；
- PAT 创建 generated-output PR 后真实触发唯一 `pr-validate` 的事件链；
- draft、未合并、已合并、篡改、orphan/index repair、retry、resume-promotion 与 republish 的 protected test repository 演练；
- GitHub Release 上传后重新下载全部 assets 并核对 size/SHA-256 的真实证据；
- self-hosted runner 上 explicit cold、cache miss publication 与后续 cache hit 的运行证据。

在上述证据补齐前，Phase 2 remote-write authority 和 production republish 保持默认禁用，不得据此切换生产发布权限。PR 8 属于可选的 release-only authority cutover，仍需独立设计与批准。

## 1. 计划定位

本文是 `docs/plans/gamesymbol-infrastructure-migration.md` 已实施方案的后续阶段，选择性迁移以下四项能力：

1. immutable alias metadata companion；
2. 稳定的 `pr-validate` 终态门禁；
3. 可验证的 warm IDB cache；
4. Release provenance 与 promotion 状态机。

前一份方案把 IDB 持久化和 release promotion 列为当期非目标，是为了先建立 GoldSrc 自己的多 tag、语义 impact planner、selected-node execution、immutable candidate 与只读 PR validation。本文不改写那个历史决策，而是在上述基础已经落地后，为缓存和发布建立新的、显式的信任边界。

施工继续遵循“能力迁移，不做源码同步”。不得把 CS2 的同名 Python 文件或 workflow 当作 drop-in；所有身份、路径、schema 与失败语义都必须按 GoldSrc 的 `<family>-<build>` tag、PE32/ELF32、`bin` submodule、语义 planner 和当前 candidate contract 重写。

## 2. 当前基础与缺口

GoldSrc 当前已经具备：

- schema 6 canonical snapshot 与多版本 reader；
- config digest、binary hash 和 analysis output contract；
- immutable symbol candidate、gamedata candidate、session、guard 与 atomic publish；
- merge-workspace semantic impact planner、bound plan digest 与 selected-node analysis；
- hosted snapshot/gamedata gate、Windows self-hosted IDA gate；
- content-addressed Pages assets 与 append-only `pages-snapshots` archive。

本文只补以下边界：

- Pages 构建仍从当前可变 `configs/<tag>.yaml` 读取 alias，历史 snapshot 的展示语义没有冻结；
- gamesymbol PR workflow 没有一个固定名称、能覆盖所有动态路由结果的终态 required check；
- 当前没有 warm IDB cache/probe；self-hosted workflow 在每次分析前后清理 IDA database，因此每次都走 cold loader/auto-analysis；
- candidate/session 只证明一次本地生成事务；已有 canonical hashing/inventory 基础，但没有跨 source SHA、bin gitlink、generated-output PR、Git tag 和 GitHub Release 的 durable provenance；
- 当前 `finalize` job 在 `github.event.action == 'closed'` 时明确不做 staging 或 promotion，尚无 release publication authority；
- 当前 main 只跟踪 snapshot，没有 metadata、gamedata 或 release manifest；Release shadow 之前必须先完成 canonical-output bootstrap。

## 3. 总体决策

### 3.1 实施顺序

建议按以下顺序交付：

| 顺序 | 工作包 | 原因 |
| --- | --- | --- |
| 0 | 固定 identity、event、authority 与 activation gates | 先消除 manifest 自引用、PR 事件链、merge policy 和状态机歧义 |
| 1 | 稳定 `pr-validate` | 先固定 source/output PR 共用的 branch-protection contract；仓库配置在观察完成后再切换 |
| 2 | immutable alias metadata | 固定 snapshot/companion owner identity并回填当前snapshot |
| 3 | canonical gamedata bootstrap | 让source PR完整拥有snapshot、metadata、gamedata三类reviewed/tracked payload |
| 4 | release content manifest 与 shadow verification | 只证明 content identity/verifier，不 remote write，不改变 publication authority |
| 5 | warm IDB cache core 与 workflow | 可与步骤4并行；只优化性能，release必须保留显式cold mode |
| 6 | generated-output PR 与 promotion 演练 | 先在protected test repository验证event、merge、tag、Release与恢复路径 |
| 7 | production activation | 完成branch/ruleset、merge policy、protected tag、Environment和token门禁后才启用 |
| 8 | 可选 release-only authority cutover | 独立设计与批准，不随Phase 2自动实施 |

`pr-validate` 与 alias metadata 在实现层面相互独立，但仍建议先固定终态 check，避免后续 workflow 改造反复调整 branch protection。

### 3.2 目标数据流

```text
source PR merge ref
  -> merge-workspace semantic plan
  -> hosted and/or self-hosted validation
  -> stable pr-validate

selected binary identity + bound plan
  -> bind cache_mode
     -> warm: probe/publish exact immutable generation -> strict restore
     -> cold: validated clean -> normal loader/auto-analysis
  -> selected-node analysis

validated snapshot bytes + matching config projection
  -> gamesymbols/<tag>.yaml
  -> gamesymbols/<tag>.metadata.yaml
  -> content-addressed Pages asset

exact main source SHA + bin gitlink + source-PR-owned canonical outputs
  -> content manifest + generated-output PR
  -> output PR validation
  -> merge-time provenance verification
  -> immutable tag and verified GitHub Release assets
  -> durable completion record
```

### 3.3 不迁移内容

- 不迁移 CS2 的 changed-path full/light router；GoldSrc 保留 tag/node/DAG 语义 planner。
- 不迁移 CS2 的单 GAMEVER 假设和数字版本正则；GoldSrc tag 继续使用 `<family>-<build>`。
- 不引入 C++ ABI/HL2SDK gate。
- 不维护 `PERSISTED_WORKSPACE/bin/<tag>` accepted-bin 镜像；GoldSrc binary identity 由 Git `bin` submodule gitlink 与 snapshot hashes 提供。
- 不复制 BinSync `.bsproj`、`.binsync.json` 规则；GoldSrc 当前没有该状态域。
- warm cache 不保存 finder/Agent 已修改后的分析结果，只保存中性、可重建的 IDA baseline。
- READY pointer、Actions artifact、runner workspace 或 cache hit 均不是发布真相来源。
- 不伪造无法取得对应 config/upstream/source 身份的历史 metadata 或 release provenance。

### 3.4 Production activation 外部门禁

仓库代码和 contract tests 不能替代 GitHub/runner 外部配置。2026-08-23 核验时，`main` 没有 branch protection/ruleset，merge commit、squash、rebase 均允许，且仓库没有 Git tag 或 GitHub Release。因此 Phase 2 可以开发和在 protected test repository 演练，但 production activation 必须等待：

- `main` 禁止 direct push 与未审计的 admin bypass，并只 require 唯一的 GitHub Actions `pr-validate`；
- Phase 2初版配置merge-commit-only并把two-parent identity算法写入verifier；若未来改用merge queue或squash/rebase，必须先升级schema/verifier并重新演练；
- output branch prefix 只允许受信任 PAT account 或 release bot 创建，source/output workflow 使用同一个 classifier contract；
- protected tag pattern、`win64` Environment 审批、最小权限 PAT、Pages archive branch 保护均已配置；
- self-hosted runner 的 persisted root ACL、runner affinity/共享存储模型、全局 MCP port 互斥已经确定；
- 保存 GitHub 设置、workflow run、source SHA、bin gitlink 和演练结果的 captured-at 证据。

## 4. 工作包 A：Immutable alias metadata companion

### 4.1 目标

将 Pages 使用但 snapshot 本体不保存的 alias 投影冻结为与 snapshot 同版本发布的 companion：

```text
gamesymbols/<tag>.yaml
gamesymbols/<tag>.metadata.yaml
```

Pages 不再读取 `configs/<tag>.yaml`。config 的日常变化不能在没有新 companion 的情况下改变旧 snapshot 对应的 content-addressed JSON bytes。

### 4.2 字段边界

config 投影字段纳入 companion 必须同时满足：

1. 字段存在于 `configs/<tag>.yaml`；
2. snapshot 本体没有保存该字段；
3. Pages 构建确实消费该字段。

初版声明投影只包含 `modules[].name`、`symbols[].name` 和非空 `symbols[].alias`。此外必须保存由当前 planner 解析出的 record owner identity：`symbols[].artifacts[]` 中的 `platform + artifact`；它是绑定字段，不是要展示的 config 副本。当前 config 允许 `symbols[].artifact` 覆盖默认文件名，而 snapshot/Pages record 以解析后的 artifact stem 作为 owner；只保存逻辑 `name` 无法无歧义附加 alias。不得顺便复制 path、skill、description、重试参数或其他 config 内容。

companion schema 1 建议固定为：

```yaml
schema_version: 1
game_version: hl-10210
snapshot_sha256: <lowercase-raw-sha256-of-exact-canonical-snapshot-bytes>
config_digest_version: 2
config_sha256: <lowercase-raw-snapshot-bound-config-digest>
modules:
  - name: engine
    symbols:
      - name: SV_SendServerinfo
        artifacts:
          - platform: windows
            artifact: SV_SendServerinfo
          - platform: linux
            artifact: SV_SendServerinfo
        alias:
          - SV_SendServerInfo
```

相较 CS2 当前只有 config-shaped projection 的 companion，GoldSrc 增加顶层 schema、自绑定字段与解析后的 artifact identities。`snapshot_sha256` 与 `config_sha256` 都使用 lowercase raw 64 hex；读取 snapshot 内现有 `sha256:<hex>` config digest 时先验证算法前缀再规范化。Pages 在附加 alias 前必须以 `module + platform + artifact` 核对唯一 snapshot record，并核对 `game_version` 与 `snapshot_sha256`；不允许依赖 `name == artifact`，也不允许把同名但不匹配 snapshot 的 companion 静默附加到数据集。

### 4.3 生成与编码契约

新增 `gamesymbol_metadata.py`，至少提供：

```text
generate
verify
compare
```

- `generate` 必须读取 exact snapshot bytes，通过 `SnapshotSymbolStore`/snapshot codec 验证 game version、canonical bytes 与 config contract，再生成 companion；
- alias string/list 统一规范化为非空 string list，保持 config 声明顺序，拒绝非字符串、空字符串和重复成员；
- module、symbol 与解析后的 artifact identity 必须按当前 config contract 校验，每个 artifact 必须唯一命中 snapshot record，不允许 metadata 引入 snapshot/config 中不存在的 owner；
- 只输出有非空alias的symbol并省略空module；module/symbol保持config声明顺序，artifact按固定`windows, linux`顺序输出且只包含实际plan/snapshot存在的platform；
- 输出使用 canonical YAML、UTF-8、LF、稳定 key order 和同目录临时文件 `os.replace`；
- `verify` 验证 schema、canonical bytes、自绑定 hash、config digest 与 alias owner；
- `compare` 用于 PR workflow 比较临时生成 companion 与 tracked companion，错误信息必须指出 tag 与首个差异路径；
- companion 文件名必须由严格的 snapshot tag parser 派生，不能通过枚举 `*.yaml` 把 `.metadata.yaml` 误当 snapshot。

### 4.4 Candidate 与 PR planner 集成

alias metadata 不进入 symbol candidate bytes，以免为 UI projection 修改 snapshot schema；它作为与 snapshot 同一 Git-tree publication transaction 的独立 tracked output。文件系统不能原子替换两个独立文件，因此不得把两次 `os.replace` 描述成双文件原子发布。

candidate/session 必须扩展为：

- metadata 在 snapshot candidate bytes 固定后生成，session 记录 exact metadata path、SHA-256 与绑定的 snapshot SHA-256；
- guard/compare 同时验证 candidate snapshot 与 metadata pair；任一缺失或错配均 fail-closed；
- 本地 publish 先验证两份 staged bytes，再写包含 old/new digests 的 journal，按固定顺序替换并在中断后完成或回滚；中间错配状态不能通过 verifier；
- Git commit/tree 才是 snapshot 与 companion 对外可见的原子边界；release 只能读取 exact Git blobs，不能把本地 session/inode/mtime 当 durable provenance。

需要扩展 bound plan：

- `digests` 增加 `base_metadata:<tag>` 与 `merge_metadata:<tag>`；
- `snapshot_rebuild=true` 时必须同时执行 metadata generate/verify/compare；
- metadata 文件 add/modify/delete 视为 snapshot-domain change，但不选择 IDA nodes；
- `gamesymbol_metadata.py`、metadata schema/codec与共同owner parser变更视为snapshot-domain contract change，必须为现有snapshot选择companion rebuild/compare，但不能因此凭空选择IDA nodes；
- alias config change 保持现有 config semantic diff。当前 alias 已进入 node fingerprint，因此初版 alias change 会选择 re-analysis；若未来需要 alias-only fast path，必须单独升级 shared fingerprint contract。无论是否选择分析，都必须重建 companion；
- zero-symbol 且没有 snapshot 的 tag 不生成孤立 metadata；删除 tag 时 snapshot 与 metadata 必须同时删除；
- 当前`cstrike-10210`与`cstrike-8684`是合法的config-only zero-symbol tags：有config、无snapshot/metadata不构成缺失或删除错误。严格enumerator必须从snapshot集合派生companion，不能要求每个config都存在snapshot；
- hosted deleted-tag validation同时检查config、snapshot、metadata与gamedata残留；hosted/self-hosted compare都验证snapshot/metadata pair，不能只比较snapshot；
- selective materialize 不把 metadata 当分析 YAML，它只参与 bound Git-tree verification。

### 4.5 Pages 集成

修改 `pages/gameSymbolsPlugin.ts` 与 `pages/vite.config.ts`：

- plugin 只接收 `gamesymbols` directory，不再接收 `configs` directory；
- 对每个 snapshot 派生 `<tag>.metadata.yaml`；
- metadata 缺失、schema 错误、snapshot hash 不匹配或 alias owner 非法时，production build/verify hard fail；
- dev server 可以给出明确错误，但不得回退读取 live config；
- cache identity 同时包含 snapshot 与 companion 的 mtime/size；最终资产完整性仍由编码后 JSON SHA-256 决定；
- watcher 加入 companion；移除 config watcher；
- Pages workflow 不再因一般 `configs/**` 变化直接触发部署，只有 snapshot/metadata/pages/workflow 变化才部署；
- append-only archive 继续保存最终合并 alias 后的 content-addressed JSON，不单独发布 companion URL。

### 4.6 历史迁移

- 新 release 必须有 companion，不能缺失降级；
- 当前 10 个 tracked snapshot（`cof-5936`、`hl-10210`、`hl-3248`、`hl-3266`、`hl-3329`、`hl-3647`、`hl-4554`、`hl-6153`、`hl-8684`、`svencoop-10257`）均为 schema 6/config digest v2，且当前对应 config digest 与 snapshot `config_sha256` 匹配；PR 2 必须一次性回填，不为当前集合启用 legacy 缺失降级；
- 对未来导入且无法取得匹配 config revision 的历史 snapshot，只能通过 immutable tracked legacy allowlist 明确绑定 exact tag + snapshot SHA-256，并规定“无 companion、绝不附加 alias”；不得使用工作树 live config；
- 不允许用当前无关 config 给历史 snapshot 生成形式正确但语义错误的 alias；
- `.gitignore` 当前同时忽略`gamesymbols/*.yaml`与`gamedata/*/`。PR 2为metadata增加`!gamesymbols/*.metadata.yaml` tracked exception并测试普通`git add`可见companion；PR 3保留gamedata ignore，通过第7.2节的candidate-manifest驱动、严格path-limited `git add -f -- <exact-path>` tracked化。两条策略有意不同；
- Python reader 支持 schema 1-6 不代表 Pages raw parser 也支持同样范围；Pages compatibility policy 以其显式支持的 snapshot schema 为准。

### 4.7 测试与验收

至少覆盖：

- projection 只包含三类声明字段与解析后的 artifact owner identities；
- alias string/list、空值、重复项、非法类型与未知 owner；
- canonical bytes、单文件 atomic replace 与双文件 journal 中断恢复；
- snapshot/config/tag/hash 不匹配 fail-closed；
- metadata 文件不会被 snapshot enumerator 识别；
- `cstrike-10210`/`cstrike-8684`等config-only zero-symbol tags不会被要求生成snapshot/metadata，也不会被误判为deleted tag；
- planner add/modify/delete/rename 与 plan digest binding；
- Pages 不再读取 config，metadata 篡改改变或阻断最终 asset；
- Pages archive/verification 同时验证新旧版本 policy；
- production build 对当前 tracked snapshot 缺 companion 时失败；未来 legacy 仅可由 exact snapshot hash allowlist 放行且不得附加 alias；
- 所有 `gamesymbols/*.yaml` 消费者使用严格 tag parser；repository contract test 不得把 `.metadata.yaml` 当 snapshot。

验收标准：

- 修改 live config 但不更新 snapshot/companion，不会改变已发布历史 asset；
- 新 snapshot 无匹配 companion 时不能通过 PR/release gate；
- companion bytes 被 tracked content inventory 与后续 release manifest 绑定。

## 5. 工作包 B：稳定的 `pr-validate` 终态门禁

### 5.1 目标

在 `.github/workflows/gamesymbol-pr-validation.yml` 增加固定 job ID 与显示名：

```yaml
pr-validate:
  name: pr-validate
```

branch protection 只依赖该名字，不依赖 `plan`、`validate-hosted`、`analyze-self-hosted` 等内部拓扑。未来拆分 warmup、metadata 或 release validation job 时，required check 名不变化。

### 5.2 汇总规则

source `pr-validate` 使用等价于 `always() && github.event.action != 'closed' && route == 'source'` 的条件，`needs` 至少包含：

- `plan`；
- `validate-hosted`；
- `analyze-self-hosted`；
- `fork-analysis-blocked`。

终态逻辑必须读取 `needs.<job>.result` 与 planner outputs，而不是仅依赖 GitHub 默认的 skipped propagation：

| Plan 结果 | 路由 | 必须满足 |
| --- | --- | --- |
| failure/cancelled/skipped | 任意 | 失败；`closed` 时 aggregator 根本不创建 |
| success | no actions | `plan=success`，其他 validation jobs 应为 skipped |
| success | hosted only | `validate-hosted=success` |
| success | analysis, same repo | `analyze-self-hosted=success` |
| success | hosted + analysis | 两个执行 job 都 success |
| success | analysis, fork | `analyze-self-hosted=skipped`、`fork-analysis-blocked=failure`，明确失败并输出 trusted-runner 边界原因；若同时有 hosted action，则 hosted job 仍必须 success |

任何被要求执行的 job 出现 `skipped`、`cancelled` 或 `failure` 都使终态失败；任何不应执行的 job 意外成功也应被 workflow contract 测试发现，防止路由条件漂移。

`closed` 事件不运行 `pr-validate`，不能只依赖 upstream jobs skipped 后的 propagation。source PR 与未来 generated-output PR 必须通过同一个严格 classifier contract 产生 `route=source|output`：

- classifier 只根据 event metadata 与严格的 `gamesymbols/build/<tag>/<build-id>` parser 做路由，不授予信任；
- source workflow 的 plan、执行 jobs、fork blocker 与 aggregator 全部要求 `route=source`；
- output workflow 的 verifier 与 aggregator 全部要求 `route=output`；output-like 但 repository/author/bot identity 不可信的 PR 进入 output verifier 并明确失败，不能回落到 source self-hosted path；
- 每个非 closed PR 恰有一个名为 `pr-validate` 的终态 check；0 个或 2 个都视为 contract failure。

PR 1先落地shared classifier contract和source aggregator，但在output workflow尚未存在时不得提前启用`route=output`。PR 7必须在同一变更中加入output workflow并原子切换source/output predicates；部署顺序或feature flag不得产生一个没有`pr-validate`的窗口。

### 5.3 Trust boundary

- source PR 在默认 merge checkout 中原地执行 semantic planner；不得引入 CS2 的 path glob router；
- aggregator 不重新计算 impact，只验证 bound plan 已选择的执行结果；
- fork PR 不因 aggregator 存在而获得 self-hosted 权限；
- branch protection切换前必须真实演练fork hosted-only和fork hosted+analysis。若`bin` submodule不能由fork事件的`github.token`读取，明确把该路由标为unsupported并fail-closed；不得向fork注入PAT/App token或self-hosted secrets；
- workflow permission 保持 `contents: read`；
- `win64` Environment approval 与 secrets boundary 保持在 self-hosted job，不上移到 aggregator；
- branch protection 切换到 `pr-validate` 前，先观察 no-op、hosted-only、same-repo analysis、hosted+analysis、fork-analysis 和 output PR；保存 check App identity 与结果，并移除旧动态 required checks。

### 5.4 测试与验收

扩展 workflow contract tests，使用 YAML parser 机械解析 job DAG 与关键 expressions，并把 aggregator truth table 抽成可单测的 helper/明确映射。测试约束 job ID、`needs`、closed exclusion、shared classifier、结果语义和 source/output 互斥，不约束 YAML 排版或 step 文案。

验收标准：

- no-op PR 仍产生成功的 `pr-validate`；
- hosted/self-hosted 混合计划不会因其中一个 job skipped 而误通过；
- fork analysis 明确失败；
- 内部 job 重命名或新增时，只需更新 aggregator，不需修改 branch protection；
- 每个非 closed source/output PR都恰有一个稳定终态 check。

## 6. 工作包 C：可验证的 warm IDB cache

### 6.1 正确性边界

warm cache 是昂贵但可重建的性能层，不是分析或发布真相来源。orchestrator 在启动 analysis 前把 `cache_mode=warm|cold` 绑定进 plan/selection：warm mode 的 exact generation 缺失或损坏时当前 run 失败；cache disabled、probe miss 后无法 warm、或基础设施不可用时只能启动一个明确的 cold run，不得在已开始的 strict warm consumer 中静默 fallback。不得因 cache 不可用而从未知 persisted workspace 拷贝数据库。

缓存内容必须是“刚完成 IDA loader/auto-analysis、尚未执行项目 finder、Preprocessor、Agent rename/comment/patch 的中性 baseline”。selected-node analysis 对 restored database 的修改只存在于当前 run，cleanup 时删除，不回写 immutable generation。

### 6.2 Identity 与目录模型

新增 `idb_cache.py`，cache identity schema 1 至少包含：

```json
{
  "schema_version": 1,
  "tag": "hl-10210",
  "ida_runtime": {
    "kernel_version": "9.0",
    "processor": "metapc",
    "bitness": 32,
    "file_type": "PE",
    "loader_name": "pe",
    "loader_module_sha256": "...",
    "plugins": []
  },
  "warmup_contract_version": 1,
  "warm_worker_sha256": "...",
  "normalized_ida_args": [],
  "binaries": [
    {
      "module": "engine",
      "platform": "windows",
      "path": "engine/hw.dll",
      "size": 1,
      "sha256": "..."
    }
  ]
}
```

cache key 是上述 canonical JSON 的 SHA-256。为避免“只有 warm 后才知道 key”的循环，`probe-runtime` 必须先从 pinned runner installation、binary format与规范化参数生成 expected runtime contract；若某字段只能在实际打开 binary 后取得，probe使用同一受限worker的neutral identity-only模式。warm process随后记录 observed runtime identity，publication要求 expected/observed逐字段一致。identity覆盖IDA kernel、processor/bitness、实际file type/loader、loader module digest、allowlist plugin identities、warm worker digest与规范化`ida_args`；安装文档中的IDA版本不能代替runtime record。skill config、description、重试次数等不会改变中性database的字段不进入key。

路径：

```text
<PERSISTED_WORKSPACE>/idb-cache/<tag>/
  generations/<cache-key>-<run-id>-<attempt>/
    manifest.json
    payload/binaries/<module>/<relative-binary-path>
    payload/databases/<module>/<relative-database-path>
  READY.json
```

`READY.json` 只是 cache probe 的便利指针。在途 consumer 必须使用 producer 返回的 exact `generation + cache_key + manifest_sha256`，不能在稍后重新读取 READY 决定消费对象。

GoldSrc 代码同时识别 `.i64` 和 `.idb` primary database，但当前 path/side-file helper 仍是 `ida_analyze_bin.py` 私有实现。PR 5 必须先抽取受测试的 `ida_database_paths.py`，并由 generation manifest 使用 `database_files: [{relative_path, size, sha256, role}]` 记录完整允许文件集；不得把 database 建模成单一 suffix，active lock 文件不得发布。

### 6.3 Publication 与 restore

提供以下命令/函数：

```text
probe
warm
publish
restore
prune
verify
```

- `probe` 从 config 声明的 exact binary pairs 计算 identity，只接受 inventory 完整且 manifest canonical 的 generation；
- `warm` 在 workspace 已验证 binary 上运行新的受限 warm worker：只打开输入、显式等待 auto-analysis、采集 runtime identity、保存并关闭，不加载 finder/Preprocessor/Agent。若实现复用 `idalib-mcp`，就必须占用同机全局 MCP-port lock，不能同时宣称“不占共享端口”；初版固定并发 1；
- warm 前强制删除该 binary 的所有 IDA side files与锁；失败、超时或残留锁时删除本次不完整 database；
- `publish` 复制 exact binary + 全部允许的 `database_files` 到 UUID `.incoming-*`，写全量 path/size/SHA-256 inventory，复核后用同文件系统 `os.replace` 发布 immutable generation，最后原子更新 READY；
- generation 已存在时只能逐字节相同并幂等成功，不能覆盖；
- `restore` 先验证 schema、cache key、manifest hash、IDA version、binary/database inventory 与 reparse-point 边界，再以临时文件 + `os.replace` 复制；
- restore 后重新计算 workspace binary identity；`IdaMcpLifecycle` 新增 strict restored policy（例如 `database_policy=restored_strict`、`save_on_success=false`），打开时再次验证 database identity，任何不符直接失败，禁止 stale-IDB invalidate/cold rebuild，selected-node 修改也不保存回 generation；
- CI consumer 使用 strict mode：要求的 generation 缺失或损坏时，当前 analysis job 失败，不在 consumer phase静默生成另一个未绑定 generation；重新 warm 只能由同一组合 job的producer phase或新的run负责；
- 本地 CLI 也必须显式选择 `cache_mode=warm|cold`；cold mode记录未读取 persisted root，不提供“先尝试strict restore、失败后原地fallback”的隐式选项。

### 6.4 Workflow 集成

初版把 probe/warm/restore/analyze 合并在同一个受保护的 self-hosted job 中，避免 GitHub 把 producer 与 consumer 调度到不同 runner 而看不到本机 persisted root。可以复用 workflow steps/CLI，但不能把依赖本机 generation 的 producer 与 consumer 拆成两个普通 `[self-hosted, Windows, X64]` jobs。流程：

1. checkout exact source/merge SHA 与 exact `bin` gitlink；
2. 下载并复核 bound plan artifact与已绑定的`cache_mode`；
3. warm mode只为`analysis_nodes`涉及的`(tag,module,platform)` pairs执行runtime/cache probe；cache miss时bounded warmup并发布/选择exact generations；
4. warm mode在同一job写canonical `cache-selection.json`与SHA-256并复核；可上传为证据，但Actions artifact不是cache transport/truth；
5. warm mode从selection指定的exact local/shared generation restore，以strict warm-IDB mode执行selected-node analysis；
6. cold mode不读取`PERSISTED_WORKSPACE`，执行validated clean后直接走normal loader/auto-analysis与selected-node analysis；
7. finally清除当前workspace restored/modified databases，但不删除immutable cache generation。

当前 workflow 的 clean 顺序必须调整为：

```text
validated bin-submodule clean
  -> exact cache restore
  -> analysis
  -> validated bin-submodule clean
```

禁止在 restore 后、analysis 前再次执行 `git clean -ffdx`。

该组合 job 运行在唯一专用 runner label（在通用 labels 之外增加仓库配置的专用 label）和受保护的 `win64` Environment。只有在所有 runner 共享同一具备原子 rename 语义的受控存储时，未来才允许拆分 producer/consumer。`PERSISTED_WORKSPACE` 只在这些 jobs 中注入，且 canonical-resolve 后必须位于 `GITHUB_WORKSPACE/bin` 与整个 checkout 之外并拒绝 reparse-point escape；hosted planner 不读取该 secret。

### 6.5 并发、retention 与恢复

- bound plan 当前把多 tag 顺序放在一个 self-hosted job；初版沿用该结构，以 per-tag persisted lock 保护 generation，同时以仓库级 self-hosted IDA concurrency group和runner本地file lock双重保护固定MCP port。只有 planner 输出并绑定 canonical tag/pair matrix 后才允许改成按 tag GitHub matrix concurrency；
- generation immutable，因此 consumer 之间允许并发读取；
- `.incoming-*` 超过 24 小时可清理；
- 每个 tag 保留 READY generation 与最新 3 个 generation，其余至少等待 7 天再删，给在途 consumer 留窗口；
- 自动 prune 只处理当前被 warm 的 tag，不跨 tag 扫描删除；
- runner 运维需有单独的 retired-tag 清理流程；
- cache hit/miss、generation、key、warm wall time、restore wall time写入日志，但不得记录 secrets 或本地敏感绝对路径；
- 中断 publication 不更新 READY；损坏 READY 可由 generation probe 重建；损坏 generation 永不原地修复，只发布新 generation。

### 6.6 测试与验收

采用 Level 2/TDD，至少覆盖：

- key 对 binary bytes、path、module/platform、IDA/loader/args/contract version敏感；
- 不相关 config/description 变化不改 key；
- PE32/ELF32 与 `.i64`/`.idb` database path；
- missing/locked database、tampered manifest、binary 或 IDB 被拒绝；
- incoming publication、atomic generation、READY 写入顺序与幂等；
- exact-generation restore 不受后续 READY 改变影响；
- symlink/reparse point/path escape/case collision；
- worker failure、timeout、内存限制与 side-file cleanup；
- retention 不删除 READY、最新 generation 或最小年龄内 generation；
- workflow 只 warm selected binary pairs，且 restore 后不被 pre-analysis clean 删除；
- consumer strict mode 不 inline fallback；
- strict lifecycle identity mismatch 不 invalidate/rebuild restored DB，normal exit 不保存 selected-node 修改；
- producer/consumer 在同一 runner/storage authority，通用 label 多 runner 场景不能误消费另一台机器的 READY；
- 显式 cold run 不读取 persisted root，并能在 warm cache 未部署时完成同一 selected-node validation。

验收标准：

- 同一 binary identity 的第二次 PR run 明确 cache hit，不执行 warm worker；
- binary、IDA 或 loader identity 任一变化都会生成不同 key；
- cache 篡改不能进入 `IdaMcpLifecycle`；
- cache 功能关闭或无法满足 warm selection 时，由 orchestrator 启动并绑定显式 cold run；只影响性能/调度，不改变 candidate、gamedata 与 release hash contract。

## 7. 工作包 D：Release provenance 与 promotion 状态机

### 7.1 分阶段目标

Release 迁移分为一个 bootstrap 和三个阶段，禁止一次性切换：

0. **Canonical-output bootstrap**：source PR 继续拥有 canonical publication authority，并把 snapshot、matching metadata 与 gamedata 全部作为 reviewed/tracked outputs；当前 main 只有 snapshot，因此 bootstrap 是 shadow 的硬前置；
1. **Shadow provenance**：从 exact main Git tree 读取已经跟踪的 snapshot/metadata/gamedata，生成并验证 content manifest，但不修改 Git refs、contents、PR、tag 或 Release；
2. **Generated-output PR + promotion**：source PR 仍拥有 snapshot/metadata/gamedata authority。release workflow 是唯一有权写 release output branch/tag/GitHub Release 的自动化（现有 Pages publication 是独立状态域），generated-output PR 通常只新增 immutable release content manifest；它不得改变或重新生成 source SHA 上的 canonical payload bytes。output PR merge 是 tag/Release promotion gate；
3. **可选 release-only authority**：source PR 不再直接提交 canonical outputs，改为 validation staging + merge promotion + generated-output PR。该阶段才把 snapshot/metadata/gamedata authority 转移给 release workflow，需单独设计与批准。

Phase 2 的 re-analysis 只能作为只读复核；结果必须与 source SHA tracked bytes byte-identical，否则 fail-closed。任何允许 release workflow 产生不同 canonical bytes 的设计都属于 Phase 3，不能提前混入 Phase 2。

Shadow evidence 至少覆盖三个不同 GoldSrc tag，并至少覆盖一次 `new` mode decision。当前仓库没有既存 immutable tag/Release，真实 `republish` shadow 不能在 production 仓库凭空构造；必须在 protected test repository 演练，或等首个 production `new` release 完成后补齐。在 republish 证据完成前，production republish 保持 disabled。每条证据记录 workflow run URL、workflow SHA、source SHA、bin gitlink、manifest/inventory SHA、mode decision 与同输入重复运行结果。

### 7.2 Tracked output 与 manifest

Phase 2 的 tracked payload outputs（由 source PR 发布）与 release manifest（由 generated-output PR 发布）为：

```text
gamesymbols/<tag>.yaml
gamesymbols/<tag>.metadata.yaml
gamedata/<tag>/**
release-manifests/<tag>.json
```

Canonical-output bootstrap 对 `gamedata/<tag>/**` 使用受测试、严格 path-limited 的强制 stage（例如从 candidate manifest逐项执行 `git add -f -- <exact-path>`），随后从临时 index/tree重新计算 allowlist和inventory；禁止用工作目录 glob把 ignored/untracked 文件混入提交。metadata 使用第 4.6 节的 tracked exception。Phase 2 output commit不再重新stage这些payload。

`tracked_content_inventory_sha256` 只覆盖前三类 payload 的 exact Git-tree blobs，明确排除 `release-manifests/<tag>.json`；否则 manifest 会参与自己的 hash，形成不可求解的自引用。release manifest 通过 output commit/head SHA、private manifest SHA、merge SHA 与 completion record 另行绑定。

release content manifest schema 1 只保存稳定 content identity，至少绑定：

```text
schema_version
game_version
release_tag
repository_id
source_sha
bin_gitlink_sha
candidate_sha256
snapshot_schema_version
analysis_output_contract_version
metadata_sha256
tracked_content_inventory_sha256
snapshot_binary_inventory_sha256
analysis_config_path
analysis_config_sha256
config_digest_version
config_contract_sha256
gamedata_path
gamedata_manifest_sha256
generator_contract_sha256
workflow_repository
workflow_path
workflow_ref_sha
release_tool_contract_sha256
```

设计约束：

- `source_sha` 是 exact default-branch commit，不接受用户随意提供的 branch/head；它已经包含 source-PR-owned snapshot、metadata 与 gamedata；
- `bin_gitlink_sha` 来自主仓库 `source_sha` 的 Git tree，并与 checkout 后 submodule HEAD 一致；
- `candidate_sha256` 绑定 exact canonical snapshot bytes；
- `metadata_sha256` 绑定 companion，且 companion 自身绑定 candidate/config；
- tracked content inventory 从 `source_sha` Git tree/blob bytes 构建，不从可能有未跟踪文件的工作目录 glob；entry 固定包含 path、Git mode、size、blob-bytes SHA-256，按 UTF-8 path bytes 排序，只允许当前 tag 的 snapshot、metadata 与 gamedata；
- content inventory 明确排除 release manifest；output commit 只增加 manifest 时，必须重新证明前三类 payload 与 `source_sha` byte-identical；
- 所有 SHA-256 字段编码为 lowercase raw 64 hex；读取现有 `sha256:<hex>` contract 时先验证算法前缀再规范化。Git object identity 使用显式 `*_git_oid`/`*_sha` 字段，不与内容 SHA-256 混用；
- `build_id`、run ID/attempt/URL、PR number/head、merge SHA、tag target、Release ID 与 promotion markers 是 attempt/promotion identity，放在 private stage、public provenance asset 或 completion record，不写入 tracked content manifest；
- `workflow_ref_sha`/tool contract 绑定实际执行的 trusted workflow/verifier bytes，不能只记录可变 URL；
- provenance证明的是exact inputs与最终tracked bytes，不承诺LLM/IDA re-analysis可重复。Phase 2只读re-analysis必须保留tracked `last_publish_time`且byte-identical；若实际执行，attempt/provenance另记IDA、agent/model/provider/tool versions，任何delta都拒绝；
- manifest canonical JSON，schema version表示 verifier/inventory 规则变化，不只是字段集合变化；
- 新 writer 只写最新 schema，reader 对历史 schema 使用显式 verifier；
- 未来增加 gamedata per-entry metadata 时必须升级 verification rule，不能无版本地改变 expected inventory。

### 7.3 Identity、authority 与 event matrix

实现前先固定三类 identity，不允许在一个 manifest 中混用：

| Identity | 稳定内容 | Truth source |
| --- | --- | --- |
| content identity | source SHA、bin gitlink、config contract、snapshot、metadata、gamedata、generator、workflow/tool contract | exact Git tree/blob + canonical content manifest |
| attempt identity | build ID、run ID/attempt/URL、output branch、PR number/head、PAT actor/association | private stage + GitHub API |
| promotion identity | merge SHA、immutable tag object/target、Release ID、downloaded asset hashes、completion state | GitHub API + durable completion record |

Phase 2 authority 固定为：source PR 作者/reviewer 负责前三类 canonical payload bytes；release workflow 独占 release output branch/tag/GitHub Release 写权限，只负责生成 content manifest、创建 output PR、tag、Release 与 provenance/completion。现有 local candidate/session 只能作为生成期 guard，release verifier 只信任 exact Git blobs。

Event/trust contract 固定为：

- build 仅从受保护的 default-branch workflow 以 exact `origin/main` SHA启动；
- production output branch/PR 统一使用受保护 `win64` Environment 中的静态 PAT secret `HLND2T_GH_TOKEN` 创建。release build 的默认 `GITHUB_TOKEN` 保持 `actions: read`、`contents: read`、`pull-requests: read`；PAT 只用于 exact checkout、Git authentication、output branch push 与 PR create。默认 `GITHUB_TOKEN` 创建的 PR/push 通常不会再次触发 `pull_request` workflow，不能作为 required-check 事件链；
- output PR validation 使用普通 `pull_request`、`contents: read`，从 event base/source SHA 读取 trusted verifier，绝不执行 output head 修改的代码；
- promotion 使用普通 `pull_request` 的 `closed && merged` 事件；只接受同仓 `gamesymbols/build/` 分支和 `github-actions[bot]` 或 `OWNER`/`MEMBER`/`COLLABORATOR` author association，并继续复核 exact PR/head/merge/content identities。promotion workflow 的 `${{ github.token }}` 单独取得 `contents: write`、`pull-requests: read`，用于 immutable tag 与 GitHub Release；PAT 不进入 promotion；
- production 初版要求 output PR 使用 merge-commit-only：head 的唯一父提交是 `source_sha`，merge commit 两个父分别是验证过的 pre-merge base 与 exact output head。pre-merge base 必须是 `source_sha` 的后代，但不要求等于 `source_sha`。若将来允许 squash/rebase/merge queue，必须先升级 schema/verifier 和演练证据；
- 不得把 default branch merge 进 immutable output head，也不要求 GitHub “up-to-date with the base branch”。只要当前 PR base 是 manifest `source_sha` 的后代，且 GitHub mergeability 无冲突，就允许 default-branch advancement。lightweight verifier 与 merge-time `verify_promotion()` 都用 ancestor + exact source parent 绑定 output identity；changed-path allowlist 只审计 `source_sha..head`。Git 冲突仍由 GitHub mergeability/branch policy 阻止合并。只有当 base 与 `source_sha` 无祖先关系、output head 不再直接基于 `source_sha`，或 allowlist/hash/trust 失败时，才需要 replacement build/PR。

### 7.4 Release build 与 private staging

新增`release_workflow.py`，并扩展现有`release_workflow_lib/`。现有`hashing.py`、`errors.py`与`__init__.py`已经提供candidate事务复用的local-only canonical hashing/inventory骨架，必须在其上扩展，不能另建重复实现。职责分离为：

- 复用并按release contract扩展canonical hashing/inventory；
- manifest build/validate；
- staging/index；
- Git identity verification；
- promotion；
- Release asset verification；
- completion/cleanup。

`new` build workflow 固定从 immutable `origin/main` SHA执行；`republish` 不创建新的 tracked manifest/output PR，走 7.9 的独立操作：

1. 解析 exact tag，确认不存在同 tag manifest、immutable tag、Release 或 active build；
2. checkout `source_sha`、full history 和 exact `bin` submodule；
3. 从 `source_sha` Git tree 验证 config、snapshot、metadata、gamedata 与 content inventory；
4. 若执行 re-analysis，只能走已绑定的 explicit warm/cold mode并做 byte-identical 复核，不得产生 output delta；
5. 生成 canonical content manifest，输出 commit 直接以 `source_sha` 为唯一父提交且只增加 `release-manifests/<tag>.json`；
6. 原子写 `BUILDING.json`，绑定 content/attempt identity 与预定 branch；
7. 创建 output commit 后写 `HEAD_BOUND.json`，再 push immutable branch；
8. 使用受保护 `HLND2T_GH_TOKEN` PAT 创建 draft PR；
9. 原子写 `PR_CREATED.json` 与 `pr-index/<pr-number>.json`，复核远程 repository/branch/head/base/PR；
10. 最后写 `READY.json`；只有 READY 才表示 stage、branch、draft PR 与 index 全部存在且互相匹配；
11. READY 复核成功后才把 PR 标为 ready for review。

GoldSrc private stage 不复制 accepted binary tree。建议内容：

```text
<PERSISTED_WORKSPACE>/release-staging/<tag>/<build-id>/
  content-manifest.json
  BUILDING.json
  HEAD_BOUND.json
  PR_CREATED.json
  READY.json
  PROMOTION_STARTED.json
  PROMOTED.json
  PROMOTION_COMPLETE.json
  FAILED.json | CANCELLED.json | PR_CLOSED.json

<PERSISTED_WORKSPACE>/release-staging/pr-index/<pr-number>.json
<PERSISTED_WORKSPACE>/release-staging/completed/<tag>/<build-id>.json
<PERSISTED_WORKSPACE>/release-staging/locks/<tag>.lock
```

所有 state JSON 使用版本化 schema，绑定 tag、build ID、content-manifest SHA-256、前一 state hash、run identity 与 lease/owner，并只允许 `BUILDING -> HEAD_BOUND -> PR_CREATED -> READY -> PROMOTION_STARTED -> PROMOTED -> PROMOTION_COMPLETE`。`FAILED/CANCELLED/PR_CLOSED`作为append-only诊断记录，必须指向最后一个成功边界，不删除或伪造其状态；retry创建新build，resume-promotion从同一build最后成功边界继续。必要的output bytes已在generated-output commit；binary可由`source_sha + bin_gitlink_sha`精确重建。stage只保存private identity、状态标记和不能安全放进tracked manifest的PR binding，不保存IDB、MCP/BinSync状态或另一份accepted-bin。

### 7.5 Generated-output PR

branch 采用：

```text
gamesymbols/build/<tag>/<build-id>
```

Phase 2 每个 output commit 必须直接以 release `source_sha` 为唯一父提交，只允许新增当前 tag 的 `release-manifests/<tag>.json`。snapshot、metadata、gamedata 相对 `source_sha` 必须无 delta；改变这些 payload 的 PR 属于 Phase 3，Phase 2 verifier 必须拒绝。创建 PR 前必须：

- 检查无其他同 tag READY build/output PR；
- 使用临时 index/commit tree并检查没有 allowlist 外变化；不得从被 `.gitignore` 隐藏的未跟踪工作树 glob 构建 inventory；
- staged/private manifest 逐字段一致；
- source SHA 上的 candidate、metadata、gamedata 与 tracked content inventory hashes 一致；release manifest 不参与自身 inventory；
- output commit 后记录 exact head SHA；
- output PR 使用独立 validation workflow，但终态 job 同样命名 `pr-validate`；
- output validation 工具从 PR event base/source SHA 读取，不能使用 output branch 自己修改的 verifier；
- PAT actor association、head repository、branch parser、direct-parent、changed-path allowlist 和 shared classifier全部通过后才能把 draft PR转为 ready。

自动 release 失败后不无限重试。保留失败 stage与诊断；尚未写 `PROMOTION_STARTED.json` 时允许显式 retry，promotion 已开始则只能 resume 同一 build。`republish` 不是 build retry。同 tag 已有 READY build/output PR 时，新 run fail-closed。

### 7.6 Merge-time promotion

promotion workflow只接受可信 merged output PR，至少验证：

- event repository、PR head repository、受信任 PAT actor association/Actions bot、base branch与严格 branch parser全部命中 allowlist；
- PR number/head SHA与 `PR_CREATED.json`、READY、private PR index一致；
- output head 的唯一父提交等于 pending `source_sha`，changed paths 从 `source_sha..head` 计算并必须通过 allowlist；
- merge commit/API identity符合已经配置并演练的 merge-commit-only contract，其两个父提交分别等于 pre-merge base与 exact output head；
- pre-merge base 必须是 `source_sha` 的后代，不要求等于 `source_sha`；default-branch advancement 本身不是 stale，不能仅因 main 前进就按 7.3 强制 replacement build/PR；
- tracked content manifest、private manifest、source payload inventory、merge tree、snapshot、companion、gamedata与 bin gitlink全部一致，且 manifest未参与自己的 inventory；
- 仓库不存在目标 tag/Release；Phase 2 output promotion只处理 `new`，republish走已完成 release上的独立操作。

验证成功后按顺序：

```text
verify
  -> write PROMOTION_STARTED
  -> reconstruct exact workspace from source SHA + bin gitlink + merged outputs
  -> create deterministic payload assets
  -> create/verify immutable tag
  -> write release provenance（列出 payload assets，不自引用）
  -> write release checksum（覆盖 payload + provenance，排除 checksum 自身）
  -> create Release and upload all assets
  -> download all assets and verify size/SHA-256
  -> write PROMOTED.json（tag object/target、Release ID、downloaded asset hashes）
  -> write durable completion record
  -> write PROMOTION_COMPLETE
  -> cleanup through recoverable trash rename
```

发布完成的判断以 durable completion record、immutable Git tag object/target、GitHub Release ID 与下载回来的全部 asset hashes共同成立为准。仅创建 GitHub Release、仅上传资产或仅写 PROMOTED marker都不算完成。`PROMOTION_STARTED` 之后中断必须以同一 tag/build/PR/head/merge identity执行 `resume-promotion`，不得换 build ID绕过已创建的 tag或部分资产。

### 7.7 Release assets

初版建议发布：

```text
gamesymbols-<tag>.yaml
gamesymbols-<tag>.metadata.yaml
gamedata-<tag>.zip
release-provenance-<tag>.json
release-assets-<tag>.sha256
```

是否发布 game binaries 必须单独确认许可证与分发策略；本文不默认把 `bin` submodule 内容上传 GitHub Release。即使不发布 binary asset，provenance 仍必须记录 `bin_gitlink_sha` 和 snapshot binary hashes。

archive 从已合并的 `gamedata/<tag>/` 构建，不在 promotion 阶段访问 live upstream 或重新运行 generator。archive entry order、timestamp、path separator与压缩参数必须固定，保证同输入可复现。

`release-provenance-<tag>.json` 绑定 content manifest SHA、source/output/merge SHA、workflow repository/path/ref SHA、run ID/attempt、PR number/head、tag object/target、Release ID与 payload asset hashes。`release-assets-<tag>.sha256` 覆盖 snapshot、metadata、gamedata archive 与 provenance，明确排除 checksum 文件自身。

Pages deploy/archive 是 main push 后的独立 publication domain，Phase 2 release completion 不等待也不绑定 Pages 状态，不得声称 GitHub Release 完成意味着 Pages 已同步。若未来要统一 completion，必须另行把 Pages build commit、最终 JSON verification manifest和 `pages-snapshots` branch protection纳入 schema/状态机；当前只保留独立的 append-only contract。

### 7.8 可选：Release-only publication authority

只有 generated-output PR/promotion 稳定后，才评估把 source PR 从“提交 expected snapshot”切换为“只提交 source/config，CI stage actual candidate”。目标模型：

```text
source PR validation
  -> actual candidate + gamedata guard
  -> durable PR analysis stage（仅 YAML/candidate，不含 binary/IDB）
  -> source PR merge
  -> finalizer验证 head/merge/plan/config/bin identities
  -> promote到 accepted-analysis workspace
  -> release workflow消费 accepted state
  -> generated-output PR发布 canonical snapshot/metadata/gamedata
```

切换前必须解决：

- source PR 不再有 tracked expected snapshot时，review 如何查看 candidate diff；
- nondeterministic Agent/LLM 输出如何审计；
- 多 tag PR stage必须来自同一成功 run，不能混合；
- source merge后的 config/bin/generator drift如何使旧 stage失效；
- accepted-analysis workspace只保存分析 YAML，不成为 binary truth；
- Actions artifact retention不能替代 durable stage；
- source PR、output PR与 branch protection如何避免重复/缺失 checks。

在这些条件未全部满足前，保留 author-provided snapshot/metadata/gamedata + strict compare 模式；Release 阶段 1/2仍可独立提供 provenance、tag和asset promotion，但不得改动 source SHA 上的 canonical payload bytes。

### 7.9 失败恢复与人工操作

必须提供显式、受保护的操作：

- retry：仅允许尚未写 `PROMOTION_STARTED.json` 的失败 build；复用相同 source/tag/content identity但使用新 build ID，旧失败 stage保持只读，旧 draft PR/branch必须先按记录关闭或标记 superseded；
- resume-promotion：`PROMOTION_STARTED.json` 已存在时，只能复用同一 build ID、PR head、merge SHA、tag target和content manifest，从已验证 marker 边界继续；
- republish：只针对已有 durable completion 的 release，以原 completion/content manifest 重建并逐字节验证缺失/损坏的原始 assets；不创建新 output PR、不修改 tracked manifest、不改变 immutable tag target。republish attempt identity只写新的受保护 operation/completion record；
- abandon：仅允许尚未出现 `PROMOTION_STARTED.json` 的 pending build，要求 exact tag/build ID、确认词与原因；无 PR index 的 orphan 必须先通过 GitHub API验证 branch/PR/head 后才能处理；
- repair-index：只修复 private stage/PR index，不修改 Git refs、PR head、tag或Release；要求 exact repository ID、branch、PR number/head/base与content manifest全部匹配；
- cleanup：只删除已有 durable completion record绑定的 stage；先原子 rename到 cleanup-trash，再可重试删除；
- reconcile：只读报告 Git tag、Release、stage、PR index与completion record差异，不自动修复。

所有远程写入 workflow使用受保护 Environment与最小 permissions。PR validation保持 `contents: read`；创建 output PR、tag或Release的 token不进入 source PR self-hosted analysis job。

### 7.10 测试与验收

采用 Level 2/TDD，至少覆盖：

- canonical content manifest、self-excluding Git-tree inventory、schema reader/writer与unknown/missing fields；
- content/attempt/promotion identity分离、path allowlist、tag/build/branch parser；
- source SHA、bin gitlink、config、candidate、metadata、gamedata、generator hashes任一篡改被拒绝；
- `BUILDING -> HEAD_BOUND -> PR_CREATED -> READY`顺序、draft PR、orphan branch/PR与repair-index；
- PAT 创建 PR 后确实触发 output validation；默认 `GITHUB_TOKEN` 事件抑制不能造成缺失 check；
- PR index/head/two-parent merge identity、pre-merge up-to-date gate、default-branch unrelated drift与relevant drift；
- duplicate pending build、new/retry/republish/resume-promotion规则；
- promotion interruption在每个marker边界可重入；
- provenance/checksum生成顺序、自引用排除、deterministic archive与上传后下载hash验证；
- completion record前不cleanup；cleanup中断可恢复；
- workflow permissions、Environment、job DAG、source/output PR互斥路由；
- stage与Release assets不包含IDA database、临时candidate/session、secrets或未声明文件；
- Phase 2 output commit只增加release manifest，source-PR-owned snapshot/metadata/gamedata在未cutover前保持不变。

阶段 1 验收：

- 至少三个不同 GoldSrc tag在shadow模式生成完全可复核manifest，并覆盖一次`new` mode decision；
- shadow workflow不修改Git refs、contents、PR、tag或Release；
- 相同source和tracked bytes重复运行得到相同inventory/hash；
- republish在protected test repository完成演练；production republish在此之前保持disabled。

阶段 2 验收：

- 只有generated-output PR merge才触发promotion；
- output PR只增加release manifest，不改变source SHA上的snapshot/metadata/gamedata；
- 未合并、失败、cancelled或被篡改的PR不会创建tag/Release；
- 发布asset下载后hash与provenance一致；
- durable completion存在后才允许cleanup；
- 不创建accepted-bin副本；
- production activation前，branch/ruleset、merge-commit-only、protected tags、Environment/PAT identity与required check均有captured evidence。

## 8. 建议 PR 拆分

| PR | 范围 | 主要文件 | 质量门禁 |
| --- | --- | --- | --- |
| PR 1 | 稳定 `pr-validate` | gamesymbol PR workflow、workflow contract tests、CI docs | Level 1 + workflow routing matrix |
| PR 2 | alias metadata core/Pages/PR binding | `gamesymbol_metadata.py`、planner/CLI、Pages plugin、metadata tests/docs | Level 2 + Python/Pages/full suites |
| PR 3 | canonical gamedata bootstrap | source PR compare/publish contract、tracked gamedata、planner/workflow/tests | Level 2 + full suites，建立shadow输入前提 |
| PR 4 | release content manifest + shadow verifier | 复用现有`release_workflow_lib/hashing.py`与`errors.py`骨架并扩展、CLI、self-excluding inventory tests、shadow workflow | Level 2，无remote write |
| PR 5 | IDB cache core | `ida_database_paths.py`、`idb_cache.py`、restricted warm worker、strict lifecycle | Level 2，纯本地/临时目录，不先改 workflow |
| PR 6 | warm/cold self-hosted integration | combined runner job、selection、workflow tests、operations docs | Level 2 + cold/miss/hit真实证据 |
| PR 7 | generated-output PR + promotion | build/output-validation/promotion/recovery workflows、PAT、docs | Level 2 + protected test repository演练 |
| PR 8 | 可选 release-only authority cutover | PR staging/finalizer、accepted-analysis state、review UX | 独立设计评审，不随PR 7自动实施 |

PR 4必须等待PR 2与PR 3完成。PR 5/6是独立性能工作，可与PR 4并行；PR 7必须等待PR 1-4完成，但不硬依赖PR 5/6，因为它必须能绑定并验证显式 cold mode。没有可信warm generation时不得消费cache，也不得在strict warm consumer内inline fallback。

## 9. 验证策略

每个实现 PR 至少运行与改动直接相关的定向测试，并在完成前运行仓库质量门禁：

```text
uv run python format_repo_files.py --check
uv run python tests/run_test_suite.py unit -b --durations 30
uv run python tests/run_test_suite.py repository-contract -b --durations 30
uv run python tests/run_test_suite.py all -b --durations 30
```

涉及 Pages 时另外运行：

```text
cd pages
npm ci
npm test
npm run lint
npm run build
npm run verify:gamesymbols
npm run test:e2e
```

涉及 self-hosted IDA 或 Release 时，普通单测不能替代真实环境验证。必须记录：

- exact source SHA、bin gitlink、workflow repository/path/ref SHA与run ID/attempt/URL；
- explicit cold、cache miss publication与后续cache hit各一次；
- generated-output draft PR、未合并、合并、篡改、orphan/index恢复、retry与resume-promotion各一条演练证据；
- tag/Release asset上传后下载hash核验；
- cleanup/recovery marker状态；
- branch/ruleset、required-check App identity、merge policy、protected tag和Environment设置的captured-at证据。

无法执行真实环境门禁时，不得声明对应阶段完成或可切换production authority。

## 10. 文档与运行手册

实施时同步更新：

- `README.md`：只补最终用户可见的release/metadata入口；
- `docs/en/architecture.md` 与中文对应文档：更新数据流、cache与release boundary；
- `docs/en/ci-cd.md` 与中文对应文档：稳定check、warmup、output PR、promotion/cleanup；
- `docs/en/snapshot-and-gamedata.md`：companion、tracked output和release contract；
- `docs/en/requirements.md`：self-hosted persisted root、IDA identity和GitHub Environment；
- memory：分别沉淀 alias metadata、warm IDB、release staging/promotion与completion recovery；
- operator runbook：retry、resume-promotion、republish、abandon、repair-index、reconcile、retired cache/tag cleanup。

旧的 `gamesymbol-infrastructure-migration.md` 保留为已实施历史，不把其中当期非目标改写成“当时设计错误”；新文档和最终架构文档负责描述后续能力。

## 11. 最终验收标准

四项能力全部完成时必须满足：

- Pages 的历史 alias只由同版本snapshot companion决定，不读取live config；
- snapshot与companion在PR、Pages和release inventory中形成可验证的一对；
- gamesymbol source/output PR通过共享classifier互斥路由，每个非closed PR都恰有一个稳定的`pr-validate`终态；
- warm cache按binary/IDA/loader identity内容寻址，exact generation消费，篡改fail-closed；
- cache generation不包含项目finder/Agent产生的可变状态；
- warm cache未部署或不可用时有预先绑定、可验证的cold mode；strict warm consumer不inline fallback；
- release content manifest端到端绑定source SHA、bin gitlink、config、candidate、metadata、gamedata、generator与workflow identity，content inventory明确排除manifest自身；
- Phase 2 source PR拥有snapshot/metadata/gamedata authority，generated-output PR只增加release manifest；只有Phase 3可转移canonical output authority；
- generated-output PR merge是唯一promotion gate；output head 绑定 exact `source_sha`（单父且该父提交等于 source）；当前 PR/merge base 必须是该 source 的后代；output-only diff 不把 default-branch drift 算入 output PR；Git 冲突仍阻止合并，祖先关系或 identity 破坏时才需要 replacement build/PR；
- Git tag、Release assets和completion record的identity/hash一致；
- promotion中断后以同一identity安全resume，pre-promotion retry与republish语义互不混淆；cleanup中断可恢复；
- production activation由branch/ruleset、merge policy、protected tag、Environment和PAT identity共同门禁；仓库历史提交形状不能替代配置；
- Pages publication保持独立状态域，Release completion不虚假宣称Pages同步完成；
- 未引入CS2 accepted-bin、BinSync、单GAMEVER、path-glob router或C++ gate假设；
- 除非PR 8另行批准，author-provided snapshot/metadata/gamedata模式保持不变。
