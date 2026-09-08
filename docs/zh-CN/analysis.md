[返回 README](../../README_CN.md) | [English](../en/analysis.md)

# 二进制获取与符号分析

## 下载游戏 depots

先下载配置的 depot 版本，再把目标二进制复制到工作区：

```bash
uv run python download_depot.py -tag cstrike-10210 -depotdir depots
uv run python download_depot.py -all -depotdir depots

uv run python copy_depot_bin.py -gamever cstrike-10210 -platform all-platform
uv run python copy_depot_bin.py -gamever cstrike-10210 -platform windows -checkonly
```

- `download_depot.py -tag <tag>` 下载单个 release tag；`-all` 下载 download config 中声明的全部 tag。`-os`
  可选 `windows`、`linux`、`macos` 或 `all`（默认）。`download.yaml` 只控制下载，与控制批量分析的
  `configs/config.yaml` 相互独立。
- `configs/<tag>.yaml` 中的每个 `depot_<platform>` 都是相对于该 tag 在 `download.yaml` 中 `basepath`
  的安全路径；`module_<platform>` 独立声明 `bin/<gamever>/<module>/` 下的二进制文件名。
- `copy_depot_bin.py -platform` 接受 `windows`、`linux` 或 `all-platform`。`-checkonly` 只检查所有期望的目标
  二进制是否已存在于 `bin/<gamever>/...`：就绪返回 `0`，缺失返回 `1`，配置或参数错误返回 `2`。

使用 `/init-gamebin` 为 `download.yaml` 中的每个 tag 初始化 `depots/` 与 `bin/` 目录树。

### Blob 游戏二进制

部分旧 GoldSrc 版本携带非 PE 的 Metahook "blob" 二进制。分析前请使用 `/decrypt-blob-gamebin` 斜杠命令（或
`decrypt_blob.py`）把 `bin/` 下的每个非 PE blob 转换成普通 PE32 DLL。有效的 PE/ELF 二进制、IDA 数据库与
YAML 工件会被跳过。

## 分析配置的符号

Analyzer 会为 `configs/<GAMEVER>.yaml` 中声明的符号查找并生成 signature。

命令概要：

```bash
uv run python ida_analyze_bin.py -gamever cstrike-10210 -configyaml configs/cstrike-10210.yaml -platform windows,linux
uv run python ida_analyze_bin.py -gamever <GAMEVER> -modules <MODULE> -skill <EXACT_SKILL_NAME> -platform windows,linux -debug
```

必须显式指定 `-gamever`、`-allgamever` 或 `-batch_selection`；analyzer 不再回退到 `GSVIBE_GAMEVER`。支持的参数：

- `-configyaml` 选择显式分析配置（默认 `configs/<GAMEVER>.yaml`）。
- 逗号分隔的 `-platform`（`windows`、`linux`）与 `-modules`。
- `-skill=<exact-name>` 只在当前 `-modules` 过滤内运行精确 skill 名。
- `-agent` 与 `-agent_model` 选择 Agent CLI 与模型。
- 配套的 `-llm_model`、`-llm_apikey`、`-llm_baseurl`、`-llm_temperature`、`-llm_effort`、`-llm_fake_as`
  配置 LLM-backed 工作流。
- `-maxretry` 限制 Agent 重试；skill 显式 `max_retries` 优先。
- `-oldgamever` 选择同一 game family 中最近的旧 build，并把 old-YAML map 交给 Preprocessor。
  `download.yaml` 中的 `major_update: true` 会禁用自动旧版本选择。旧 YAML 直接复制保持禁用。
- `-ida_args` 用于追加 IDA 启动参数。`-rename` 与 Source2 专用 finder 语义保持排除。
- IDB cache mode 不再是 CLI 参数。每次 analysis 都要求先恢复 exact IDB generation，并固定使用 strict no-rebuild/no-save 语义。
- `-skip_pp` 跳过单一 Preprocessor，直接运行 Agent。`-skip_error` 允许运行失败后继续，但最终退出状态仍非零。
- `-process_reporter=console` 输出 typed `ProcessEvent` JSONL；`redis` 以 best-effort 方式写入
  `gsvibe:analysis:v1` Redis 协议。`-redis_url` 与 `-redis_prefix` 配置 Redis backend；`-run_id` 设置运行身份。
- `-debug` 启用调试输出。

### Local IDB cache core

`idb_cache.py` 提供 `probe`、`warm`、`publish`、`restore`、`verify` 与 `prune`。

Warm production 按 job 拆分：reusable `warmup-idb` producer 写入 canonical `cache-selection.json` 及其 SHA-256
evidence；consumer（`idb_cache_release.py restore` / `idb_cache_workflow.py restore`）验证该 selection、restore
exact generation，再以 `database_policy=restored_strict` 与 `save_on_success=false` 运行 Analyzer。Miss、corrupt
generation 或 runtime mismatch 会使 run 失败；任何 analysis consumer 都不能回退为重建。Consumer 绝不重新
probe `READY.json`，只 restore 其自身 producer 发布的 exact generation。本地调用也必须先恢复已验证的 exact
generation，再启动 Analyzer。

### 使用 `-allgamever` 批量分析

`ida_analyze_bin.py -allgamever` 会批处理 `configs/config.yaml` 中声明的每个 game-version tag。该索引是批量
成员与顺序的唯一权威；tag 只有显式列出才会运行，而声明了但 `configs/<tag>.yaml` 缺失的 tag 是致命配置错误，
不是静默跳过。没有 `configs/config.yaml` 时使用兼容性的旧顺序：`download.yaml` manifest 声明顺序，随后按字典序
排列其余 `configs/*.yaml` tag。

当 `-allgamever` 与 `-modules` 一起使用时，未声明任何请求模块的 tag 会被跳过；单独使用 `-gamever` 时，请求的
模块不存在仍会报错。

### 精确选中节点批量分析

`-batch_selection selections.json` 接受通用清单，不直接读取 PR plan：

```json
{"schema_version":1,"selections":[{"tag":"cstrike-10210","node_ids":["engine:windows:EXACT_SKILL_NAME"]}]}
```

节点 ID 必须来自对应 tag 的配置 DAG。未知或重复 tag/节点、空集合、版本不支持、重复 JSON key、多余字段及类型错误，
均在启动 worker 前使整批失败。不允许组合其他选择参数、`-configyaml`、`-oldgamever`、`-run_id` 或 `-skip_error`。
`-validate_selection_only` 在 materialize 前校验清单与完整 DAG，不检查尚未准备的输入文件。

先 exact warm restore，再 materialize 未选中上游产物，随后执行：

```bash
uv run python ida_analyze_bin.py -batch_selection selections.json -bindir bin -artifactdir <isolated-root> -batch_diagnostics <diagnostic-root>
```

先按完整 DAG 分类，再过滤精确节点集合；同 binary 的依赖保留在单 worker 内，跨 binary 的目标与下游闭包进入全局串行尾队列。
只有全部并行 worker 成功退出，才启动尾队列；不扩展上游、不补跑节点。首个 worker 启动前统一检查所选节点的外部必需输入，
由本批次前置节点生成的输入留到执行阶段检查。IDB 保持 `restored_strict`、不保存修改。

整个批次共享既有 analysis 并发上限、内存预算和初始预留配置，默认并发仍为 `1`；有效并发大于 `1` 必须显式配置内存预算。
首次失败停止派发并有界等待在途 worker；超时或取消仅清理所属进程树，未确认退出视为失败且不释放配额。
全批次成功后才允许后处理。

每批诊断目录唯一，包含独立 worker 日志与 `summary.json`，记录 tag、binary、阶段、节点、状态、耗时、失败原因及日志位置。
控制台仅输出生命周期与资源等待状态，避免原始并发输出交错。诊断工件不含请求文件、IDB 或二进制，已知凭证值会脱敏。
未指定 `-batch_diagnostics` 时，写入系统临时目录下的 `gsvibe-analysis-diagnostics`。

## 分析合约

分析顺序为单一 skill-specific Preprocessor → Agent fallback。Preprocessor 在绑定的 IDA MCP session 中运行，可
显式声明 `llm_config`，并返回 `success`、`absent_ok`、`no_script` 或 `failed`。

必需与可选工件加显式 prerequisites 构成一个 DAG。Output 只允许 module-local；input 可使用安全 sibling 引用，
如 `../engine/X.{platform}.yaml`，规范化到 game-version root 内并连成真实跨模块 DAG 边。不安全路径、环路、
重复或大小写冲突名称、缺失必需输入、架构错误与二进制被改动均属致命错误。

### 工件路径与身份

工件路径固定为 `bin_artifacts/<tag>/<module>/<symbol>.<platform>.yaml`。`bin/` 是独立的二进制与 IDA scratch 根，
不再是分析 YAML 的 truth source。Config symbol 使用 `name` 加唯一分类符
`category`；拒绝 `type` 与 `kind`。Artifact 拒绝通用 `name/type/kind`，按 category 使用 `func_name`、
`gv_name`、`patch_name`、`vtable_class` 或 `struct_name/member_name`。Payload identity 不要求与 config symbol
name 相等，这与 CS2 loader 合约一致。

支持的 category 为 `func`、`gv`、`vfunc`、`vtable`、`patch`、`struct`、`structmember`。primary/ordinal vtable
helper 必须显式使用并 fail closed；Source2 专用 dispatch 协议保持排除。x86 虚拟函数 slot 固定为 4 字节。

## Production 注册

Production finder 的覆盖范围与依赖链声明在 `configs/<GAMEVER>.yaml` 中。Config 是当前清单的唯一事实来源，
Analyzer 根据其中的 input/output 构建执行 DAG。可复用的 finder 模式参见
[创建符号分析 skill](creating-skills.md)。
