[返回 README](../../README_CN.md) | [English](../en/architecture.md)

# 架构

## 数据流

```text
download.yaml + configs/<tag>.yaml
  -> depots/<basepath>
  -> bin/<tag>/<module>/<binary>
  -> 经过校验的分析 DAG
  -> versioned stage/job/task execution plan
  -> bin_artifacts/<tag>/<module>/<symbol>.<platform>.yaml（Git truth）
  -> 仅 release 阶段生成的不可变 candidate
  -> gamesymbols/<tag>.yaml + gamesymbols/<tag>.metadata.yaml（bundle）
  -> SymbolStore -> 严格 gamedata generator
  -> gamedata/<tag>/gamedata-manifest.json + declared payloads

RunRequest -> Redis Stream -> 单并发 scheduler -> Analyzer
  -> ProcessEvent + heartbeat -> Redis state/streams
  -> 只读 API/SSE -> React process dashboard

snapshot + immutable metadata companion -> Vite asset plugin
  -> content-addressed JSON + index v4
  -> append-only pages-snapshots archive -> GitHub Pages Symbol Explorer

exact source + bin gitlink + bin_artifacts -> analyze all game versions
  -> release bundle + canonical manifest + SHA256SUMS
  -> hosted verify -> protected publish-release -> GitHub Release

trusted PR plan + cache_mode=warm evidence
  -> probe/publish exact generation -> canonical selection -> strict restore
  -> strict no-save selected-node analysis -> validated clean
```

`analysis_planner.py` 是模块、符号、工件路径与 DAG 校验的唯一来源。snapshot contract 复用同一实现，避免分析和
发布阶段对工件归属产生不同解释。
Output 只允许 module-local；input 可使用 `../<module>/<artifact>` sibling 引用。planner 将 producer 与 consumer
统一规范化为 game-root 相对 owner path，并建立真实跨模块边。

Config symbol 使用 `name + category` 并拒绝 `type/kind`；artifact payload 按类别使用 `func_name`、`gv_name`、
`patch_name`、`vtable_class` 或 `struct_name/member_name`，拒绝通用 `name/type/kind`。Payload identity 不与
config symbol identity 强制比较。

## 分析层次

`ida_analyze_bin.py` 当前对每个 DAG 节点依次执行两个可运行层次：

1. 在绑定的 IDA MCP session 中执行并进程内缓存 `ida_preprocessor_scripts/<skill>.py`；脚本只有显式声明
   `llm_config` 才会收到 LLM runtime 配置，并返回 `success`、`absent_ok`、`no_script` 或 `failed`；
2. 在需要 fallback 时通过 Agent runner 有界重试具体 skill。

Agent runner 会校验各 CLI 的 model 参数、保持 Claude/OpenCode retry session 稳定、注入 Codex developer prompt、
并发 drain stdout/stderr，并通过本地 reporter 发出 attempt 级结构化诊断。MCP list preflight 结果按 Agent 可执行文件、
server 和 normalized MCP endpoint 分别缓存（仅成功）。

旧 YAML 直接复制已禁用，因为携带地址的旧工件可能保留陈旧地址。旧版本自动选择仅限同一 game family 中更早的
最高 build，并可通过 `major_update: true` 禁用；Analyzer 将 new-output 到 old-YAML 的映射交给 Preprocessor，
由具体脚本通过 MCP 重新定位 signature 并重建地址。共享 GoldSrc x86 helper 保持 CS2 Finder API，覆盖
func/vfunc、GV、patch、structmember、primary/ordinal vtable、继承 slot、xref filter 和受验证的 LLM fallback。

二进制在分析前必须是 32 位 I386，并以 path、platform metadata 和 hashes 核对 opened database identity。按
CS2 runtime contract，分析期间不再额外增加每个 skill 后的 binary-mutation guard。待执行工作会分配一个空闲
本地端口，并在 `127.0.0.1:<dynamic-port>` 上为每个 binary 启动一次 owned `idalib-mcp` 生命周期（不再保留固定
`13337`）；对每个 module/platform binary，Analyzer 检查 IDB lock 与端口、启动 supervisor、等待 MCP contract
ready、绑定唯一活动数据库、核对 survey identity、允许一次健康恢复，并定向关闭 owned worker、停止 supervisor、
等待端口释放。verified runtime endpoint 会以 invocation-scoped MCP override 注入 Agent fallback，使每个 Agent
连接到其 binary 对应的 exact owned lifecycle。Preprocessor 每次调用都绑定该 binary/database，并获得严格解析的
image base；Preprocessor 与 Agent 产物经过同一层 YAML、symbol schema 与当前 IDB 地址校验。`-ida_args` 已支持，
`-rename` 仍延期。

`-skip_pp` 跳过单一 Preprocessor，直接运行 Agent Skill。`-skip_error` 允许运行期的后续
module/platform/skill 继续，但 config 与 DAG contract 错误仍立即失败；任何已记录运行失败最终都会返回非零。

## Warm IDB cache 边界

`idb_cache.py` 为中性 IDA database 提供 local immutable-generation cache。Schema-1 key 绑定 exact binary
path/bytes、observed IDA kernel/processor/bitness/file type、pinned loader 与 allowlisted plugin digest、normalized
IDA arguments，以及 warm-worker source contract。Generation 保存 exact cached binary 与完整允许的 `.i64`/`.idb`
primary/side-file inventory；active lock file 一律拒绝。

Publication 会先验证 incoming tree，再 atomic rename，最后更新 `READY.json`。READY 只是 probe hint，不是 consumer
authority；restore 始终绑定 exact generation、key 与 manifest SHA-256。READY 写入是幂等的——canonical bytes 相同
就不再替换；JSON writer 自身使用 UUID 临时文件并对 Windows sharing violation 做 bounded retry，避免并发 reader
留下半写或 PID 冲突文件。Restore 拒绝 reparse point、path escape、case collision、stale workspace binary、被篡改
的 manifest/payload 与 active lock。`restored_strict` lifecycle policy 不会 invalidate 或 cold-rebuild 错配的
restored database，并可禁用 success save，确保 selected-node 修改不回流 immutable generation。

Selection primitive 是共享的。`idb_cache_selection.py` 负责 canonical entry shape、coverage/identity 校验、
SHA-256 evidence 文件、带锁的 probe/warm/publish 路径与带锁的 exact restore；PR 与 release workflow 各自构建顶层
document（`plan_sha256`/`merge_sha` vs `source_sha`/`bin_commit`），但 generation contract 不会漂移。
`idb_cache_locks.py` 负责跨进程 tag lock——publisher、pruner、restorer 与直接调用 `idb_cache.py` CLI 都会取得它，
因此任何路径都无法绕过 high-level authority。

Trusted PR plan 携带固定证据字段 `cache_mode=warm`。所有 analysis 路由都把 producer 拆到 reusable
`warmup-idb` job，`analyze-self-hosted` 变成纯 consumer：下载 canonical selection、对照自身 checkout 与 pinned
runtime 验证、在 tag lock 下 restore exact generation、再执行 strict selected-node analysis。Release build 使用同一
producer（`scope: release-all`）和结构一致的 consumer，不存在 analysis 侧 rebuild/save 路由。Repository-level
Actions concurrency group 串行化唯一的官方 producer，runner-local file lock 保护固定 MCP port。

## Reporter 与调度

经过验证的分析 DAG 仍是唯一 planning source。`build_process_execution_plan()` 将它投影为 immutable schema-v1
graph，提供稳定的 stage/job/task、layer、edge 与 auxiliary node ID；直接 Analyzer 和 scheduler 执行因此得到同一图。

`ProcessEvent` 定义 run/task 状态机、phase、稳定 reason、payload、发生时间与 revision 顺序。Reporter 生命周期为
`initialize_run`、`emit`、`heartbeat`、`finalize_run`、`flush`、`close`。Analyzer 始终使用
`BestEffortProcessReporter` 包装 backend，因此监控故障不会改变分析结果。console backend 输出当前 JSONL 协议；
Redis backend 在 `gsvibe:analysis:v1` 下原子更新 run/task view 并追加 event。不保留任何旧 event API 或格式。

`RedisRunQueue` 使用 consumer-group Stream 保存经过验证的最小 `RunRequest`。Scheduler 通过可续期的 Redis 全局
lease 保证一次只运行一个 Analyzer，不经 shell 拼接构造 argv，注入 reporter/run-ID 环境值，以 heartbeat 防止重复
启动，通过 `XAUTOCLAIM` 回收 stale pending entry，拒绝重放 terminal run；若 Analyzer 未写终态，则按子进程 exit
code 补齐，并原子 abort 所有未完成 task、重算 summary 后再追加 run terminal event。

## Snapshot 边界

writer 输出 schema 6，包含 config digest v2、analysis output contract version 2、UTC 发布时间、canonical YAML 工件，以及
每个配置二进制与路径无关的 SHA-256、MD5、CRC32、CRC64 和 size。reader 兼容 schema 1–6；schema 5 仍严格要求
旧 binary `path`。restore / verify 会拒绝链接、
路径逃逸、未声明或缺失的 YAML、非 canonical bytes 与 contract drift。

candidate session 绑定 canonical snapshot 与 alias metadata companion 的 hash、文件系统 identity 和 pair identity。
本地 pair 发布使用可恢复 journal；对外候选边界是 verified release bundle。发布仍必须先验证匹配的 gamedata session，
candidate session 不包含 C++ 测试步骤。

Canonical gamedata 只从 guarded candidate inventory 派生并复制到 release staging，绝不进入 Git index。每个 tag
都有一个排除自身的 canonical manifest，绑定 snapshot/config/generator identity 与声明的 payload 文件；因此空
generator 集合也有一份可验证输出。

## Release provenance 边界

Release build 会在 checkout 外的 fresh root 强制重建所有 configured artifact，并与 Git `bin_artifacts` 做 exact byte
comparison；随后生成 snapshot、metadata、gamedata、binary-only/game-data archive、canonical Release manifest 和
`SHA256SUMS`。self-hosted job 只有 read 权限；GitHub-hosted job 对 exact source 与 Git blobs 完整复验封闭 bundle。
受保护的 `publish-release` 是 `release-build.yml` 中唯一 `contents: write` job：创建或恢复 matching draft，拒绝
tag/asset drift 与覆盖，复核远端 name/size/hash 后才发布。published version 不可覆盖；内容变化必须使用新版本。

## API、Dashboard 与不可变 Pages 资产

`process_api.py` 只读提供 health/readiness、run 分页、graph/snapshot/task/event view 和支持
`Last-Event-ID` 的 SSE。默认 live 游标先固定为具体 Stream ID；游标早于 Redis 保留窗口或在连接期间被 trim 越过时，
reset contract 会要求客户端重新读取 atomic snapshot。
服务默认绑定 `127.0.0.1`、无内置认证；CORS 只允许显式 origin，浏览器 private-network preflight 也必须显式开启。

React dashboard 提供 run list、graph/list、task detail、status filter 和 SSE live update，同时包含静态 Symbol
Explorer。Symbol snapshot 使用 `<family-build>` tag，按 family 分组并在组内按数字 build 降序。Vite plugin 将
published Release 中下载的 schema-6 YAML 与必需的 schema-1 metadata companion 转成精确 UTF-8 content-addressed JSON 与 index
schema v4，并且绝不读取 live config alias；部署 workflow 把所有 digest
保存到 append-only `pages-snapshots` 分支，并校验 current/archive/CDN bytes。该分支只是从 published Release
派生的非权威展示镜像，绝不是 source 或 release truth。GitHub Pages 只托管静态资产，不托管 Process API。

## 当前排除与延期

Plan preview 继续删除，内部 builder 只服务真实执行。generic Source2 vcall finder、Source2 RTTI/dispatcher、
远程 API hosting、C++ layout、自动版本 bump、广泛 production signature 覆盖和目标专属 generator 保持排除。
商业 IDA 验证仍需要已配置的本地或 self-hosted runner。当前 production finder 覆盖范围以 game-version config
中的声明为准，不在文档中维护独立清单。
