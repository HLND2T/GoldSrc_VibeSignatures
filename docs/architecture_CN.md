# 架构

## 数据流

```text
download.yaml + configs/<tag>.yaml
  -> depots/<basepath>
  -> bin/<tag>/<module>/<binary>
  -> 经过校验的分析 DAG
  -> bin/<tag>/<module>/<symbol>.<platform>.yaml
  -> 不可变 candidate
  -> gamesymbols/<tag>.yaml
  -> SymbolStore -> 严格 gamedata generator
```

`analysis_planner.py` 是模块、符号、工件路径与 DAG 校验的唯一来源。snapshot contract 复用同一实现，避免分析和
发布阶段对工件归属产生不同解释。

## 分析层次

`ida_analyze_bin.py` 当前对每个 DAG 节点依次执行三个可运行层次：

1. 执行 `ida_preprocessor_scripts/<skill>.py` 的 deterministic preprocessor；
2. 使用显式 LLM runtime 配置执行 `ida_llm_preprocessor_scripts/<skill>.py`；
3. 通过 Agent runner 有界重试具体 skill。

history stage 名称仍保留，但旧 YAML 直接复制已禁用，因为携带地址的旧工件可能保留陈旧地址。旧版本自动选择仅限
同一 game family 中更早的最高 build，并可通过 `major_update: true` 禁用。当前只把选中的旧目录写入上下文，
直到 MCP-bound 实现能够重新定位 signature 并重建地址。

二进制在分析前必须是 32 位 I386；每个 skill 后以及整个 job 结束时都会重新核对 SHA-256。对每个仍有待执行工作的
module/platform binary，Analyzer 拥有一次完整 `idalib-mcp` 生命周期：检查 IDB lock 与端口、启动 supervisor、等待
MCP contract ready、绑定唯一活动数据库、核对 survey identity、允许一次健康恢复，并定向关闭 owned worker、停止
supervisor、等待端口释放。绑定后的 host/port/database 信息通过 `context["mcp"]` 传给 preprocessor；`-ida_args`
已支持，`-rename` 仍延期。

`-skip_pp` 跳过 history 与两个 preprocessor 层，直接运行 Agent Skill。`-skip_error` 允许运行期的后续
module/platform/skill 继续，但 config 与 DAG contract 错误仍立即失败；任何已记录运行失败最终都会返回非零。

## Snapshot 边界

writer 输出 schema 5，包含 config digest v2、analysis output contract、UTC 发布时间、canonical YAML 工件，以及
每个配置二进制的 SHA-256、MD5、CRC32、CRC64 和 size。reader 兼容 schema 1–5。restore / verify 会拒绝链接、
路径逃逸、未声明或缺失的 YAML、非 canonical bytes 与 contract drift。

candidate manifest 固定候选 hash 与文件系统 identity。发布使用原子替换，并且必须先验证匹配的 gamedata session。
candidate session 不包含 C++ 测试步骤。

## 当前排除与延期

框架只提供 console / in-memory reporter；CS2 process/Redis Reporter 本次延期，CLI 不暴露 backend、Redis 或
run-ID 参数。Plan preview 已明确删除，但真实执行仍复用内部 execution-plan builder；generic Source2 vcall finder
保持排除。

仓库当前不包含服务 API、UI、远程 release promotion、C++ layout、自动版本 bump，也不包含目标专属的生产签名
和 generator。
