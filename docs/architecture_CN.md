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

`ida_analyze_bin.py` 对每个 DAG 节点依次尝试：

1. 仅在旧工件的每个签名都能在新二进制中唯一命中时复用；
2. 执行 `ida_preprocessor_scripts/<skill>.py` 的 deterministic preprocessor；
3. 执行 `ida_llm_preprocessor_scripts/<skill>.py` 的 LLM preprocessor；
4. 通过 Agent runner 有界重试具体 skill。

二进制在分析前必须是 32 位 I386；每个 skill 后以及整个 job 结束时都会重新核对 SHA-256。IDA MCP 会按规范化
二进制路径绑定唯一的活动数据库。

## Snapshot 边界

writer 输出 schema 5，包含 config digest v2、analysis output contract、UTC 发布时间、canonical YAML 工件，以及
每个配置二进制的 SHA-256、MD5、CRC32、CRC64 和 size。reader 兼容 schema 1–5。restore / verify 会拒绝链接、
路径逃逸、未声明或缺失的 YAML、非 canonical bytes 与 contract drift。

candidate manifest 固定候选 hash 与文件系统 identity。发布使用原子替换，并且必须先验证匹配的 gamedata session。
candidate session 不包含 C++ 测试步骤。

## 明确不包含

框架只提供 console / in-memory reporter，不包含服务 API、UI、远程 release promotion、C++ layout、自动版本 bump，
也不包含目标专属的生产签名和 generator。
