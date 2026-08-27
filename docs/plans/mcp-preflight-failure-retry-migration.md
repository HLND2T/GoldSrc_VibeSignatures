# MCP preflight 失败重试语义迁移计划

状态：已实施

日期：2026-08-27（Asia/Singapore）

优先级：P1

GoldSrc 规划基线：`main@98e7247502f1e5c8e30481295d67712b6db5282d`

CS2 参考合并提交：`3076f534794977a646b702ae6587eeb44765615c` (D:/CS2_VibeSignatures)

CS2 直接参考提交：`d0d7dfa103071ecda0ba0409cd0d2dd3ac702e95` `fix(agent): retry failed MCP preflights` (D:/CS2_VibeSignatures)

## 1. 目标

修改 `agent_runner` 的 MCP preflight cache：

- 成功结果继续缓存，避免每个 Skill 重复执行 `<agent> mcp list`；
- 失败结果不跨 `run_skill()` 调用缓存；
- 后续 Skill 可以在 MCP supervisor 恢复后重新 preflight；
- 失败原因与结构化 diagnostics 保持不变。

该迁移解决“第一次瞬时 preflight 失败污染整个进程后续 Skill”的问题，不增加无限重试或隐藏真实基础设施故障。

## 2. 当前问题

`agent_runner._MCP_PREFLIGHT_CACHE` 当前保存 `McpPreflightResult`，`_perform_mcp_preflight()` 无论成功或失败都会写入 cache。

结果是：

```text
第一次 preflight 瞬时失败
  -> failure 被缓存
  -> 后续 run_skill() 直接读取失败
  -> 不再执行 agent mcp list
  -> 即使 owned MCP 已恢复，后续 Skill 仍全部失败
```

这与 `ida_analyze_bin` 的 MCP lifecycle recovery 不一致：lifecycle 可以在 binary 处理期间恢复 supervisor，但 agent preflight cache 仍可能持有恢复前的失败状态。

现有测试 `test_preflight_caches_success_and_failure_per_agent` 明确锁定了失败缓存，需要在实施时改写为新的 contract。

## 3. 行为决策

### 3.1 缓存规则

cache 只保存 `result.ok is True` 的结果。

以下失败均不写 cache：

- timeout；
- agent executable 不存在；
- OS/process execution error；
- `mcp list` 未列出 required server；
- 非零 return code 且输出不满足 server detection；
- 未来新增的其他 `McpPreflightResult(ok=False)`。

### 3.2 重试粒度

失败后允许下一次 `_perform_mcp_preflight()` 或下一次 `run_skill()` 重新执行 preflight。

本计划不在同一个 `run_skill()` 调用内增加 preflight retry loop。`max_retries` 继续只约束 Agent Skill execution attempts，不隐式改变为 MCP preflight 重试次数。

### 3.3 与动态 endpoint 计划的接口

本计划先保留当前 cache key `(agent, server_name)`，只改变成功/失败写入语义。

后续 `dynamic-mcp-endpoint-migration.md` 会把 cache key 扩展为 endpoint-aware identity。为减少冲突，本计划实现应保持 cache 写入集中在 `_perform_mcp_preflight()` 尾部，不引入新的全局 success/failed 集合。

## 4. 非目标

- 不增加 sleep、backoff、timer 或失败 TTL cache；
- 不在一次 Skill 调用内无限重跑 `mcp list`；
- 不改变 Agent command、session resume 或 model 参数；
- 不新增动态 MCP URL；
- 不改变 `McpPreflightResult` 的 reason/detail schema；
- 不把 preflight 失败降级成 warning；
- 不允许 MCP preflight 被跳过，除非现有显式 `mcp_preflight=False` 调用者已选择跳过。

## 5. 实施方案

### 5.1 TDD 调整

先修改 `tests/test_agent_runner.py`：

1. 将成功与失败缓存测试拆开；
2. 保留“成功只执行一次”的断言；
3. 新增“第一次失败、第二次成功会执行两次 preflight”的断言；
4. 验证第二次成功后第三次调用读取 success cache；
5. 对 timeout、FileNotFoundError 与 server missing 分别证明失败不缓存；
6. 保留结构化 reason/detail 断言。

### 5.2 修改 cache 写入

修改 `agent_runner._perform_mcp_preflight()`：

```text
cached success -> return cached
execute preflight
result.ok -> cache and return
not result.ok -> return without cache
```

不需要改变 `_MCP_PREFLIGHT_CACHE` 的容器类型，也不需要新增 `_MCP_PREFLIGHT_FAILED`。

为避免以后误把 failure 放回 cache，可以把写入条件表达为显式 `if result.ok:`，并让所有异常分支统一产生结构化 result 后走同一个收尾路径。

### 5.3 调用链核对

核对以下调用者不依赖 failure cache：

- `has_required_mcp_server()`；
- `run_skill()`；
- `ida_analyze_bin` 的 Agent fallback；
- tests 或本地工具中显式调用 preflight helper 的路径。

重复失败会使每个后续 Skill 再执行一次 bounded `MCP_LIST_TIMEOUT` preflight，这是有意的恢复性权衡。日志与 progress reporter 必须继续报告每次真实失败。

## 6. 测试矩阵

至少覆盖：

1. 同 agent/server 成功两次：process 只调用一次；
2. 第一次 server missing、第二次 connected：process 调用两次，第二次成功；
3. 第二次成功后第三次调用：不再调用 process；
4. timeout 后再次调用：重新执行；
5. agent executable missing 后再次调用：重新执行；
6. 不同 agent 的 success cache 相互隔离；
7. 不同 server name 的 success cache 相互隔离；
8. failure reason/detail 与 stdout/stderr 截断规则保持不变；
9. `run_skill()` preflight 失败仍立即返回 false，不启动 Agent command；
10. lifecycle 恢复后后续 Skill 可以重新 preflight 并执行。

## 7. 验证命令

定向验证：

```text
uv run python -m unittest tests.test_agent_runner
uv run python -m unittest tests.test_analysis_planner
```

完成前质量门禁：

```text
uv run python format_repo_files.py --check
uv run python tests/run_test_suite.py unit -b --durations 30
uv run python tests/run_test_suite.py repository-contract -b --durations 30
uv run python tests/run_test_suite.py all -b --durations 30
```

## 8. 风险与权衡

### 风险：MCP 长时间不可用时重复等待

每个后续 Skill 可能再次等待最多 `MCP_LIST_TIMEOUT`。这是恢复能力与快速失败之间的明确权衡。

初版不增加 failure TTL。若真实运行证明重复等待造成不可接受的墙钟时间，应另行设计 run-scoped circuit breaker，并以 supervisor generation/endpoint identity 作为恢复信号，不能恢复永久 failure cache。

### 风险：测试继续锁定旧语义

必须删除或改写“success and failure 都缓存”的断言，不能只新增旁路测试。

### 风险：与动态 endpoint 工作重复冲突

先合入本计划，再实施 endpoint-aware key。P2 计划只扩展 key，不重新改变 failure cache policy。

## 9. 实施顺序

1. 改写 preflight cache tests；
2. 实施 success-only cache；
3. 运行 `test_agent_runner`；
4. 补 lifecycle 恢复后的跨 Skill 测试；
5. 运行 analyzer 定向测试；
6. 运行仓库质量门禁；
7. 在真实本地 MCP 启动延迟/重启场景做一次手工验证并记录日志。

## 10. 验收标准

- successful preflight 仍按 agent/server 缓存；
- failed preflight 不进入 cache；
- transient failure 后下一 Skill 可以重新检查并成功；
- persistent failure 仍明确失败且保留结构化 diagnostics；
- Agent execution retry/session 语义未变化；
- 没有新增无限 retry、sleep 或 silent fallback；
- 定向测试与仓库质量门禁有真实通过证据。
