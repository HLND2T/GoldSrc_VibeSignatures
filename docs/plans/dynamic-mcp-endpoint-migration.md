# 动态 MCP endpoint 迁移计划

状态：待实施

日期：2026-08-27（Asia/Singapore）

优先级：P2

GoldSrc 规划基线：`main@98e7247502f1e5c8e30481295d67712b6db5282d`

CS2 参考合并提交：`3076f534794977a646b702ae6587eeb44765615c`

CS2 endpoint override 参考提交：`8656bbcf34ca4b67dbb5ea7ee406574a4bdb9149` `fix(agent): inject dynamic MCP endpoint overrides`

CS2 动态端口参考提交：`dde2464938c77384709bf675423d4fc6c139a16a` `feat(ida): allocate a dynamic MCP port per binary`

依赖：建议先完成 `docs/plans/mcp-preflight-failure-retry-migration.md`

## 1. 目标

让每个由 analyzer 拥有的 `idalib-mcp` lifecycle 使用独立的本地动态端口，并把该 lifecycle 的 exact MCP URL 注入对应的 Claude、Codex 或 OpenCode Agent Skill 调用。

目标结果：

- analyzer 不再默认占用固定 `127.0.0.1:13337`；
- 本地已运行的交互式 `ida-pro-mcp` 不会阻止 batch analyzer 启动；
- Agent fallback 总是连接当前 binary 对应的 owned `idalib-mcp`；
- MCP preflight success cache 按 endpoint 隔离；
- 未来可以在保持 binary/IDB ownership 的前提下评估并行分析。

动态端口分配与 endpoint 注入必须作为一个原子能力迁移。只改端口而不改 Agent override 会让 Agent 继续连接静态配置中的错误 MCP。

## 2. 当前状态

GoldSrc 当前：

- `DEFAULT_HOST = 127.0.0.1`；
- `DEFAULT_PORT = 13337`；
- analyzer 的 selected-node 与普通 binary lifecycle 都传入固定 port；
- Preprocessor 已使用 `McpRuntime.host/port`；
- Agent fallback 调用 `agent_runner.run_skill()` 时没有传 endpoint；
- `agent_runner` 的 Claude/Codex/OpenCode command 都依赖静态 MCP 配置；
- preflight cache key 只有 `(agent, server_name)`，不能区分两个 binary lifecycle endpoint。

`McpRuntime` 已经保存 `host` 与 `port`，应复用为 owned endpoint truth source，不新增第二套 runtime identity。

## 3. 核心设计

### 3.1 Endpoint identity

新增一个集中 helper，从已验证的 runtime 构造 URL：

```text
http://127.0.0.1:<dynamic-port>/mcp
```

约束：

- scheme 只允许 `http`；
- host 必须是 analyzer-owned local/loopback host；
- port 必须是 `1..65535`；
- path 固定 `/mcp`；
- 禁止 credentials、query 与 fragment；
- URL 通过参数数组或 JSON 传递，不拼接 shell command；
- endpoint 不是 secret，但日志不得输出包含其他 config/credential 的完整 command payload。

默认只支持本机 owned `idalib-mcp`。远程 MCP、任意用户 URL 或 external supervisor 不在本计划范围。

### 3.2 动态端口生命周期

新增 `_allocate_local_port(host=DEFAULT_HOST) -> int`：

1. 创建 TCP socket；
2. bind `(host, 0)`；
3. 读取 OS 分配的 ephemeral port；
4. 关闭 reservation socket；
5. 将端口传给当前 `IdaMcpLifecycle`。

端口的 ownership 范围是单个 MCP lifecycle，不是整个 process、tag 或 repository。

`DEFAULT_PORT` 保留供显式测试、诊断和兼容调用使用，但 production analyzer 默认路径改为 `port=None`，由 lifecycle 创建前分配动态端口。

bind 后释放再启动 child process 存在很小的 TOCTOU 窗口。初版记录该限制，不通过无限重试隐藏 IDA 启动失败。若检测到端口已被占用，可在 child 启动前做一次 bounded re-allocation；child 已启动后的 readiness/identity failure 继续走现有 lifecycle recovery budget。

### 3.3 Agent endpoint overrides

扩展 `agent_runner.run_skill()` 及内部 command builders，增加可选 `mcp_url: str | None = None`。

当 `mcp_url` 非空时：

#### Claude

通过 invocation-scoped config：

```text
--mcp-config <canonical-json>
--strict-mcp-config
```

JSON 只声明 `ida-pro-mcp` 的 HTTP URL，防止静态配置中的同名 server 覆盖 owned endpoint。

#### Codex

通过独立 argv entries 注入：

```text
-c mcp_servers.ida-pro-mcp.url=<json-encoded-url>
-c mcp_servers.ida-pro-mcp.required=true
```

必须继续保持 developer instructions 通过现有安全通道传递，不能因插入 endpoint args 改变 `exec`/resume 参数顺序。

#### OpenCode

在当前复制的 process environment 中写 invocation-scoped `OPENCODE_CONFIG_CONTENT`，只覆盖 `ida-pro-mcp` remote URL 与 enabled 状态，不修改父进程环境。

当 `mcp_url is None` 时，保持现有静态配置行为，确保独立调用 `agent_runner.run_skill()` 的兼容性。

### 3.4 Endpoint-aware preflight cache

完成 P1 后，success-only cache key 扩展为：

```text
(agent executable, server name, normalized MCP URL or None)
```

要求：

- 同 agent、同 endpoint 的成功 preflight 可复用；
- 同 agent、不同动态端口必须分别 preflight；
- 静态配置 `None` 与动态 URL 不共享 cache；
- 失败仍不缓存；
- Claude/Codex preflight command 与实际 Skill command 使用相同 override；
- OpenCode preflight 与实际 Skill process 使用相同 environment override。

### 3.5 Analyzer wiring

修改 `ida_analyze_bin.py`：

1. 在默认 analyzer 路径中用 `port=None` 表示动态分配；
2. 在 `_create_ida_mcp_lifecycle()` 或其唯一上游集中分配 port，确保 selected-node 与普通全量路径语义一致；
3. `IdaMcpLifecycle` 继续只接收已解析的整数 port；
4. lifecycle readiness/identity 验证成功后，以 `McpRuntime.host/port` 构造 `mcp_url`；
5. Preprocessor 继续使用 runtime host/port，不改其 session API；
6. Agent fallback 调用 `agent_skill_runner(..., mcp_url=<owned-runtime-url>)`；
7. lifecycle recovery 后若 runtime endpoint 改变，后续 Agent 调用必须使用恢复后的 runtime，而不是旧 URL；
8. Process Reporter 可记录 host/port 或 endpoint identity，但不得把它当 durable plan/cache identity。

不允许从全局 `DEFAULT_PORT` 推导 Agent URL；唯一 truth source 是当前 verified `McpRuntime`。

## 4. 文件范围

预计修改：

- `agent_runner.py`：URL validation、command/env override、endpoint-aware preflight、`run_skill()` 参数；
- `ida_analyze_bin.py`：动态端口分配、lifecycle wiring、Agent endpoint 传递；
- `tests/test_agent_runner.py`：三种 Agent override 与 preflight cache tests；
- `tests/test_analysis_planner.py`：runtime endpoint 传递和 lifecycle tests；
- 必要时 `tests/test_ida_analyze_bin.py`；当前大部分 analyzer/lifecycle tests 位于 `test_analysis_planner.py`，实施时遵循现有归属，不为同一行为重复建测试；
- `docs/en/requirements.md` 及中文对应文档：移除“batch analyzer 必须独占固定 13337”的运维假设；
- `docs/en/architecture.md`、CI/CD 文档与对应中文文档：描述 invocation-scoped endpoint；
- `memory/idalib-mcp.md`：实施完成后更新固定端口约束、恢复与诊断方式。

不修改 root dependencies、CI runner topology 或 workflow concurrency，除非实施核验发现当前 workflow 显式依赖固定端口；这类扩张必须单独确认。

## 5. TDD 与测试矩阵

### 5.1 Port allocation

至少覆盖：

1. `_allocate_local_port()` 返回合法端口；
2. 分配时使用指定 loopback host；
3. 默认 analyzer lifecycle 不再固定传 `13337`；
4. 显式 integer port 调用保持原值；
5. selected-node 与普通 full path 都使用动态 lifecycle；
6. 两个连续 lifecycle 得到可独立使用的 endpoint；
7. 已存在 `.id0` lock 时仍在启动前失败，不因动态端口放宽 IDB ownership；
8. shutdown/recovery/save/identity verification 始终使用同一 lifecycle port。

### 5.2 Agent command construction

至少覆盖：

1. Claude preflight 与 Skill command 都含相同 strict MCP config；
2. Codex preflight、初次 execution 与 resume 都含相同 `-c` overrides；
3. OpenCode preflight、初次 execution 与 session retry 都使用相同 `OPENCODE_CONFIG_CONTENT`；
4. `mcp_url=None` 时 command/env 与当前行为一致；
5. malformed、non-loopback、含 credentials/query/fragment 的 URL 被拒绝并报告结构化 reason；
6. URL/JSON encoding 不产生 argument splitting 或 shell execution；
7. command display 不泄漏 developer instructions 或其他敏感 config。

### 5.3 Cache 与 runtime wiring

至少覆盖：

1. 同 endpoint success cache 命中；
2. 不同 endpoint 不共享 success cache；
3. dynamic endpoint 与 static `None` 不共享；
4. endpoint A failure 不阻止 endpoint A 后续重试；
5. endpoint A failure/成功均不污染 endpoint B；
6. Agent fallback 收到当前 `McpRuntime` URL；
7. MCP recovery 返回新 runtime 时使用新 endpoint；
8. Preprocessor 与 Agent 在同一 node 上连接同一个 verified runtime；
9. all-existing-output/no-Agent 路径不无意义启动 MCP；
10. `mcp_preflight=False` 只跳过 list check，实际 command 仍使用显式 endpoint override。

## 6. 验证命令

定向验证：

```text
uv run python -m unittest tests.test_agent_runner
uv run python -m unittest tests.test_analysis_planner
uv run python -m unittest tests.test_ida_mcp_session
```

完成前质量门禁：

```text
uv run python format_repo_files.py --check
uv run python tests/run_test_suite.py unit -b --durations 30
uv run python tests/run_test_suite.py repository-contract -b --durations 30
uv run python tests/run_test_suite.py all -b --durations 30
```

真实环境验证不能由 mock tests 代替，至少记录：

- 交互式 MCP 占用 `127.0.0.1:13337` 时，batch analyzer 仍能启动；
- Claude、Codex、OpenCode 中仓库实际支持的每一种 Agent 至少完成一次 endpoint preflight；
- Agent 查询到的 binary identity 与 analyzer-owned `McpRuntime.expected_binary` 一致；
- 连续处理两个 binaries 时使用不同 endpoint 且无串线；
- lifecycle recovery 后 Agent 使用恢复后的 endpoint；
- analyzer 退出后动态端口已释放、owned child process 已终止。

未配置或未安装的 Agent 必须标记为未验证，不能声称三种 Agent 全部通过。

## 7. 安全与可靠性边界

- endpoint 只来自 analyzer-owned verified runtime，不接受不可信 config/path 输入；
- 所有 subprocess 调用使用 argv list，不启用 shell；
- OpenCode override 写入 child env copy，不污染全局 `os.environ`；
- dynamic port 不改变 IDB `.id0` lock、binary identity、database policy 或 recovery budget；
- dynamic endpoint 不是并行安全的充分条件；IDB、workspace、Process Reporter、cache 与 runner concurrency 仍需各自门禁；
- 本计划不移除 GitHub workflow 的全局 self-hosted IDA concurrency；
- preflight success 只对 exact agent/server/endpoint 有效；
- 不缓存 preflight failure，遵循 P1 contract。

## 8. 风险与缓解

### 风险：只改端口导致 Agent 仍连接静态 13337

缓解：端口分配、runtime URL、Agent override、preflight key 和 tests 必须在同一实施 PR 完成。

### 风险：端口分配 TOCTOU

缓解：使用 OS ephemeral allocation、启动前复核、有限重分配；不得无限重启或吞掉真实 IDA startup error。

### 风险：不同 Agent CLI 参数顺序漂移

缓解：分别为 Claude/Codex/OpenCode 建立完整 argv/env tests，覆盖初次执行与 retry/resume。

### 风险：旧 endpoint success cache 被错误复用

缓解：cache key 强制包含 normalized URL；lifecycle recovery 的新 URL 产生新 key。

### 风险：误把动态端口等同于允许并行

缓解：保留当前 workflow concurrency 与 binary/IDB locks；并行化必须另立计划并验证共享状态。

## 9. 实施拆分

建议在同一 feature branch 分两个可独立 review、最终一起交付的内部步骤：

### Step A：Agent endpoint injection

- URL validation/normalization；
- Claude/Codex/OpenCode overrides；
- endpoint-aware success cache；
- agent_runner tests；
- analyzer 仍可显式使用固定 port 验证 wiring。

### Step B：Dynamic lifecycle port

- `_allocate_local_port()`；
- analyzer 默认 `port=None`；
- selected/full lifecycle 集中分配；
- runtime URL 传入 Agent；
- lifecycle/analyzer tests；
- 真实 IDA/Agent 验证与文档更新。

Step A 可以先提交，但在 Step B 完成前不得宣称动态 endpoint 迁移完成。Step B 不得在缺少 Step A 时启用动态默认端口。

## 10. 验收标准

- analyzer 默认不再依赖固定 `13337`；
- 每个 owned lifecycle 使用合法的动态本地端口；
- Preprocessor 与 Agent 均连接 exact verified runtime；
- Claude/Codex/OpenCode overrides 有定向测试，实际可用 Agent 有真实运行证据；
- preflight cache 按 endpoint 隔离且只缓存成功；
- static `mcp_url=None` 调用保持兼容；
- IDB ownership、recovery、save/shutdown 与 strict restored policy 未被削弱；
- 当前 workflow concurrency 未被错误放宽；
- 交互式 13337 被占用时 batch analyzer 仍成功；
- 定向测试、仓库质量门禁与真实 IDA 验证结果均被如实记录。
