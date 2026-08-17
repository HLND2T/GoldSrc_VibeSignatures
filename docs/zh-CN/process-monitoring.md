[返回 README](../../README_CN.md) | [English](../en/process-monitoring.md)

# 进度上报、调度与看板

## Redis 进程上报

Redis 进程上报是可选的。设置：

```text
GSVIBE_PROCESS_REPORTER=redis
GSVIBE_REDIS_URL=redis://127.0.0.1:6379/0
```

或向 Analyzer 传入 `-process_reporter=redis`、`-redis_url=...` 与可选的 `-redis_prefix=...`。

Reporter 会发布不可变执行图、当前 Run/Job/Task snapshot、event Stream、原子 summary 计数器与带 TTL 的
heartbeat。临时 Redis 故障不会改变分析结果；重连后回放最近一次本地 snapshot。

## Scheduler

先入队一个 Analyzer 运行，再启动单并发 worker：

```bash
uv run python process_scheduler_cli.py submit --gamever cstrike-10210 --agent claude
uv run python process_scheduler_cli.py run
```

Redis Stream consumer group 保持 FIFO 顺序，Scheduler 重启后恢复 pending entry，且不会在 Analyzer heartbeat
仍存活时重启已恢复的 Run。队列载荷是经过验证的字段而非可执行 shell 命令。请求合约刻意保持最小：`run_id`、
`gamever`、`platforms`、`modules`、`skill_filter`、`agent`、`created_at`；scheduler 控制自己的 argv 与环境。
Scheduler 恢复会原子 abort 所有未完成 task 并重算 summary。

## 只读进度 API

本地启动 API：

```bash
uv run uvicorn process_api:app --host 127.0.0.1 --port 8000
```

服务在 `/api/v1` 下提供 `/healthz`、`/readyz`、run list/detail、execution graph、snapshot、task、event page 与
SSE stream。SSE 支持 `Last-Event-ID`，当保留的 Redis 游标过旧（包括连接期间被 trim 越过）时发出 reset event；
默认 live 游标在阻塞前固定为具体 Stream ID。

服务默认绑定 localhost 且无内置认证。外部部署应放在带认证的反向代理之后。用 `GSVIBE_API_CORS_ORIGINS` 配置
浏览器 origin，通过 `GSVIBE_SSE_BLOCK_MS` 与 `GSVIBE_SSE_BATCH_SIZE` 调节 SSE，用 `/healthz` 与 `/readyz`
检查存活与 Redis 就绪。

## 看板与 Symbol Explorer

`pages/` 中的 React dashboard 消费该 API，并提供静态 Symbol Explorer。构建：

```bash
cd pages
npm ci
npm run build
```

GitHub Pages 只部署静态 `pages/dist`，不托管 API/SSE 进程——浏览器会连接运行它的计算机上的 Process API。若
公开 Pages origin 要连接同一浏览器机器上的 FastAPI，需把精确 origin 加入 `GSVIBE_API_CORS_ORIGINS` 并设置
`GSVIBE_API_ALLOW_PRIVATE_NETWORK=true`。

`pages-snapshots` 分支只允许追加，存储每个 content-addressed `<family-build>.<sha256>.json` snapshot。
`npm run verify:gamesymbols` 与部署 job 会校验精确响应字节与 digest。
