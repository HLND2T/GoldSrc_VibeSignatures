---
title: idalib-mcp ad-hoc scripting pitfalls
type: note
permalink: goldsrc-vibesignatures/notes/idalib-mcp-ad-hoc-scripting-pitfalls
tags:
- idalib-mcp
- pitfalls
- asyncio
- mcp
- debugging
---

# idalib-mcp ad-hoc scripting pitfalls

## Trigger

Writing an ad-hoc driver script around `IdaMcpLifecycle` (anchor probes, one-off validation, custom analysis passes) instead of going through `ida_analyze_bin.py`'s pipeline.

## Facts — mistakes actually made (2026-09-06 session)

1. **Never enter the sync `with IdaMcpLifecycle(...)` from inside a running asyncio event loop.** `__enter__` → `wait_for_mcp_ready` and the graceful-quit path call nested `asyncio.run(...)`, which raises `RuntimeError: asyncio.run() cannot be called from a running event loop` AFTER the worker already opened the IDB. The failed-enter cleanup can then only force-stop (and before PR #72, force-stop left an orphan worker holding the lock). Symptom chain: RuntimeError in `wait_for_mcp_ready` → next run fails with `IDB lock file detected (<binary>.id0)`.
2. **Correct pattern** (mirrors `_execute_selected_nodes`): keep `with lifecycle:` in plain sync context; inside the block run each MCP phase with its own `asyncio.run(analyze(lifecycle.runtime), ...)`:
   ```python
   with IdaMcpLifecycle(binary, platform, "127.0.0.1", None, [], False,
                        database_policy=DATABASE_POLICY_RESTORED_STRICT,
                        save_on_success=False) as lifecycle:
       asyncio.run(analyze(lifecycle.runtime))
   ```
3. **`lifecycle.runtime` is an `McpRuntime` dataclass** (host/port/binding), NOT a session. Open the callable session per phase: `async with open_ida_mcp_session(runtime.host, runtime.port, expected_binary=runtime.expected_binary, explicit_database=runtime.binding.session_id) as session:` then `await session.call_tool(...)`.
4. **py_eval result envelope**: `CallToolResult.structured_content` is `{"result": <repr string>, "stdout": ..., "stderr": ...}` — `result` is a JSON-encoded *string* (often literally `"None"`), so `parse_mcp_result` can yield `None` misleadingly. Return data by `print("__MARKER__" + json.dumps(payload))` and read `structured_content["stdout"]`; surface `stderr` on failure.
5. **IDA 9.3 python**: `from ida_strlist import strings` does not exist and `idautils.Strings` objects are iterable but not callable. Use `s = idautils.Strings(default_setup=False); s.setup(strtypes=[ida_nalt.STRTYPE_C], minlen=8)` then `for item in s:` — `str(item)` returns decoded text with real newline bytes, so a `FULLMATCH:` needle needs the literal `\n` in the Python string.
6. **After any crashed lifecycle run**, check for orphans before rerunning: `python -m ida_pro_mcp.idalib_server` processes (wmic/tasklist) holding the DB, plus `<binary>.id0/.id1/.id2/.nam/.til` sidecars next to the `.i64`. Kill the orphan PID (it was started by the crashed run, so it is task-owned) and delete the stale sidecars — they are just the unpacked, unmutated view of the still-intact `.i64`.
7. **Git Bash on Windows**: single-quoted `\\` args don't match Windows paths in Python comparisons; normalize argv with `.replace("/", "\\")` and compare `.lower()`.

## 验证方式

Post-run: no `*.id0` sidecars under `bin/*/engine`, no lingering `idalib_server` in tasklist, `server_health` ok before exit, lifecycle exit prints "Stopping the current idalib-mcp process..." once per worker.

## 适用范围

Any ad-hoc `IdaMcpLifecycle` consumer (probe scripts, fallback agents, future debugging sessions). Production pipeline code is unaffected (it already uses the sync-with + async-phase pattern).