---
title: issue114 renderer batch anchor research
type: note
permalink: goldsrc-vibesignatures/notes/issue114-renderer-batch-anchor-research
tags:
- issue114
- lifecycle
- mcp
- contextvar
---

# Issue #114 residual notes

The per-symbol anchors from issue #114 (BuildGammaTable, CL_FxBlend, studioapi_StudioSetRenderamt,
ClientPortalManager\*, ClientPortal offsets/textures) now live under `memory/locators/`. What remains
here are the non-locator lessons from that work.

## PR #119 follow-up: reference lifecycle context ownership

- Trigger: reference YAML is written successfully, but automatic MCP shutdown raises a ContextVar token reset error. Also reproduced on Python 3.13, so this is not specific to Python 3.12.
- Root cause: separate `asyncio.to_thread` calls copy separate contexts for lifecycle entry and exit. `WorkerMcpClient` sets its token in the first context and cannot reset it in the second; reset failure precedes client transport/thread cleanup. Repeated startup cancellation could also abandon cleanup, and cleanup errors could mask the original body error.
- Correct approach: enter and exit through one dedicated `copy_context().run`, serially. Shield and drain each lifecycle operation through repeated cancellation, then propagate cancellation. Pass the original exception to exit and retain it if cleanup also fails, reporting the cleanup failure as a note where supported.
- Verification: real ContextVar test doubles cover success, body/startup/cleanup failures, combined body and cleanup failures, and repeated cancellation during startup or cleanup. All 35 reference tests pass on Python 3.12 and 3.13. A real Python 3.12 Sven client RenderPortals export writes its YAML to a temporary path, exits with status 0, and verifies every owned MCP client thread is closed.
- Scope: the synchronous lifecycle bridge in `generate_reference_yaml.py`; MCP SDK async transport ownership remains in its existing owner task. Sharing a Context is not a general replacement for same-task ownership of async transports.

## MCP payload constraint

- RenderPortals' decoded instruction payload exceeds the remote MCP result limit. Embed the same tested Python helper alongside the IDA decoder inside the worker and return only the recovered offsets; do not transfer the full instruction list through `py_eval` results.
