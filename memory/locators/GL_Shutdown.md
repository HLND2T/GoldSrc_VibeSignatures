---
title: GL_Shutdown locator
type: note
permalink: goldsrc-vibesignatures/locators/gl-shutdown
tags:
  - locator
  - engine
  - func
---

# GL_Shutdown

## Symbol

- **Name**: `GL_Shutdown`
- **Category**: `func`
- **Module**: engine (`hw.dll` / `hw.so`)
- **Producer**: `ida_preprocessor_scripts/find-GL_Shutdown.py`

## Availability

- Declared in 10 engine configs: cof-5936, hl-10210, hl-3248, hl-3266, hl-3329, hl-3647, hl-4554, hl-6153, hl-8684, svencoop-10257.
- Platforms: registered ungated in eight configs; **Windows-gated** in hl-10210 and svencoop-10257. The skill accepts only `windows`/`linux` and requires `pointer_size == 4`.
- Inlined / absent:
  - `hl-10210/linux`: the body is a **395-byte byte-identical clone of `FreeFBOObjects`** (compiler cloning) — no unique `func_sig` can exist, so that branch is excluded.
  - `svencoop-10257/linux`: `Sys_Shutdown` has no `GL_Shutdown` call at all.
  - `svencoop-10257/windows`: `GL_Shutdown` is a 5-byte `jmp` thunk; its signature needs branch displacements pinned (acceptable because the per-version rel32 is fixed at link time).
  - In practice only hl-8684/linux produced a Linux artifact among the ungated configs.

## Predecessors

- None.

## How it is located

`GL_Shutdown` (`engine/gl_vidnt.c`, Windows) owns no diagnostic string, so the anchor is the `TRACESHUTDOWN` literal `Sys_Shutdown()` from `sys_dll2.cpp`.

1. **Anchor scan** — the exact C literal plus trailing NUL is byte-scanned across readable segments (segment permission bit 4, not section names; on the old Windows `hw.dll` family the literal lives in writable `.data`). A match only counts when it is preceded by a NUL byte or starts the segment, which reproduces `FULLMATCH` semantics. Owners are collected from `DataRefsTo`. The shared `strings.setup()` list is deliberately **not** used, because rebuilding IDB-wide string state leaks into later skills.
2. The scan set is the owners plus their direct callees (CoF routes the shutdown call through `Sys_Shutdown` one level deeper). At most two owners normally exist: `Sys_InitGame`, which references the literal as the `TraceInit` shutdown pair, and the real shutdown path, which references it through `TraceShutdown`.
3. **Call-shape discrimination** — inside the scan set, every direct `E8` call whose target is a function start no larger than `MAX_TARGET_SIZE` (0x200) is scored over a backwards window of at most 16 instructions that **stops at the preceding `call`/`jmp`**. A candidate qualifies with at least three distinct absolute-global argument sources (`mov reg,[abs]` or `push [abs]`), at least three argument writes (`push reg`, `push [reg]`, `push [abs]`, or `mov [esp+X],reg`), and the pmainwindow-style double dereference (a register loaded from an absolute global is later re-read through `[reg]`). This separates `GL_Shutdown(*pmainwindow, maindc, baseRC)` from `TraceShutdown`/`TraceInit` wrappers, which only push immediate offsets.
4. Exactly one distinct target must survive, otherwise the skill reports `GL_Shutdown call shape is not unique`.
5. **Signature** — forward-only expansion from the function start with immediates pinned and relocatable operands wildcarded, retried in two passes: first with branches wildcarded, then with branch displacements pinned (needed so the SvEngine 5-byte `jmp` thunk still yields a unique signature). The first token boundary with >= 6 bytes that is unique wins. The function is then `set_name`-ed and verified through `_inspect_function_via_mcp`, with an `allow_across_function_boundary` retry and a `_find_unique_bytes` fallback on the py_eval-generated signature.
6. Emitted fields: `func_name`, `func_sig`, `func_va`, `func_rva`, `func_size` (plus `func_sig_allow_across_function_boundary` when the retry path was used).

## Pitfalls

- The backwards window **must** end at the preceding `call`/`jmp`; otherwise a trailing tail-chunk call reuses an earlier call's argument setup and a wrapper call qualifies.
- The argument shape must count `push [abs]` (`FF 35`) and `push [reg]` (`FF 30`); counting only plain `push reg` makes the HL25/SvEngine call form fail.
- Operand encoding: register-indirect memory without displacement decodes as `o_phrase`, and `mov [esp+X],reg` may also be `o_phrase` — handle both, and never treat register `0` as "no base register" (`0` is eax).
- The `hl-10210/linux` FreeFBOObjects clone means that branch can never produce a unique signature; it is excluded rather than worked around. Same pattern for `svencoop-10257/linux` (no call at all).
- The py_eval scoping rules apply to this script's embedded code: helpers must stay at top level and `globals().update(locals())` must run after all top-level defs, since functions cannot see module constants or each other otherwise.
