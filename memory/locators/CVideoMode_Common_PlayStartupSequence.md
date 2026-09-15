---
title: CVideoMode_Common_PlayStartupSequence locator
type: note
permalink: goldsrc-vibesignatures/locators/cvideomode-common-playstartupsequence
tags:
  - locator
  - engine
  - func
---

# CVideoMode_Common_PlayStartupSequence

## Symbol

- **Name**: `CVideoMode_Common_PlayStartupSequence`
- **Category**: `func`
- **Module**: engine (`hw.dll` / `hw.so`)
- **Producer**: `ida_preprocessor_scripts/find-CVideoMode_Common_PlayStartupSequence.py`

## Availability

- Declared in 1 engine config: hl-10210 only.
- Platforms: Windows + Linux (met by the hl-10210 `hw.dll` and `hw.so`; artifacts exist for both).
- Inlined / absent: HL25-only symbol. It does not exist on the GDI/GL build families, where the startup graphic is reached from `CVideoMode_Common_Init` instead.

## Predecessors

- `VideoMode_Create.{platform}.yaml` (produced by `find-VideoMode_Create`, consumed via `expected_input`).

## How it is located

A plain string xref cannot select this function: the `-novid` literal has **two** raw owners. The finder therefore walks the VideoMode vtables instead:

1. Load `VideoMode_Create.{platform}.yaml`; require `func_name == "VideoMode_Create"`, a non-empty `func_sig`, and `func_va >= image_base`.
2. Re-verify the artifact's signature with `_find_unique_bytes`; it must still resolve to the recorded `func_va`, otherwise the artifact is treated as stale and the finder aborts.
3. `LOCATE_PY` (32-bit only) builds the writer set: `VideoMode_Create` itself plus its direct callees (only `o_near` `call` targets, capped at `MAX_CREATE_CALLEES = 64`).
4. In each writer it collects vptr stores: `mov [reg(+disp)], imm32` where the immediate is non-zero, not `0xFFFFFFFF`, not inside an executable segment, and the displacement is `<= 0x40` (an object head or embedded member, not a large field).
5. For each distinct vptr value it reads a run of consecutive 4-byte slots (`MAX_VTABLE_SLOTS = 512`), stopping at the first slot that is zero or not a function entry — GoldSrc vtable slots are four bytes, so a valid table is a run of code entries.
6. Independently it collects the owners of the `-novid` literal (all functions referencing it; there are two).
7. A vtable member that is also a `-novid` owner is a candidate. Exactly one unique target VA must survive; zero or several fail closed.
8. The survivor is inspected over MCP and emitted as `func_name`, `func_sig`, `func_va`, `func_rva`, `func_size`. The slot index is deliberately **never** hardcoded — it is reported only in the `debug` trace.

## Pitfalls

- The whole chain depends on `VideoMode_Create`'s artifact signature still resolving uniquely in the current database. A regenerated or drifted `func_sig` aborts the finder before any vtable walk, so a stale predecessor shows up as "no PlayStartupSequence" rather than as a wrong address.
- Do not replace this with a plain `xref_strings: ["FULLMATCH:-novid"]` — the literal has two owners, so that anchor would be non-unique and fail closed (or worse, pick the wrong one if the unicity gate were relaxed).
- The vtable-walk heuristics are bounds, not exact facts: `MAX_VTABLE_SLOTS = 512` and `MAX_CREATE_CALLEES = 64` cap the search, and the slot run stops at the first non-code entry. A build whose vtable layout breaks the "consecutive code entries" assumption (e.g. a data slot in the middle) would truncate the run and lose the candidate.
- The function is short (hl-10210: `0x34` bytes Windows, `0x41` bytes Linux) and consists of the `COM_CheckParm("-novid")` guard plus two registry vtable calls and the tail call into `CVideoMode_Common_DrawStartupGraphic`. A tiny body like this is easy to mistake for a thunk; it is the real function.
- This symbol is the hl-10210 **predecessor** for `CVideoMode_Common_DrawStartupGraphic`, so its artifact is a required dependency of that LLM step.
