---
title: D_FillRect locator
type: note
permalink: goldsrc-vibesignatures/locators/d-fillrect
tags:
  - locator
  - engine
  - func
---

# D_FillRect

## Symbol

- **Name**: `D_FillRect`
- **Category**: `func`
- **Module**: engine (`hw.dll` / `hw.so`)
- **Producer**: `ida_preprocessor_scripts/find-renderer-draw-helpers.py`

## Availability

- Declared in 9 engine configs: cof-5936, hl-10210, hl-3248, hl-3266, hl-3329,
  hl-3647, hl-4554, hl-6153, hl-8684.
- Platforms: Windows + Linux (the producer declares no `platform` gating).
- SvEngine 10257/8948 Windows/Linux: issue #148 audit found no standalone body with the legacy two-pointer ABI and source role. The connection-message path instead calls the already-covered `Draw_FillRGBABlend` eight-int interface. Confirmed disposition: not applicable; these four branches are excluded from the candidate gap. Publish the separate `Draw_FillRGBABuf` identity on all four branches.
- This is a replaced interface, not verified ICF folding or demonstrated inlining of `D_FillRect`. The Windows connection-message caller itself is inlined into `SCR_UpdateScreen_RenderBody` on 10257.
- Anchor-shape differs on the HL25 Windows outlier (hl-10210 `hw.dll`), which dropped the `Downloading %s` literal.
- `D_FillRect` is `engine/gl_screen.c D_FillRect`.

## Predecessors

- `SCR_UpdateScreen_RenderBody` — via `expected_input` (used directly by the depth-two
  HL25 fallback).
- `Sys_Error` and `cl_enginefuncs` — also declared as `expected_input` (entry gate; the
  `Sys_Error` VA is loaded and reported in `_debug`).
- All three artifacts must exist and carry `func_va` / `gv_va`, otherwise the finder
  returns False before any walk.

## How it is located

Primary path (literal present):

1. Collect every xref site to the C string `Downloading %s`.
2. For each reference site take its *unit* — the IDA function that owns it, or, when the
   site lives in code IDA never promoted, the terminator-bounded basic block recovered by
   `region_items` (walk back/forward over contiguous `is_code` heads, stopping at
   `retn`/`ret`/`jmp`/`int3` or at the previous/next IDA function boundary).
3. Collect the unit's `call` targets that are function start EAs. Keep a callee `f` only if:
   `f` has **no calls of its own** (zero-call leaf), it has 1 or 2 callers, and *every*
   caller is either the literal's owner unit or a direct callee of
   `SCR_UpdateScreen_RenderBody`.
4. Exactly one survivor becomes `D_FillRect`; otherwise the run logs
   `D_FillRect_candidates` and writes nothing.

Fallback path (HL25 Windows, hl-10210 `hw.dll`, which has no `Downloading %s` literal):

5. Walk `SCR_UpdateScreen_RenderBody`'s direct callees; keep the one whose caller set is
   exactly `{SCR}` (the only-called-by-SCR intermediate), then take that intermediate's
   callee which is called only by it and calls nothing itself. `D_FillRect` therefore sits
   two edges below `SCR_UpdateScreen_RenderBody` (SCR → intermediate → D_FillRect).

The located address is inspected for `func_va` / `func_rva` / `func_size` / `func_sig`
(with an across-function-boundary retry). Discovery never uses a byte pattern or an old
YAML.

## Pitfalls

- HL25 Windows is the documented outlier — on that build the literal does not exist and the
  depth-two shape is the only anchor. The two paths are mutually exclusive
  (`if not cand:`), so a build that has the literal never reaches the fallback.
- The zero-call + "≤2 callers, all in {literal owner} ∪ SCR-callees" gate is what
  disambiguates the real leaf from the many other zero-call leaves in the engine; widening
  either condition reintroduces candidates.
- The literal's owner may be un-promoted code. `region_items` bounds the search with the
  previous/next IDA function and terminates on the first branch/return mnemonic; when
  several un-promoted functions share one gap (old HL builds) that terminator-bounded
  block is the recovery unit, because `ida_funcs.get_func` and `_ensure_function_owner`
  both fail there.
- A unique candidate is mandatory: the finder returns a `_candidates` list and skips the
  write instead of emitting a guess.

## Issue #148: SvEngine binary audit (2026-09-19)

### ABI and identity

All entries below are `engine / func`, x86-32. Windows image base is `0x1d00000`; Linux image base is zero. The buffered body decompiles as `int __cdecl(int x, int y, int w, int h, int r, int g, int b, int a)` in all four IDBs. The inferred `int` return is the remaining vertex count in EAX, not proof of an original source return type. The eight stack arguments and their uses are independently visible in disassembly.

| Build | Buffered-body VA | RVA | func_size | Identity evidence |
| --- | --- | --- | --- | --- |
| svencoop-10257 Windows | `0x1d51600` | `0x51600` | `0x1f1` | Former `NET_DrawRect` artifact; eight integer stack arguments |
| svencoop-8948 Windows | `0x1d513b0` | `0x513b0` | `0x1f4` | Former `NET_DrawRect` artifact; same buffer semantics |
| svencoop-10257 Linux | `0x12a590` | `0x12a590` | `0x25b` | Anonymous body; matches named 8948 peer's control/data flow |
| svencoop-8948 Linux | `0x177080` | `0x177080` | `0x25b` | ELF symbol `_Z16Draw_FillRGBABufiiiiiiii` |

The body tests the used vertex count against 1024 (Linux uses `<= 1023`), flushes with `glDrawArrays(GL_QUADS, 0, count)` when full, and appends four records of six floats (24-byte stride). Fields are `x/y` and normalized `r/g/b/a`; blend is `(GL_SRC_ALPHA, GL_ONE)`. For Windows 10257, `0x1d516d1` reads stack argument 0 as an integer with `fild`, `0x1d516e2` reads argument 1, and `0x1d516ed..0x1d5171c` read arguments 4..7. No `vrect_t*` or color-pointer dereference implements those arguments.

This contradicts treating that address as `D_FillRect(vrect_t*, unsigned char*)`. Neither shared legacy patterns nor matching consumer field values prove `/OPT:ICF`. There is no PDB/map evidence of a second linker identity. The historical ICF claim in [[NET_DrawRect locator]] is withdrawn.

Linux 8948 additionally has `NET_FillRect` at RVA `0x137970`, size `0x5b`, ELF name `_Z12NET_FillRectP7vrect_sPhh`. It decompiles as `int __cdecl(int *rect, unsigned char *color, unsigned char alpha)` and forwards `rect[0..3], color[0..2], alpha` to `Draw_FillRGBABuf`. This three-argument adapter is also incompatible with the two-argument `D_FillRect` handler. No `D_FillRect` or `NET_DrawRect` name occurs in the ELF symbol inventory; symbol absence alone is not used to conclude code absence.

### Original caller has a replacement

The official source `D:/HLND2T_official/engine/gl_screen.c:962-985` defines the two-pointer immediate-mode function, and `SCR_ConnectMsg` calls it at line 1040. In all four SvEngine binaries the connection-message rectangle instead uses the already-covered eight-int `Draw_FillRGBABlend(x, y, w, h, 0, 0, 0, 255)`:

| Build | Connection-message owner RVA / size | Call-site RVA | Blend-body RVA |
| --- | --- | --- | --- |
| 10257 Windows | `SCR_UpdateScreen_RenderBody` `0x5cf20 / 0x4c0` (connection-message code inlined here) | `0x5d2b1` | `0x4faa0` |
| 8948 Windows | `SCR_ConnectMsg` role `0x5d5f0 / 0x184` | `0x5d6d5` | `0x4f800` |
| 10257 Linux | `SCR_ConnectMsg` role `0x136950 / 0x219` | `0x136a63` | `0x1280c0` |
| 8948 Linux | `_Z14SCR_ConnectMsgv` `0x183400 / 0x219` | `0x183513` (PLT call) | `0x174bb0` |

Caller discovery used the exact `scr_connectmsg`, `scr_connectmsg1`, `scr_connectmsg2` literals, their cvar objects/string fields, and current-binary code xrefs; 8948 Linux names independently confirm the roles. The old exact `Downloading %s` anchor is absent in all four; contemporary download strings lead to the GameUI/resource paths. A supplementary bounded GL-semantic scan found sprite/polyblend/particle functions rather than a legacy two-pointer `D_FillRect`. It is corroborating evidence, not an exhaustive proof over arbitrary machine code. No byte signature or LLM result was used to establish these identities.

### Confirmed disposition and consumer consequence

The user confirmed supporting actual engine identities and ABI, then explicitly rejected retaining `NET_DrawRect` as a compatibility alias. `D_FillRect` is not applicable to these four Sven branches because its source-role interface has been replaced. Existing HL/CoF coverage remains applicable. This is neither demonstrated ICF nor a claim that the old function was inlined.

Publish [[Draw_FillRGBABuf]] on Sven 10257/8948 Windows/Linux; remove the old `NET_DrawRect` producer, registrations and two Windows artifacts. No same-RVA `D_FillRect` alias is emitted. `Draw_FillRGBABlend` remains independently covered.

MetaHookSv must query `Draw_FillRGBABuf` for the buffered eight-int hook, skip resolving/installing its two-pointer `D_FillRect` hook on SvEngine, and retain its independent `Draw_FillRGBABlend` hook. This is a catalog-name migration: `NET_DrawRect` no longer resolves in the new catalog. Consumer modifications are outside this repository and were not made here.

### Reproduction and validation

- SHA-256, 10257 Windows: `e3c7f374b70845fb6f45c05906e4b5fe3dc9f394ab37bb653501d3b6a3282596`.
- SHA-256, 8948 Windows: `22fd4d1ad0d3e11a44e7cd5643fe9f6b8ded1234cce819cc242ba5a3fd338ce8`.
- SHA-256, 10257 Linux: `8cead76a51204a4ba1036c85cc2099b7c3542950d924846a9aa2ccf619df7dfd`.
- SHA-256, 8948 Linux: `aad1299bf2389070f9fa27a7413543e028f8b26ef50d7ecfaa11504be26e4b0e`.
- Local evidence: `.candidates/issue148/REPORT.md`, `*.closure.evidence.json`, `*.followup.evidence.json`, `elf-symbols.json`. These ignored working files contain full pseudocode/disassembly, xrefs, survey and health results; this note preserves the reviewable findings in tracked documentation.
- Executed `uv run python .candidates/issue148/probe.py`, `closure.py`, `elf_symbols.py`, and `report.py` (each script under that directory). Final passes exited 0. The probe initially required an isolated `exec(..., {})` namespace fix; the corrected run succeeded.
- Four owned `IdaMcpLifecycle` sessions verified exact input hashes and x86-32 architecture, received final `server_health`, saved `bin/<game>/engine/hw.<dll|so>.i64`, and closed. `REPORT.md` records final IDB UTC mtimes and verifies all four recorded supervisor ports released. No external worker was stopped.
- Task 1 published no artifact and performed no hook/rendering test. The subsequently approved implementation publishes `Draw_FillRGBABuf`; its four real-binary signature validations are recorded in [[Draw_FillRGBABuf]]. No SvEngine `D_FillRect` artifact is produced.
