---
title: Draw_FillRGBABlend locator
type: note
permalink: goldsrc-vibesignatures/locators/draw-fillrgbablend
tags:
  - locator
  - engine
  - func
---

# Draw_FillRGBABlend

## Symbol

- **Name**: `Draw_FillRGBABlend`
- **Category**: `func`
- **Module**: engine (`hw.dll` / `hw.so`)
- **Producer**: `ida_preprocessor_scripts/find-renderer-draw-helpers.py`

## Availability

- Declared in 9 engine configs: cof-5936, hl-10210, hl-3248, hl-3266, hl-3329,
  hl-3647, hl-4554, hl-6153, hl-8684.
- Platforms: Windows + Linux (producer has no `platform` gating).
- SvEngine: svencoop-10257 and svencoop-8948, Windows + Linux, via
  `ida_preprocessor_scripts/find-svengine-fill-rgba.py` (issue #147). Both have
  distinct drawing bodies; neither is absent or inlined. The existing table indices
  remain valid, but their entries forward to the actual GL implementation.

## Predecessors

- `cl_enginefuncs` — `gv_va` supplies the table base.
- `SCR_UpdateScreen_RenderBody` and `Sys_Error` — declared `expected_input` entry gate.

## How it is located (HL/CoF)

1. Slot address = `cl_enginefuncs.gv_va + 130 * 4` (`cl_enginefunc_t` field order,
   `engine/APIProxy.h`).
2. The dword at the slot must be a function start, otherwise
   `Draw_FillRGBABlend_error = "slot is not a function start"` and nothing is written.
3. Blend-factor validator (output check, not discovery anchor): the body must contain
   **both** `GL_SRC_ALPHA` (0x302) and `GL_ONE_MINUS_SRC_ALPHA` (0x303) — this is the
   distinction from `Draw_FillRGBA`, whose body has only `0x302`.
4. Emission via `_inspect_function_via_mcp`, with the `CUSTOM_SIG` pinned-immediate fallback
   when the default signature generator cannot separate it from `Draw_FillRGBA`.

`Draw_FillRGBABlend` has **no engine caller** and no diagnostic string, so the table slot is
the only deterministic anchor. No byte pattern or old YAML participates.

## Pitfalls

- The immediates matter: `_inspect_function_via_mcp` wildcards them, and this function
  differs from `Draw_FillRGBA` only by `mov edx, 303h` vs `mov edx, 1`. Expect the
  pinned-immediate fallback to be the path actually taken, not an exotic branch. The
  fallback keeps immediates fixed and wildcards only `o_mem` / `o_near` / `o_far` /
  `o_displ`, growing from a 6-token seed and checking uniqueness with the string-form
  `ida_bytes.find_bytes`; a non-unique prefix aborts the symbol (`no unique signature`).
- `ida_bytes.find_bytes` returns `BADADDR` on the terminating probe; keep the previous match
  in a separate variable when testing uniqueness.
- SvEngine retains the same slot index but requires forwarding resolution. Checking
  the slot entry as if it were the GL body fails; see the SvEngine section below.
- If the inspected body is not a function start the finder fails closed with `_error`; there
  is no second anchor.

## SvEngine forwarding locator (issue #147)

- Trigger: slot validation fails although the public SDK entry exists.
- Root cause: Windows uses a direct JMP entry; Linux uses an eight-int cdecl wrapper
  with a get-PC thunk. 8948 Linux additionally resolves the body through PLT/GOT.
  The prior "different table layout" explanation was incorrect.
- Dependency: only current-binary `cl_enginefuncs.{platform}.yaml`; no SCR/Sys_Error input.
- Anchor: slot 130, then verified forwarding to the drawing body. Linux must pass
  all eight arguments unchanged and have one non-PIC call. Windows RGBA code may lack
  an IDA function definition; create it only after validating code bounds and behavior.
- Validator: exact ordered GL operations, including texture/blend setup, four vertices,
  state restoration, and actual `glBlendFunc(0x302, 0x303)` arguments.
  The destination factor is 0x303 (GL_ONE_MINUS_SRC_ALPHA). Unknown control/data flow fails closed.
- Symbol identity: 8948 ELF preserves the C++ body name `Draw_FillRGBABlend(int,int,int,int,int,int,int,int)`;
  its `Draw_FillRGBABlend_I` forwarding entry is not the artifact target. Anonymous peers use
  the source-role identity corroborated by the table, ABI and GL implementation.
- Discovery never uses byte signatures or old YAML. Output generation shares
  `renderer_draw_signatures.CUSTOM_SIG` with HL/CoF and validates uniqueness after discovery.
  Immediates are pinned (including ELF's position-independent GOT delta); absolute and
  instruction-relative address operands are wildcarded. These are per-binary signatures.
- Verified body RVAs: 10257 Windows `0x4faa0`, Linux `0x1280c0`; 8948 Windows `0x4f800`, Linux `0x174bb0`.
- Verification: owned IDA sessions on all four exact binaries; formal analyzer runs
  with an initially empty target-output directory prevent skip-existing from masking work.
  Regression tests exercise argument corruption, caller clobbers, multiple calls,
  unsupported flow and stdcall cleanup using synthetic instructions.
- Scope: engine / func, SvEngine 10257 and 8948 on Windows/Linux. HL/CoF discovery is unchanged.
