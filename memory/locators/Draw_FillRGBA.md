---
title: Draw_FillRGBA locator
type: note
permalink: goldsrc-vibesignatures/locators/draw-fillrgba
tags:
  - locator
  - engine
  - func
---

# Draw_FillRGBA

## Symbol

- **Name**: `Draw_FillRGBA`
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
- `SCR_UpdateScreen_RenderBody` and `Sys_Error` — declared `expected_input` entry gate; the
  finder returns False if their `func_va` (or the table's `gv_va`) is missing.

## How it is located (HL/CoF)

1. Read `cl_enginefuncs`'s `gv_va` and compute the slot address
   `table + 11 * 4` (`cl_enginefunc_t` field order, `engine/APIProxy.h`).
2. Read the dword at that slot and require it to be a **function start**
   (`ida_funcs.get_func(ptr).start_ea == ptr`); otherwise report
   `Draw_FillRGBA_error = "slot is not a function start"` and write nothing.
3. Validate the blend-factor immediates in that body as an **output validator, not a
   discovery anchor**: the body must contain `GL_SRC_ALPHA` (0x302) and must **not** contain
   `GL_ONE_MINUS_SRC_ALPHA` (0x303). Slot 130 (`Draw_FillRGBABlend`) is the mirror case that
   contains both. A mismatch reports `"blend factor immediates do not match"`.
4. `_inspect_function_via_mcp` emits the function. If that fails (see pitfalls) the finder
   falls back to `CUSTOM_SIG`.

There is no string and no engine caller for this function, so the table slot is the only
deterministic anchor. Discovery never uses a byte pattern or an old YAML.

## Pitfalls

- `_inspect_function_via_mcp` auto-wildcards immediates, so `Draw_FillRGBA` and
  `Draw_FillRGBABlend` (byte-identical apart from `mov edx, 1` vs `mov edx, 303h`) can
  produce **no unique `func_sig`** and the normal write path fails. The fallback rebuilds
  the signature with immediates **pinned** and only relocatable operands
  (`o_mem` / `o_near` / `o_far` / `o_displ`) wildcarded, then binary-searches the shortest
  token prefix (minimum 6 tokens) that matches exactly once in the segment via
  `ida_bytes.find_bytes(..., radix=16)` using the string signature form. If even the pinned
  signature is not unique the symbol is skipped and `debug` prints
  `pinned signature failed (...)`.
- `ida_bytes.find_bytes` wildcard search returns `BADADDR` on the terminating probe;
  uniqueness is decided by "a second match appeared", so the last match must be kept in a
  separate variable.
- SvEngine retains the same slot index but requires forwarding resolution. Checking
  the slot entry as if it were the GL body fails; see the SvEngine section below.
- The GL enum check is a validator, not a discriminator — if a build's body no longer
  mentions the blend factors the finder fails closed rather than falling back to a raw
  table read.

## SvEngine forwarding locator (issue #147)

- Trigger: slot validation fails although the public SDK entry exists.
- Root cause: Windows uses a direct JMP entry; Linux uses an eight-int cdecl wrapper
  with a get-PC thunk. 8948 Linux additionally resolves the body through PLT/GOT.
  The prior "different table layout" explanation was incorrect.
- Dependency: only current-binary `cl_enginefuncs.{platform}.yaml`; no SCR/Sys_Error input.
- Anchor: slot 11, then verified forwarding to the drawing body. Linux must pass
  all eight arguments unchanged and have one non-PIC call. Windows RGBA code may lack
  an IDA function definition; create it only after validating code bounds and behavior.
- Validator: exact ordered GL operations, including texture/blend setup, four vertices,
  state restoration, and actual `glBlendFunc(0x302, 1)` arguments.
  The destination factor is 1 (GL_ONE). Unknown control/data flow fails closed.
- Symbol identity: 8948 ELF preserves the C++ body name `Draw_FillRGBA(int,int,int,int,int,int,int,int)`;
  its `Draw_FillRGBA_I` forwarding entry is not the artifact target. Anonymous peers use
  the source-role identity corroborated by the table, ABI and GL implementation.
- Discovery never uses byte signatures or old YAML. Output generation shares
  `renderer_draw_signatures.CUSTOM_SIG` with HL/CoF and validates uniqueness after discovery.
  Immediates are pinned (including ELF's position-independent GOT delta); absolute and
  instruction-relative address operands are wildcarded. These are per-binary signatures.
- Verified body RVAs: 10257 Windows `0x4f970`, Linux `0x127f70`; 8948 Windows `0x4f6d0`, Linux `0x174a60`.
- Verification: owned IDA sessions on all four exact binaries; formal analyzer runs
  with an initially empty target-output directory prevent skip-existing from masking work.
  Regression tests exercise argument corruption, caller clobbers, multiple calls,
  unsupported flow and stdcall cleanup using synthetic instructions.
- Scope: engine / func, SvEngine 10257 and 8948 on Windows/Linux. HL/CoF discovery is unchanged.
