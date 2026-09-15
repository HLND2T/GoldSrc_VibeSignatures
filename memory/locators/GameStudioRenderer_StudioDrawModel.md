---
title: GameStudioRenderer_StudioDrawModel locator
type: note
permalink: goldsrc-vibesignatures/locators/gamestudiorenderer-studiodrawmodel
tags:
  - locator
  - client
  - vfunc
---

# GameStudioRenderer_StudioDrawModel

## Symbol

- **Name**: `GameStudioRenderer_StudioDrawModel`
- **Category**: `vfunc`
- **Module**: client (`client.dll` / `client.so`)
- **Producer**: `ida_preprocessor_scripts/find-client-studio-interface.py`

## Availability

- Declared in 14 client configs: cstrike-3248/3647/4554/6153/8684/10210, czero-8684/10210,
  czeror-8684/10210, hl-8684/10210, cof-5936, svencoop-10257.
- Platforms: Windows + Linux only where the client module ships a Linux half — cstrike-10210,
  cstrike-6153, cstrike-8684, hl-10210, hl-8684, svencoop-10257. The other 8 configs
  (cof-5936, cstrike-3248/3647/4554, czero-8684/10210, czeror-8684/10210) declare only
  `module_windows: client.dll`, so those runs are Windows-only.
- Always present as a standalone vtable entry. On short/GCC-split bodies the emitted
  signature is retried across the next function boundary and the artifact carries
  `vfunc_sig_allow_across_function_boundary: true`.

## Predecessors

- `HUD_GetStudioModelInterface.<platform>.yaml` (produced by `find-client-private-predecessors`),
  consumed via `expected_input`.

## How it is located

1. `HUD_GetStudioModelInterface` supplies `func_va` (the client's public studio entry export).
   The finder requires 32-bit x86 and an exact function start; anything else raises.
2. Scan the export body for operands (immediate/memory operands plus one level of pointer
   dereference) that name a mapped address whose dword 0 is `1` (`STUDIO_INTERFACE_VERSION`)
   and whose `+4` / `+8` dwords are executable function starts. That address is the returned
   `r_studio_interface_t`. Exactly one candidate must survive.
3. `thunks = [studio+4, studio+8]` — the DrawModel and DrawPlayer entry points handed to the
   engine. A per-thunk `dispatch()` collects direct `call`/`jmp` targets, indirect slot offsets
   (`o_displ`/`o_phrase`, `offset % 4 == 0` → index `offset / 4`, with GCC PC thunks skipped) and
   every instruction whose operand lands in a writable segment.
4. `shared_objects` = writable-data addresses referenced by **both** thunks: the renderer's
   common `this`. For each such object, candidate vtables come from the object's dword 0 and
   from every xref to the object — `constructor_tables` follows the ABI `this`
   (`ecx` on MSVC, `[esp+n]` on cdecl/GCC) into the constructor call and reads its
   `mov [this], imm` vptr store; direct `mov [obj], imm` stores and register-propagated
   sources are also accepted.
5. For each candidate vtable, consecutive executable dwords are enumerated. The renderer
   vtable is accepted only when **exactly one** entry index matches the DrawModel thunk's
   dispatch — an entry that is a direct callee, or an in-range indirect slot index. That index
   is the symbol's `vfunc_index`.
6. Linux only: if more than one candidate survives (a destructor can reinstall the base vptr on
   the same singleton), Itanium single-inheritance RTTI is used to drop base tables — the
   typeinfo pointer at `table-4`, keeping the child only when `child_type+8 == parent_type`.
7. Exactly one object/vptr/dispatch combination must remain. The entry is inspected with
   `_inspect_function_via_mcp`; the artifact then records `func_va/rva/size`,
   `vtable_name=GameStudioRenderer`, `vfunc_index`, `vfunc_offset = index*4` and
   `vfunc_sig` (with the across-boundary retry noted above).

## Pitfalls

- **Never carry a vfunc index across ABIs.** The proven index is 2 (offset `0x8`) on Windows and
  3 (offset `0xc`) on Linux for every config, because Itanium emits the complete destructor pair.
  The finder re-derives the index from the current binary's dispatch; no index is copied.
- The step-2 table is `r_studio_interface_t` (`common/r_studioint.h`), **not** the C++ vtable.
  The vtable entry is reached only through the shared `this` and its vptr.
- Builds whose virtual calls were devirtualized still resolve: the object is identified by its
  explicit vptr initialization, not by a call site.
- The class is bigger in the CS family (28 Windows / 29 Linux vtable entries) and in SvEngine
  (30 / 32), so a fixed entry count is never assumed.
- The signature is validated by runtime uniqueness; a GCC `.part.N` cold split can leave the
  DrawModel thunk region very short.
