---
title: VGui_ViewportPaintBackground locator
type: note
permalink: goldsrc-vibesignatures/locators/vgui-viewportpaintbackground
tags:
  - locator
  - engine
  - func
---

# VGui_ViewportPaintBackground

## Symbol

- **Name**: `VGui_ViewportPaintBackground`
- **Category**: `func`
- **Module**: engine (`hw.dll` / `hw.so`)
- **Producer**: `ida_preprocessor_scripts/find-VGui_ViewportPaintBackground.py` (thin wrapper over `ida_preprocessor_scripts/_engine_public_callback_common.py`)

## Availability

- Declared in 10 engine configs: cof-5936, hl-10210, hl-3248, hl-3266, hl-3329, hl-3647, hl-4554, hl-6153, hl-8684, svencoop-10257.
- Platforms: Windows + Linux.
- Inlined / absent: none observed; it is a `cl_enginefunc_t` entry. hl-10210 Windows body is 0x199 bytes.

## Predecessors

- `cl_enginefuncs` (consumed via `expected_input`), produced by `find-ClientDLL_HudInit-decompiles` (HL/CoF) or `find-ClientDLL_Init-pic-enginefuncs` (SvEngine Linux).

## How it is located

1. Load `cl_enginefuncs.{platform}.yaml`, read `gv_va`, compute `entry = gv_va + 78 * 4` — SDK `cl_enginefunc_t` slot 78 is `VGui_ViewportPaintBackground`.
2. `target = ida_bytes.get_dword(entry)`, then `unwrap(target)` follows a single-instruction `jmp rel32` or a ≤16-instruction straight-line wrapper with exactly one non-PC-thunk `call rel32` (see `CL_CreateVisibleEntity` for the exact unwrap rules; the helper is shared). Cycles, unexpected mnemonics, non-near call operands and non-register/stack `mov` destinations abort the walk.
3. Validate: 32-bit, executable segment, `ida_funcs.get_func(target).start_ea == target`.
4. Emit `func_name`, `func_va`, `func_rva`, `func_size`, `func_sig`; retry with `func_sig_allow_across_function_boundary: true` when strict entry inspection fails.

## Pitfalls

- This function is the *viewport callback*, i.e. the engine's `VGui` paint hook. It internally computes the refdef and calls `V_RenderView`, which is why it, and not a name string, is the deterministic predecessor for `V_RenderView`.
- SvEngine's `cl_enginefuncs` layout is different from HL's (see the Renderer-draw note: slot 11 is not a function start there), so do not reuse HL slot indices for other slots in that table. Slot 78 is validated as a function entry on the configs where this skill is registered.
- The unwrap only follows side-effect-free straight-line shims; a wrapper that is not straight-line is accepted as-is (the shim itself is then the artifact).
- `func_sig_allow_across_function_boundary` is added only when the strict inspection fails; the field's presence therefore differs between configs.
