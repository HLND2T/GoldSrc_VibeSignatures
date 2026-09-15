---
title: ClientPortal_CreateTexture locator
type: note
permalink: goldsrc-vibesignatures/locators/clientportal-createtexture
tags:
  - locator
  - client
  - func
---

# ClientPortal_CreateTexture

## Symbol

- **Name**: `ClientPortal_CreateTexture`
- **Category**: `func`
- **Module**: client (`client.so`)
- **Producer**: `ida_preprocessor_scripts/find-ClientPortal_CreateTexture.py`

## Availability

- Declared in 1 config: svencoop-10257, with `platform: linux` on both the finder and the symbol
  declaration.
- Platforms: **Linux-only**. The finder's first statement is `if platform != "linux": return False`,
  so no Windows artifact is ever emitted.
- Inlined / absent: on Windows the equivalent body is **inlined into `ClientPortalManager::RenderPortals`**
  (the offsets finder proves the Windows texture fields directly from RenderPortals' GL block);
  this symbol therefore exists as a standalone entry only on the SvEngine Linux build, where the GL
  initializer was outlined (0xF42F8 on 10257).

## Predecessors

- None. `find-ClientPortal_CreateTexture` has no `expected_input`.
- It is itself the predecessor of `find-ClientPortal-texture-decompiles`.

## How it is located

1. The finder delegates to
   `_sven_client_pic_common.preprocess_string_owner_skill_with_pic_fallback` with the exact literal
   `"Invalid GL_ACTIVE_TEXTURE, unable to reset. Couldn't create texture for PortalSource.\n"`
   (note: *PortalSource*, not "invisible texture" — the two diagnostics differ).
2. Primary path: shared `preprocess_common_skill` `FULLMATCH:<literal>` xref discovery with a unique
   owner requirement.
3. SvEngine Linux fallback: the unique exact string item is resolved by `exact_string_ea`, then the
   owner is taken from `XrefsTo`, or — since GCC PIC emits a `lea reg,[gotreg+disp32]` with no IDA
   xref — by deriving `literal - _GLOBAL_OFFSET_TABLE_` from the module's
   `call __x86.get_pc_thunk.reg; add reg, imm32` anchor, byte-searching that 4-byte displacement in
   executable segments, and keeping only sites that fall inside a decoded disp32 operand. Exactly
   one owner must remain, or the helper fails closed.
4. Artifact fields: `func_name` / `func_va` / `func_rva` / `func_size` / `func_sig`
   (plus `func_sig_allow_across_function_boundary` if needed).

## Pitfalls

- Windows coverage is intentionally absent: this is the only symbol in the portal family with a
  `platform: linux` gate. Do not expect `ClientPortal_CreateTexture.windows.yaml`.
- The Linux initializer receives the target `ClientPortal` in **EAX** (the `this` register for an
  outlined member); `find-ClientPortal-texture-decompiles` depends on that register provenance, via
  `_portal_layout.linux_texture_offsets` / `_entry_register`, when it recovers 196/200/204.
- The literal's `PortalSource` wording is load-bearing — the invisible-texture diagnostic is a
  different sentence owned by a different function.
- Linux PLT symbol names may carry a leading dot (`.glGenTextures`); the shared decoder normalizes it
  only after confirming the target lies in `.plt` and matches an import name.
- Research address 0xF42F8 for the initializer is evidence only.
