---
title: g_pGameStudioRenderer locator
type: note
permalink: goldsrc-vibesignatures/locators/g-pgamestudiorenderer
tags:
  - locator
  - client
  - gv
---

# g_pGameStudioRenderer

## Symbol

- **Name**: `g_pGameStudioRenderer`
- **Category**: `gv`
- **Module**: client (`client.dll` / `client.so`)
- **Producer**: `ida_preprocessor_scripts/find-client-studio-interface.py`

## Availability

- Declared in 14 client configs: cstrike-3248/3647/4554/6153/8684/10210, czero-8684/10210,
  czeror-8684/10210, hl-8684/10210, cof-5936, svencoop-10257.
- Platforms: Windows + Linux only where the client module ships a Linux half — cstrike-10210,
  cstrike-6153, cstrike-8684, hl-10210, hl-8684, svencoop-10257. The other 8 configs
  (cof-5936, cstrike-3248/3647/4554, czero-8684/10210, czeror-8684/10210) declare only
  `module_windows: client.dll`, so those runs are Windows-only.
- Always present. Its anchor (`ClientStudioDrawPlayer`, i.e. `studio+8`) is emitted as a
  signature; on bodies that need it the artifact carries
  `gv_sig_allow_across_function_boundary: true`.

## Predecessors

- `HUD_GetStudioModelInterface.<platform>.yaml` (produced by `find-client-private-predecessors`),
  consumed via `expected_input`.

## How it is located

1. Same root as the renderer vtable: the exported `HUD_GetStudioModelInterface` body yields the
   returned `r_studio_interface_t` (`version == 1`), whose `[studio+4, studio+8]` thunks are the
   DrawModel and DrawPlayer entry points.
2. The writable-data addresses referenced by **both** thunks are intersected; exactly one
   surviving object is the renderer `this`. The object's dword 0 is its vptr — the reason the
   same address simultaneously proves the vtable and this global.
3. `gv_va`/`gv_rva` = that object address. `gv_sig` is the **`ClientStudioDrawPlayer` thunk's**
   function signature (`studio+8`) and `gv_sig_va` its VA; when that thunk has no clean
   signature the inspection is retried across the function boundary.
4. The access instruction inside that thunk which names the object supplies
   `gv_inst_offset` (instruction EA − thunk EA), `gv_inst_length` (instruction size) and
   `gv_inst_disp` (byte offset of the 4-byte operand displacement inside the instruction).
5. `gv_resolution_fields_via_mcp` then fills the platform metadata (`gv_pic_addend`,
   `gv_address_offset` when applicable) so the runtime address is reconstructed from
   `gv_sig_va + gv_inst_offset + gv_inst_disp` (+ PIC addend) under loader relocation.

## Pitfalls

- The name reads like a pointer global, but the emitted `gv_va` is the address the returned
  thunks reference directly (an immediate operand, e.g. `mov ecx, offset <object>` on Windows,
  `mov dword ptr [esp], offset <object>` on SvEngine Linux) — it is the renderer singleton the
  thunks pass as `this`, and the location holding the vptr at offset 0.
- Resolution is code-relative: `gv_sig` is the thunk, and the address is recovered from the
  instruction anchor. Regenerating the thunk signature while keeping stale
  `gv_inst_offset/length/disp` breaks runtime resolution.
- `gv_inst_disp` is a byte offset inside the instruction, not a struct-member offset
  (observed `0x1` for `B9 imm32` on Windows, `0x3` for `C7 04 24 imm32` on Linux, `0x2` for the
  SvEngine two-byte form).
- Preserve `gv_pic_addend` when emitted (SvEngine Linux): the embedded dword is not always the
  absolute address and no loader relocation applies to the GOTOFF displacement.
- Do not confuse this global with `GameStudioRenderer_vtable`; they share an address in some
  relationships but the vtable artifact records the table VA, not the object VA.
