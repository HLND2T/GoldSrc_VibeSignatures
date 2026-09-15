---
title: ClientPortalManager_EnableClipPlane locator
type: note
permalink: goldsrc-vibesignatures/locators/clientportalmanager-enableclipplane
tags:
  - locator
  - client
  - func
---

# ClientPortalManager_EnableClipPlane

## Symbol

- **Name**: `ClientPortalManager_EnableClipPlane`
- **Category**: `func`
- **Module**: client (`client.dll` / `client.so`)
- **Producer**: `ida_preprocessor_scripts/find-ClientPortalManager_EnableClipPlane.py`

## Availability

- Declared in 1 config: svencoop-10257 (client module only).
- Platforms: Windows + Linux (no `platform:` gate).
- Inlined / absent: standalone on both builds; no inlining observed.

## Predecessors

- None. `find-ClientPortalManager_EnableClipPlane` has no `expected_input`.

## How it is located

1. Anchor literal: `"Error: Too many clip planes on portal! Maximum: 6 (Too many surfaces on
   brush?)\n"` — owned by exactly one function on the validated 10257 client.
2. Primary path: shared `preprocess_common_skill` with `FULLMATCH:<literal>`, requiring a unique
   function owner (works on Windows, direct literal reference).
3. Linux fallback: `_sven_client_pic_common.preprocess_string_owner_skill_with_pic_fallback` resolves
   the unique exact string item (`exact_string_ea`), then recovers the owner either from
   `XrefsTo` or — because GCC PIC emits `lea edx,[ebp-171AB0h]` with no IDA xref — by deriving the
   `literal - _GLOBAL_OFFSET_TABLE_` displacement from the module's `call __x86.get_pc_thunk.reg;
   add reg, imm32` anchor, byte-searching for that 4-byte disp, and accepting only sites that land
   inside a decoded disp32 operand of a real instruction. Exactly one owner must remain.
4. Artifact fields are `func_name` / `func_va` / `func_rva` / `func_size` / `func_sig`
   (`func_sig_allow_across_function_boundary` added only if the body had to cross a boundary).
5. No caller/callee walk is used for locating; the "sole caller is RenderPortals" relation is a
   validation fact, not part of the anchor chain.

## Pitfalls

- The literal is the only anchor; the function name is never matched textually, and stored research
  addresses (W 0x10050CB0 / L 0xfb97e) are validation evidence only.
- Linux dispatch really is PIC: an `XrefsTo`-only implementation reports zero owners, not a wrong
  one. The GOTOFF scan is what makes this symbol locatable on client.so.
- `EnableClipPlane` is consumed downstream by `find-ClientPortal-offsets-decompiles` as one of the
  three anchors for `ClientPortalSource_mode_offset`: its `call` site in RenderPortals is where the
  `ClientPortalSource` pointer and its `mode` field are read from the stack arguments. A wrong
  EnableClipPlane EA silently poisons that scalar, so the offsets finder requires the YAML's
  `func_name` to match before using `func_va`.
- The clip-plane accumulator caps at six planes per portal; the diagnostic fires per surface, so it
  is a per-portal budget message and not a global GL error — do not confuse it with the
  `GL_ACTIVE_TEXTURE` diagnostics owned by RenderPortals / CreateInvisiblePortalTextures /
  CreateTexture.
