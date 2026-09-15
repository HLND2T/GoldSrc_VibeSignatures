---
title: SCR_UpdateScreen_RenderBody locator
type: note
permalink: goldsrc-vibesignatures/locators/scr-updatescreen-renderbody
tags:
  - locator
  - engine
  - func
---

# SCR_UpdateScreen_RenderBody

## Symbol

- **Name**: `SCR_UpdateScreen_RenderBody`
- **Category**: `func`
- **Module**: engine (`hw.dll` / `hw.so`)
- **Producer**: `ida_preprocessor_scripts/find-SCR_UpdateScreen_RenderBody.py`

## Availability

- Declared in 10 engine configs: cof-5936, hl-10210, hl-3248, hl-3266, hl-3329, hl-3647, hl-4554, hl-6153, hl-8684, svencoop-10257.
- Platforms: Windows + Linux (no `platform:` gate in any config).
- Inlined / absent: on Windows it resolves to the full `SCR_UpdateScreen`; on Linux it may resolve to a compiler-split body such as `SCR_UpdateScreen.part.*`. It is a **predecessor-only** symbol — no other finder consumes it, but four GL pipeline entries are mined from its body.

## Predecessors

- None.

## How it is located

- Single string anchor: `FULLMATCH:load failed.\n` via `xref_strings`, owned by the per-frame rendering body after the loading-plaque check in `engine/gl_screen.c SCR_UpdateScreen`.
- The exact-match form (`FULLMATCH:`) is required — the runtime compares the string item text for equality, not substring membership, so longer diagnostics containing the phrase cannot steal the match.
- Emitted fields: `func_name`, `func_sig`, `func_va`, `func_rva`, `func_size`.
- Discovery never uses a byte signature or a stale artifact.

## Pitfalls

- The literal must have a single recoverable owner. If IDA has not promoted the owning body to a function (the `SCR_UpdateScreen.part.*` split case), the xref has no owner and the finder fails rather than guessing.
- Downstream `find-SCR_UpdateScreen_RenderBody-decompiles` runs four separate `found_call` specs against the annotated reference for this body; the reference must be regenerated per platform when the body differs (Windows full vs Linux split).
