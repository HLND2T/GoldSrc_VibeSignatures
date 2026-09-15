---
title: GL_SetMode_call_qwglCreateContext locator
type: note
permalink: goldsrc-vibesignatures/locators/gl-setmode-call-qwglcreatecontext
tags:
  - locator
  - engine
  - patch
---

# GL_SetMode_call_qwglCreateContext

## Symbol

- **Name**: `GL_SetMode_call_qwglCreateContext`
- **Category**: `patch`
- **Module**: engine (`hw.dll` only)
- **Producer**: `ida_preprocessor_scripts/find-GL_SetMode_call_qwglCreateContext.py`

## Availability

- Declared in 9 engine configs: cof-5936, hl-10210, hl-3248, hl-3266, hl-3329, hl-3647, hl-4554, hl-6153, hl-8684. **Not declared on svencoop-10257.**
- Platforms: Windows-only (`platform: windows`; the skill itself returns `False` for any other platform).
- Inlined / absent: the patch target is a single indirect `call dword ptr [qwglCreateContext]`. On the pre-SDL/WON blobs the slot has no export directory, so the site is found by instruction shape instead of by the exported variable.

## Predecessors

Host artifact, chosen per config (`HOST_FUNC_NAMES` tries `GL_SetModeLegacy` first, then `GL_SetMode`):

- cof-5936, hl-3248, hl-3266, hl-3329, hl-3647, hl-4554: `GL_SetModeLegacy.{platform}.yaml`
- hl-10210: `GL_SetMode.{platform}.yaml` (no pixel-format input — HL25 inlines it)
- hl-6153, hl-8684: `GL_SetMode.{platform}.yaml`

Plus `GL_SelectPixelFormat.{platform}.yaml` (produced by `find-GL_SelectPixelFormat`), declared as `expected_input` on every config except hl-10210. Inside the script a missing/zero pixel-format EA is tolerated: the locator then starts directly in the export/shape modes.

## How it is located

The consumer redirects the indirect call that creates the GL context inside `GL_SetMode` / `GL_SetModeLegacy` (`mov reg,[reg2]; push reg; call dword ptr [qwglCreateContext]`), so the artifact is a patch whose signature starts at the call instruction.

1. The host artifact is loaded and re-verified through `_inspect_function_via_mcp`; the inspected `func_va` must equal the artifact's EA. Its `func_sig_allow_across_function_boundary` flag (if set) is forwarded to the inspection.
2. **Preferred locator (post-selectpf)**: inside the host, find the direct `E8` call to `GL_SelectPixelFormat` (last one wins), then take the first following `FF 15 <slot>` whose slot lies in a data segment that is not `.idata` — this encodes `maindc = GetDC(hwnd); GL_SelectPixelFormat(maindc); baseRC = qwglCreateContext(maindc)`.
3. **Export locator**: resolve the exported `qwglCreateContext` variable by ordinal (`ida_entry`) and require an `FF 15` in the host whose slot equals that export EA.
4. **Shape fallback** (no export directory, e.g. decrypted WON blobs): accept an `FF 15` slot in a data segment when the instruction window (up to 3 instructions back for the `push`, up to 3 more for the `mov`) contains a push of a register that was loaded from a `o_phrase`/`o_displ` memory operand whose base register is not `esp` (4) — i.e. the pmainwindow/HWND-style double dereference. Sites whose slot is in `.idata` are always rejected.
5. Exactly one site must survive; otherwise the run reports `qwglCreateContext call site is not unique in host`.
6. Signature generation: forward-only expansion from the call instruction (6..96 bytes, at most 64 instructions), wildcarding relocatable operands. The `FF 15` slot displacement is an absolute address the loader relocates, so it is **wildcarded** — uniqueness must come from the surrounding instruction stream. The first boundary that yields exactly one match (>= max(6, target instruction length)) wins; there is no backward expansion.
7. The generated signature is re-checked with `_find_unique_bytes`; the returned EA must equal the located site EA, and the site EA must be >= the host entry EA.
8. Emitted patch fields: `patch_name`, `patch_va`, `patch_rva`, `patch_sig`, `patch_sig_disp: 0`.

## Pitfalls

- Wildcarding the `FF 15` displacement is mandatory; leaving it literal makes the signature non-portable because the loader relocates the absolute slot address.
- Two operand-encoding traps in step 4: register-indirect memory without displacement (`mov eax,[edx]`) decodes as **`o_phrase` (type 3)**, not `o_displ`; and register number `0` **is eax**, so `base != 0` must never be used to mean "no base register". The check uses `phrase or reg` and only excludes base register 4 (`esp`).
- `.idata` is excluded by segment **name** (`not startswith('.idata')` and `'idata' not in name`), not by segment type: import slots must never be mistaken for the qwglCreateContext variable.
- On hl-10210 the pixel-format selection is inlined, so no `GL_SelectPixelFormat` artifact is declared and the locator necessarily starts in the export/shape mode.
- The host artifact is required; a missing or non-matching host fails the skill (there is no direct anchor for the call site independent of the host).
