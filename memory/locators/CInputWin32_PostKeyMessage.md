---
title: CInputWin32_PostKeyMessage
type: note
permalink: goldsrc-vibesignatures/locators/cinput-win32-post-key-message
tags:
- locator
- vgui2
- func
- issue-320
---

# CInputWin32_PostKeyMessage

## Symbol

- **Name**: `CInputWin32_PostKeyMessage` (config/artifact stem); payload `func_name: CInputWin32::PostKeyMessage(KeyValues*)`
- **Category**: `func`
- **Module**: vgui2 (`vgui2.dll` / `vgui2.so`)
- **Producer**: `ida_preprocessor_scripts/find-CInputWin32_PostKeyMessage.py`
- MetaHookSv lookup name `g_pfnCWin32Input_PostKeyMessage` (`Plugins/VGUI2Extension/InputWin32.cpp`) is a local field name; the real class is `CInputWin32` (Linux `_ZN11CInputWin3214PostKeyMessageEP9KeyValues`). The method returns `void`; MetaHookSv's `bool` typedef is the consumer's own ABI choice.

## Availability

- 11 vgui2 configs: hl-3248/3266/3329/3647/4554/6153/8684/10210, cof-5936, svencoop-8948/10257. 15 binaries (Windows on all 11; Linux on hl-8684, hl-10210, svencoop-8948, svencoop-10257).
- CS/CZ/CZDS configs declare no vgui2 module — not applicable.
- ABI: Windows `__thiscall` (`ret 4`); Linux cdecl `(this, message)`.
- GCC inlines PostKeyMessage into all four callers; the out-of-line body survives with **zero** direct callers. MSVC keeps four direct `call`s.

## How it is located

Source: `D:/HLND2T_official/vgui2/src/InputWin32.cpp:1221-1293`. PostKeyMessage's only callers are `InternalKeyCodePressed/Typed`, `InternalKeyTyped`, `InternalKeyCodeReleased`, each doing `PostKeyMessage(new KeyValues("<literal>", ...))`; the body posts via `ivgui()->PostMessage(focus, message, NULL)` or calls `message->deleteThis()`.

1. Raw NUL-delimited scan (no `strings.setup`, see [[Shared IDB string-list pollution by custom finders]]) for `KeyCodePressed`, `KeyCodeTyped`, `KeyTyped`, `KeyCodeReleased`: each exactly one (literal, owning function) pair; four distinct owners.
2. In each owner, the KeyValues construction with that literal as name identifies the message value (MSVC: thiscall result; GCC: first cdecl arg).
3. **Windows**: in each owner exactly one direct call has `ecx == this`, its only stack argument is the message (or the NULL alternative of a failed `new`), and the callee's `ret` is exactly 4. All four owners must agree. The `ret 4` filter is required: cof-5936 `InternalKeyCodePressed` follows with a zero-argument thiscall (`UpdateToggleButtonState`) whose stale stack slot still holds the message.
4. **Linux**: each owner's inlined dispatch fixes one `(g_pIVgui receiver, PostMessage slot)` and one `deleteThis` slot (current-binary values, not hardcoded). Scan all functions referencing the `g_pIVgui` storage (direct or through a `.got` slot), minus the four owners: exactly one must post-or-delete its own parameter 1 through those same slots.
5. Windows also re-verifies the callee posts-or-deletes parameter 1. `write_function` emits a unique `func_sig`; ambiguity anywhere fails closed.

MetaHookSv's byte pattern (`68 ?? 68 <str> 8B C8`, first `E8` after `push eax`) is Windows-only and cannot work on Linux, where the call is inlined. ELF symbols are validation evidence only (svencoop-10257 `vgui2.so` is stripped).

## Verified results (2026-10-02)

| tag / platform | RVA | size |
|---|---:|---:|
| hl-3248/3266/3329/3647 win | 0x72a0 | 0x59 |
| hl-4554 win | 0x74b0 | 0x59 |
| hl-6153 / hl-8684 win | 0x3c10 | 0x59 |
| hl-10210 win | 0x3f30 | 0x97 |
| cof-5936 win | 0xa351 | 0x81 |
| svencoop-8948 win | 0x8730 | 0x6c |
| svencoop-10257 win | 0x8900 | 0x6c |
| hl-8684 linux | 0x25100 | 0x98 |
| hl-10210 linux | 0x20bc0 | 0x10b |
| svencoop-8948 linux | 0x25c80 | 0xeb |
| svencoop-10257 linux | 0x1bb10 | 0xeb |

- Every Windows target has exactly the four Internal* functions as code callers. hl-8684/hl-10210/svencoop-8948 Linux match `nm -C` exactly; svencoop-10257 Linux (stripped) matches svencoop-8948 in size and signature prefix.
- Linux scan sizes: 15–18 g_pIVgui users per binary, one candidate each.
- hl-3248..hl-8684 Windows bodies (0x59) need `func_sig_allow_across_function_boundary` (256-token signature, first unique at token 44); all 15 signatures match exactly once in the raw files.
- Validation: `ida_analyze_bin.py -allgamever -modules vgui2 -skill find-CInputWin32_PostKeyMessage -platform windows,linux` → 15 succeeded, 0 failed; warm strict/no-save IDBs. Unit 1343 OK (5 skipped), repository-contract 15 OK, format check and `git diff --cached --check` clean.

## Relations

- relates_to [[VGUI PaintTraverse Anchor Chain]]
- relates_to [[MetaHookSv byte patterns are hints, not portable anchors]]
- relates_to [[idalib-mcp]]
