---
title: CVideoMode_OpenGL window locators
type: note
permalink: goldsrc-vibesignatures/locators/cvideo-mode-open-gl-window-locators
tags:
- locator
- engine
- vtable
- vfunc
- gv
---

# CVideoMode_OpenGL window locators

Issue #191. Engine module (`hw.dll` / `hw.so`).

## Symbols

- `CVideoMode_OpenGL_vtable` (`vtable`) — producer `find-CVideoMode_OpenGL`
- `CVideoMode_Common_UpdateWindowPosition` (`vfunc`) — producer `find-CVideoMode_Common_UpdateWindowPosition`
- `VID_UpdateWindowVars` (`func`) plus `window_rect` / `window_center_x` / `window_center_y` (`gv`) — producer `find-VID_UpdateWindowVars`
- `VID_FlipScreen` (`gv`, function pointer) — producer `find-VID_FlipScreen`; hl-* and cof-5936 only

## Anchors

- Vtable: IDA name `??_7CVideoMode_OpenGL@@6B@` / `_ZTV17CVideoMode_OpenGL` (Itanium +8). Slot 0 GetName returns `gl` when the name is not already the OpenGL vtable symbol.
- UpdateWindowPosition: CVideoMode_OpenGL slot 11 (offset 0x2C) when any slot owns `-novid` (HL25 PlayStartupSequence); otherwise slot 10 (offset 0x28). Body must have an in-image direct call.
- VID_UpdateWindowVars: unique in-image callee of UpdateWindowPosition that writes a 16-byte RECT (four consecutive DWORD stores or MOVUPS) plus two ints. Overlapping 16-byte windows pick the lowest base. Center x/y follow first-write order of the two extra ints, not BSS adjacency. SvEngine Linux PIC uses `eax` GOT base (`gv_pic_addend` 0x2ee000 on svencoop-10257).
- VID_FlipScreen: unique writable call/jmp pointer in GL_EndRendering that is isolated from the packed qgl table (cluster gap 0x400). Tiny BLOB/CoF wrappers are a single pointer.

## Coverage

All engine configs. Linux: hl-8684, hl-10210, svencoop-8948, svencoop-10257. VID_FlipScreen omitted on svencoop (it is a function, not a pointer). svencoop-8948 hw.so may be IDB-locked; a copied binary+.i64 is a valid restored_strict identity.
