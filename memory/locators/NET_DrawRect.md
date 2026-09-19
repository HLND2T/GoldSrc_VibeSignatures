---
title: NET_DrawRect locator
type: note
permalink: goldsrc-vibesignatures/locators/net-drawrect
tags:
  - locator
  - engine
  - func
---

# NET_DrawRect

## Symbol

- Historical consumer name: `NET_DrawRect`; retired by issue #148.
- Actual identity: [[Draw_FillRGBABuf]], `engine / func`, eight integer stack arguments.
- Former producer `ida_preprocessor_scripts/find-NET_DrawRect.py` and its two Windows artifacts are removed. There is no compatibility alias.

## Availability

- The user confirmed publishing actual engine functions and explicitly rejected retaining `NET_DrawRect` as an alias when that name is not present.
- `Draw_FillRGBABuf` is now the production identity for svencoop-10257/8948 Windows/Linux. Windows symbol spelling is inferred from the named Linux 8948 peer and matching behavior, not recovered from a Windows PDB.
- The former assertion that Linux lacked the buffered function was incorrect. It lacks the old Windows instruction shape, not the function.
- No evidence establishes `/OPT:ICF` folding with the two-pointer `D_FillRect`. Shared consumer patterns are not proof of two linker identities. See [[D_FillRect locator]] for binary ABI evidence.

## Predecessors

- None.

## How it is located

The retired Windows finder scanned for ordered `mov` / `cmp 0x400` / `cmp 1` instructions and excluded non-thunk internal callees. The loaded global was the vertex-buffer entry count, not screen width. That shape located the right buffered body under the wrong name.

The replacement [[Draw_FillRGBABuf]] finder checks capacity (Windows 1024; Linux 1023), all 13 GL calls and their concrete arguments, eight incoming integer arguments and 24 floating-point buffer stores. Exactly one candidate is required before signature generation.

## Pitfalls

- Consumers must query `Draw_FillRGBABuf` after adopting the new catalog; querying `NET_DrawRect` will no longer resolve.
- The correct handler takes `(int x, int y, int w, int h, int r, int g, int b, int a)`. Do not install a two-pointer `D_FillRect` handler at that address.
- SvEngine connection-message rectangles already call `Draw_FillRGBABlend`; skip the absent legacy `D_FillRect` identity on those branches.
- This file preserves the correction/history only; it is not a published alias or a locator for another function.
