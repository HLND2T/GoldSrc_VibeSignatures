---
title: GameUI Menu private symbols
type: note
permalink: goldsrc-vibesignatures/locators/game-ui-menu-private-symbols
---

# GameUI Menu private symbols

## Overview

Recover `vgui2::Menu`'s primary vtable, `vgui2::Menu::MakeItemsVisibleInScrollRange()` and the four-byte `vgui2::Menu.m_pScroller` pointer in the configured GameUI binaries. `vgui2::Menu::PerformLayout()` is a retained predecessor artifact.

## Responsibilities

- Replace downstream Menu table scanning, the 175..181 slot window, and ScrollBar-offset disassembly with named artifacts.
- Keep discovery current-binary: RTTI table, inherited PerformLayout slot, then annotated LLM instruction selection with ordinary x86/vtable/signature validation.

## Involved Files & Symbols

- `ida_preprocessor_scripts/find-GameUI-Menu.py`: Menu RTTI table and inherited PerformLayout.
- `ida_preprocessor_scripts/find-GameUI-Menu-PerformLayout-decompiles.py`: grouped vcall/member extraction from the same predecessor.
- `ida_preprocessor_scripts/references/hl-10210/gameui/vgui2_Menu_PerformLayout.{windows,linux}.yaml`: generated reference context, annotated in both disassembly and pseudocode.
- Eleven `configs/<tag>.yaml` gameui modules; artifact stems `vgui2_Menu_vtable`, `vgui2_Menu_PerformLayout`, `vgui2_Menu_MakeItemsVisibleInScrollRange`, `vgui2_Menu_m_pScroller`.
- Source: `D:/HLND2T_official/vgui2/controls/Menu.cpp`, PerformLayout:473, MakeItemsVisibleInScrollRange:713, LayoutMenuBorder:751; `public/vgui_controls/Menu.h`.

## Architecture

1. Find the primary `vgui2::Menu` RTTI table (`??_7Menu@vgui2@@6B@` / `_ZTVN5vgui24MenuE`).
2. Read the current `GameUI_PropertySheet_PerformLayout` slot. Both classes override Panel::PerformLayout; INHERIT_VFUNCS reads that slot from the current Menu table and validates its actual body.
3. PerformLayout compares sorted-item count to the visible-line limit. Its scrolling branch adds the scrollbar then calls MakeItemsVisibleInScrollRange on the Menu receiver; both branches continue through LayoutMenuBorder.
4. A grouped LLM call selects that vcall and actual four-byte loads of the scroller member. Validate instruction ownership/displacements, the current table entry, and unique signatures. No prior artifact signature, fixed index, member offset or version-number rule locates the targets.
5. LayoutMenuBorder is corroborating semantics, not an extra requested public output. Its guarded Linux devirtualization and inlined `MenuBorder` lookup remain visible in the reference.

## Dependencies

- Existing `find-GameUI-private-symbols` publishes the PropertySheet predecessor.
- Shared `preprocess_vtable_via_mcp`, `preprocess_common_skill`, INHERIT_VFUNCS, LLM_DECOMPILE and category writers.
- [[idalib-mcp]] owned sessions and [[reference-yaml-generation]].

## Notes

### ABI and layout differences

Trigger: porting MetaHookSv's Menu TODOs or comparing the newer SDK Menu.cpp to the binary. Root constraint: the newer `D:/MetaHookSv/include/vgui_controls/Menu.cpp` declares a two-argument overload, but the official GoldSrc source, Linux symbol/prototype, and Windows call sites all establish **MakeItemsVisibleInScrollRange() with no explicit arguments**. Use the target ABI, not the newer SDK prototype. Independent body inspection confirms ScrollBar::GetValue feeds loops hiding preceding/following items and showing the visible range.

Observed facts below are validation evidence, never finder constants. Module is always gameui; Windows image base is `0x10000000`, Linux base is zero.

| Tag/platform | PerformLayout slot | MakeItems slot | m_pScroller | MakeItems RVA |
|---|---:|---:|---:|---:|
| cof-5936 Windows | 111 | 180 | 0x88 | 0x96611 |
| hl-3248 Windows | 111 | 177 | 0x88 | 0x6bdd0 |
| hl-3266 / hl-3329 Windows | 111 | 177 | 0x88 | 0x984c0 |
| hl-3647 Windows | 111 | 179 | 0x88 | 0x6b800 |
| hl-4554 Windows | 111 | 180 | 0x88 | 0x6dac0 |
| hl-6153 Windows | 111 | 180 | 0x88 | 0x6b350 |
| hl-8684 Windows / Linux | 111 / 112 | 180 / 181 | 0x88 | 0x6b4c0 / 0x122c50 |
| hl-10210 Windows / Linux | 111 / 112 | 181 / 182 | 0x90 | 0x755f0 / 0xeb650 |
| svencoop-8948 Windows / Linux | 111 / 112 | 180 / 181 | 0x88 | 0x3f1a0 / 0xb7520 |
| svencoop-10257 Windows / Linux | 111 / 112 | 180 / 181 | 0x88 | 0x3f7a0 / 0x9f770 |

Coverage is 11 tags / 15 PE32-I386 or ELF32-I386 binaries. CS/CZ/CZDS configs declare no separate GameUI; undeclared Linux combinations are not forced to match. No Menu target is missing from a configured binary. PropertySheet `_pageTabs` remains a separate, unimplemented downstream layout dependency.

### Reusable pitfalls

- Early unoptimized binaries have non-unique default short function prefixes. Enable the existing extended signature budget for output validation; discovery still uses the inherited slot and LLM-selected instruction. Do not replace this with version-specific bytes/slots.
- LLM result identities must use the exact requested finder names. Reference annotations explicitly require `func_name=vgui2_Menu_MakeItemsVisibleInScrollRange`, `struct_name=vgui2_Menu`, `member_name=m_pScroller`; writers publish the true `vgui2::Menu` C++ identities afterwards. Mixed namespace/stem annotations caused semantic-schema rejection in the first smoke run; do not relax validation to accept mismatched names.
- Instruction and vtable checks establish structural validity, not semantic truth on their own. Preserve the scrolling-branch reference annotations and inspect source behavior when changing them; do not infer identity from a slot number alone.

### Reference provenance and lifecycle

Canonical references were generated with `generate_reference_yaml.py` on hl-10210 for both platforms, after owned-IDB reconstruction. Windows has a partial Menu/ScrollBar type model and named verified callees; unverified fields remain neutral. Linux retains existing source-like symbols/types and guarded devirtualization. The different newer SDK ABI is explicitly documented.

- Windows binary SHA-256: `b9b8c0c36bd19681627001c06ce2a15496da06b72315d561a12a3964e0265811`; PerformLayout VA `0x10076a40`; member load reference `0x10076e41`; target vcall `0x10076a68`.
- Linux binary SHA-256: `6473a660d1f10c0de35c80fd328110266bb5eeb5d1d7eb07697a4867eda2ce0a`; PerformLayout VA `0xeeb80`; member load reference `0xeebac`; target vcall `0xeebcf`.
- Exact IDBs: `bin/hl-10210/gameui/GameUI.dll.i64` and `gameui.so.i64`. Survey/health verified paths, hashes, x86 and image bases before mutation; both reconstruction lifecycles reported `Saved IDB` and `PORT_RELEASED True`. Recorded post-reconstruction mtimes (Unix): `1790857119.7529001`, `1790857157.2466643`; reference generation subsequently saved them through its own owned lifecycle. No binary bytes were patched.
- Production analysis used strict restored/no-save owned workers. Temporary probes, diagnostic logs and the full per-binary hash/audit table are outside the repository under the task's temp directory.

### Verification (2026-10-01)

- Both finder phases ran with `-allgamever -modules gameui -platform windows,linux`.
- Final forced 30-node selection: `analysis-batch-20261001T204450-a1589646b3224dd28cb4e817e4e246c3`, all 15 binary tasks succeeded. The batch worker forces selected nodes and includes analyzer artifact validation.
- 60 artifacts: 45 requested records plus 15 PerformLayout predecessors. Independent artifact audit checked current table entries equal method VAs, inherited layout slots, index-times-four arithmetic, image-base/RVA arithmetic, true identities and four-byte pointer size.
- Independent read-only review found no confirmed functional defect; config parent struct identity was aligned with the existing qualified-name convention. No shared helper/schema change or implementation-mirroring test was introduced.

## Callers

MetaHookSv `Plugins/VGUI2Extension/GameUI.cpp` can consume the named method and member to remove its Menu slot scan. The vtable is also published as requested. Consumer migration and game-runtime validation are separate work.

Final repository gates: `uv run python tests/run_test_suite.py unit -b --durations 30` — 1332 tests OK (5 skipped); `repository-contract` — 15 tests OK after adding the new artifacts to Git's tracked inventory; `uv run python format_repo_files.py --check` — exit 0. The earlier contract runs correctly rejected missing/untracked newly declared artifacts; no contract was weakened. `git diff --cached --check` found two generated blank lines with spaces, which were trimmed without changing reference semantics.
