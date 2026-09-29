---
title: Client IN_Accumulate mouse guards (#295)
type: note
permalink: goldsrc-vibesignatures/locators/client-in-accumulate-mouse-guards-295
tags:
- locator
- client
- gv
- issue-295
---

# Client IN_Accumulate mouse guards (#295)

## Trigger

MetaHookSv called the target `g_iVisibleMouse`, but shipped CS/CZ `IN_Accumulate` reads `iMouseInUse`; HL/CoF read both. The CS/CZ Linux ELF symbol table can contain a 4-byte `g_iVisibleMouse` object that this callback does not read and whose writer does not satisfy the viewport predicate, so symbol presence alone does not establish the consumer's guard.

## Root cause and scope

The generic MetaHookSv fallback follows a global read in `IN_Accumulate`, while the Sven-only #281 locator identifies the viewport cursor global through its writer. These are distinct variables in several client families. This locator covers 13 configured client gamevers: cstrike-3248/3647/4554/6153/8684/10210, czero-8684/10210, czeror-8684/10210, hl-8684/10210, cof-5936. There are 22 configured Windows/Linux binary pairs; CoF and cstrike-3248/3647/4554 are Windows only. Sven 8948/10257 stay under #281.

## Correct locator

`find-IN_Accumulate.py` recovers the exact client export; the old encrypted Windows CS blobs use the verified 43-entry `cldll_func_t` table, slot 13, with exact binary identity and function-start checks. `find-client-mouse-guards.py` revalidates this function artifact against the current IDB and decodes early-return zero guards. The first camera guard is accepted as `iMouseInUse` only with writable data and current-binary 0/1 camera-state writes. For HL/CoF the other guard is accepted as `g_iVisibleMouse` only when a writer stores both 0 and 1 and calls `vgui::App::getInstance()`. Old decrypted blobs may contain a decoded camera write outside an IDA function; verify a local immediate or register constant at a direct code xref instead of inventing a function. Zero/multiple qualifying candidates fail closed. Output signatures are generated only after the current instruction operand has been selected.

The official source supports the roles: `cl_dll/inputw32.cpp` defines `g_iVisibleMouse` and `IN_Accumulate` checks `iMouseInUse`; `cl_dll/in_camera.cpp` defines/writes `iMouseInUse`; `cl_dll/vgui_TeamFortressViewport.cpp` writes cursor state and calls the VGUI App accessor. Shipped HL/CoF binary guards establish their additional read even where source revisions differ. Windows uses absolute x86 operands; current ELF builds use their own absolute relocation/data references. Do not carry an address or byte offset between builds.

## Verification

The exact-node analyzer batch selected both producer nodes on all 22 binaries: `uv run python ida_analyze_bin.py -batch_selection /tmp/issue-295-batch-selection.json -batch_diagnostics /tmp/issue-295-batch-diagnostics` yielded 44 successful nodes, 0 failed, 0 skipped. The 49 artifacts contain 22 `IN_Accumulate` functions, 22 `iMouseInUse` globals, and five HL/CoF `g_iVisibleMouse` globals; their VA/RVA and predecessor signature relationships were audited. All 20 Linux artifact addresses match the exact named ELF symbols in `readelf -Ws`. Current coverage is declared in production configs and artifacts.

## Applicable range

Client module only. CS/CZ produce `iMouseInUse`; HL/CoF produce both globals. No Sven changes or HL gamevers without configured clients.
