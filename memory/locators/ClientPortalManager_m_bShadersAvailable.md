---
title: ClientPortalManager_m_bShadersAvailable locator
type: note
permalink: goldsrc-vibesignatures/locators/clientportalmanager-shaders-available
tags:
  - locator
  - client
  - structmember
  - issue-254
---

# ClientPortalManager.m_bShadersAvailable

Producer: `find-ClientPortalManager_m_bShadersAvailable`; required predecessors:
`ClientPortalManager_InitShader` from the existing shader-chain finder and
`ClientPortalManager_DrawPortals`. Emits `struct_name`, `member_name`, `offset`, `size`.

| Build | Windows offset / size | Linux offset / size |
| --- | --- | --- |
| 10257 | `0x1e0` / 1 | `0x1d4` / 1 |
| 8948 | `0x1e0` / 1 | `0x1d4` / 1 |

Each result is independently decoded from its own IDB. The offsets are not finder constants.

## Semantic proof

`_portal_render_state` and its IDA adapter share decoded operands with the existing portal
layout machinery. Recover the InitShader this object from ECX (Windows) or its entry stack
argument (Linux), and collect its actual stores along separate forward CFG paths.
Require a one-byte availability assignment (constant 1 or a returned eligibility byte),
a clearing assignment, and a distinct four-byte program member write.

Walk only DrawPortals and its actual direct callees for InitShader calls. After each call,
allow cdecl stack cleanup, then require a byte-zero guard on that same this object.
The active branch must select the program member or zero through the same resolved module
global/GOT function-pointer slot. Both enable and disable must agree with initialization.
Linux 10257's split reset helper is followed without publishing it as DisableShader.
Windows's dead out-of-line EnableShader/DisableShader copies are never considered or emitted.

## Meaning and pitfalls

`m_bShadersAvailable` is a behavior-recovered semantic name, not a confirmed source member name.
It means the client permits shader use; initialization sets it before compilation/linking and
does not check compile/link status. It is neither successful-link status nor current binding.
The adjacent program handle and stack-local shader-compiler query are rejected by ownership,
width, initialization, active-guard, argument, and shared-slot checks.

## Verification

All four real IDB finder runs recover the table above. Synthetic regressions vary layouts,
exercise cdecl cleanup and split reset, and reject wrong widths, stack locals, mismatched
read/write offsets, program-as-flag, mismatched function slots, and missing availability writes.
The change publishes upstream data only; MetaHookSv's consuming hook is separate.

2026-09-26 delivery verification: all four shader-chain, member and clip-plane nodes,
plus both versions' Windows/Linux downstream layout nodes, succeeded against the real IDBs.
`tests/run_test_suite.py all -b --durations 15`: 1219 tests, OK, 9 skips (unavailable Redis,
platform-specific and opt-in checks). `format_repo_files.py --check` passed. Both tags passed
snapshot/gamedata/JSON candidate guards and local staging publication. The browser JSON was
checked for the byte member, corrected setup address, separate calculation identity, and
absence of Windows EnableShader/DisableShader records. Gamedata has no configured generators
and therefore produces the canonical empty manifest; published symbol data is in the JSON.
