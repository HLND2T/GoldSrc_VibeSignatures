---
title: GCC viewport constructors assign the interface pointer before its vptr store
type: note
permalink: goldsrc-vibesignatures/lessons/gcc-viewport-constructors-assign-the-interface-pointer-before-its-vptr-store
tags:
- lesson
- preprocessor
- gcc
- czeror
- dataflow
- vtable
---


# GCC viewport constructors assign the interface pointer before its vptr store

## Trigger

`find-client-ScoreInfo-handler` failed on CZDS Linux (both builds) with
`{'error': 'ScoreInfo constructor has an unproven non-null interface assignment'}` even though the
constructor and its vtable were unambiguous in the disassembly.

## Root cause / constraints

1. The Windows (MSVC) CZDS constructor stores the interface pointer as a **constant subobject address**,
   so the vptr for that subobject is already in the tracked `memory` map at the moment of the store.
2. The GCC constructor computes the subobject and stores it **register-relative**, then writes the vptr
   *afterwards*:

   ```
   0x8fad6: lea edx, [eax+8]                     ; subobject = this + 8
   0x8fae7: mov ds:gViewPortMsgs, edx            ; interface pointer assigned here
   0x8faf6: mov dword ptr [eax+8], offset off_152AA0   ; vptr lands later
   ```

   The old code resolved `memory.get(value)` at the instant of the interface store, found nothing, and
   failed closed.

## Correct approach

Keep the immediate resolution (it is what proves MSVC and what makes
`test_conflicting_branch_tables_fail_closed` / `test_unproven_nonnull_branch_fails_closed` hold), and
add a deferred fallback that resolves any still-unresolved interface value **once that control-flow
path ends**:

- on the store to the interface pointer, try `memory.get(value)` first; on success record the table,
  otherwise remember the value;
- after the path's linear walk breaks (on `ret`), retry each remembered value against that path's
  `memory`, and **fail closed if any still does not resolve**.

The fail-closed retry is essential: simply skipping unresolved values silently downgraded an
"unprovable assignment" error into "ignore this branch", which a unit test caught.

## Verification

- `tests/test_scoreinfo_constructor.py` 5/5 pass (null guard, agreeing branches, conflicting tables,
  cyclic constructor, unproven non-null branch).
- `czeror-8684/10210 client.so` now resolve `ClientScoreInfoHandler` (`0x8e240` / identical artifacts
  across a re-run with the stricter logic).
- All ten `ClientScoreInfoHandler.windows.yaml` artifacts reproduce byte-identically, so the MSVC path
  is unchanged.

## Scope

`ida_preprocessor_scripts/find-client-ScoreInfo-handler.py` (`LOCATE`). The same "assign then store the
vptr" ordering can appear in any GCC-compiled constructor that registers an interface pointer, so
re-apply the pattern rather than assuming the assignment order.
