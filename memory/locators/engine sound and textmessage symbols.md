---
title: Engine sound and textmessage symbol locators (issue #257)
type: note
permalink: goldsrc-vibesignatures/locators/engine-sound-and-textmessage-symbols
tags:
- locator
- engine
- func
- gv
- issue-257
---

# Engine sound / tmessage locators (#257)

## Trigger signal

A finder needs `S_Init`, `S_Update`, `S_Say_Reliable`, `S_FindName`, `S_StartDynamicSound`,
`S_StartStaticSound`, `TextMessageParse`, or `listener_origin` in `hw.dll`/`hw.so`.

## Constraint and cause

Every function anchor here is a literal the target owns outright (`snd_dma.c` / `tmessage.c`):
`"Sound Initialization\n"`, `"----(%i)----\n"` (the `snd_show` channel dump footer),
`"S_Say_Reliable: can't find sentence name %s\n"`, `"S_FindName: NULL\n"`,
`"Warning: S_StartDynamicSound/StaticSound Ignored, called with pitch 0"`, and
`"tmessage::TextMessageParse : messageCount>=MAX_MESSAGES"`. Each occurs exactly once per
configured binary (verified across all 11 engine gamevers × 15 binaries, BLOB versions on
`hw.decrypt.dll`).

Two structural facts break the naive shared `func_xrefs` path and clone the literal owner set
on GCC builds:

1. **Entry-instruction anchors.** MSVC emits the argument `push` as the literal first
   instruction of `S_Init` (no prologue), and on HL25 Windows `S_Say_Reliable`'s diagnostic
   reference sits at the entry with a byte-identical prefix shared with `S_Say`.
   `_ensure_function_owner` cannot confirm an anchor that is itself the function start, so
   those two finders resolve the owner with the worker-side `exact_string_owner` walk
   (`_engine_private_globals_common`) and emit via `inspect_func` (across-boundary retry for
   the duplicate-prefix case).
2. **GCC compiler clones.** `S_FindName` gets a `pfInCache == NULL` specialization
   (`S_FindName.constprop.12` on hl-8684, called by S_PrecacheSound/S_Say_Reliable/etc.) beside
   the generic body that `VOX_LoadSound` calls (`snd_mix.c` passes
   `&rgvoxword[cword].fKeepCached`). `S_StartDynamicSound` gets `.part.N` cold/wrapper splits
   (hl-10210 keeps a 163-byte ABI wrapper that tail-jumps the 879-byte `.part.3`; Sven keeps
   two full bodies, and the stripped svencoop-10257 exports nothing).

## Correct locator

- `find-S_Init`, `find-S_Say_Reliable`: `exact_string_owner` walk on the owned literal +
  `inspect_func`.
- `find-S_Update`, `find-S_StartStaticSound`, `find-TextMessageParse`: plain `func_xrefs`
  string spec (single owner everywhere).
- `find-S_FindName`: literal owners ∩ direct callees of the `VOX_LoadSound` artifact
  (`expected_input`); exactly one must remain. Windows and hl-10210 have a single owner and
  skip the intersection de facto.
- `find-S_StartDynamicSound`: candidates = literal owners ∪ {functions whose only transfer
  into an owner is a `jmp` (the hl-10210 wrapper)}; pick the candidate with the strictly
  largest distinct direct-caller count (PLT-routed calls included via the shared `callers`).
  Evidence: hl-10210 wrapper 33 vs part.3 6; svencoop-8948 export 26 vs clone 4;
  svencoop-10257 engine-wide body 31 vs sound-cluster clone 5.
- `find-listener_origin` (`gv`): depends on the `S_Update` artifact (`expected_input`,
  registered after `find-S_Update` in every config). Inside `S_Update`, the four
  `VectorCopy` store groups each write `+0/+4/+8`; `listener_origin` is the group with the
  lowest first-write index (source copies `origin` first). Covers MSVC integer stores,
  SvEngine x87 `fld/fstp`, HL25/GCC SSE `movss`, and Sven PIC `[ebx+disp]` through the shared
  GOT decoder.

## Verification

All 8 symbols × 15 configured binary/platform pairs regenerate with zero failures
(`-allgamever`, per-skill). On the three `.symtab` Linux builds (hl-10210, hl-8684,
svencoop-8948) every emitted `func_va` matches `readelf --syms` exactly (21/21 checks) and
`listener_origin` matches the symtab `vec3_t` objects (`0x13bb090` / `0x13531b4` /
`0x798f0fc`). svencoop-8948 Windows `S_Init` `0x1d96050` equals MetaHookSv's disassembly
comment. Every emitted signature matches exactly one location in its own binary
(88 whole-file checks + 32 BLOB-decrypt checks).

## Scope

Engine module across `cof-5936`, `hl-3248`..`hl-10210`, `svencoop-8948`/`10257`; Linux only
where the config declares `hw.so` (hl-10210, hl-8684, both Sven). cstrike/czero/czeror have no
engine module. `S_LoadSound` was already covered and ignored.
