---
title: FS_Open callsite patches from S_LoadSound and Mod_LoadModel
type: note
permalink: goldsrc-vibesignatures/notes/fs-open-callsite-patches-from-s-load-sound-and-mod-load-model
tags:
- finder
- patch
- fs-open
- resource-replacer
---

# FS_Open callsite patches from S_LoadSound and Mod_LoadModel

## Trigger
Need the `call FS_Open` instruction addresses inside `S_LoadSound` / `Mod_LoadModel` so ResourceReplacer can `InlinePatchRedirectBranch` those sites (not a global `FS_Open` hook).

## Facts
- Official source: `engine/snd_mem.c` has one `FS_Open(namebuffer, "rb")`; `engine/gl_model.c` has one `FS_Open(mod->name, "rb")`.
- Owning functions and `FS_Open` are already covered: `find-S_LoadSound`, `find-Mod_LoadModel`, `find-Mod_LoadModel-decompiles`.
- Across hl-3248..hl-10210, svencoop-10257, and cof-5936 (Windows + declared Linux), each owner body has exactly one direct `E8 call` whose xref start is `FS_Open`. No extra sites.
- Linux does not `push "rb"`. GCC writes `mov [esp+..], offset aRb` then `call FS_Open`. MetaHook's `FindFSOpenCallSites` PUSH+window walk is Windows-shaped; the production finder must not require PUSH.
- Blob engines (`hl-3248`..`hl-3647`) analyze `hw.decrypt.dll`. IDA may still name the callee `sub_XXXXXXXX`; match by artifact `func_va`, not the display name.

## Correct approach
Reuse the PR #78 callsite-patch pattern: consume verified owner + callee YAML, walk the owner with `_inspect_function_via_mcp`, collect unique `E8`/`E9` sites whose xref function start is the callee, emit `patch` artifacts with `patch_sig_disp: 0` and no `patch_bytes`.
Shared helper: `ida_preprocessor_scripts/_func_to_func_callsites_common.py`.
Finders: `find-S_LoadSound_to_FS_Open_callsites`, `find-Mod_LoadModel_to_FS_Open_callsites`.

## Validation
`ida_analyze_bin.py -allgamever -modules engine -platform windows,linux` produced 26 artifacts, 0 failed (13 engine binaries × 2 skills).

## Scope
hl-*, svencoop-*, cof-* engine modules. Not cstrike/czero/czeror (no engine module in this repo).
