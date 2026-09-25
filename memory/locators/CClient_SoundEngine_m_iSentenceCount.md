---
title: CClient_SoundEngine_m_iSentenceCount locator
type: note
permalink: goldsrc-vibesignatures/locators/cclient-soundengine-m-isentencecount
tags:
  - locator
  - client
  - structmember
  - llm-decompile
  - svencoop
---

# CClient_SoundEngine_m_iSentenceCount

## Symbol

- **Name**: `CClient_SoundEngine_m_iSentenceCount`
- **Category**: `structmember` (artifact identity `struct_name` + `member_name`; parent
  `category: struct` is `CClient_SoundEngine`)
- **Module**: client (`client.dll` / `client.so`)
- **Producer**: `ida_preprocessor_scripts/find-CClient_SoundEngine_LoadSoundList-decompiles.py`

## Availability

- Declared in 2 configs: svencoop-10257, svencoop-8948 (client module only).
- Platforms: Windows + Linux (no `platform:` gate). Produced per platform:
  `CClient_SoundEngine_m_iSentenceCount.{platform}.yaml`.
- No `platform` difference in the value itself: all four validated build/platform pairs resolve to
  `0x11B09C`. The MSVC and GCC layouts agree here, which is expected — the member is a late,
  engine-private addition to the object, not part of a compiler-versioned base layout. Recover it
  per platform anyway; do not hardcode the number.

## Predecessors

- `CClient_SoundEngine_LoadSoundList` (produced by `find-CClient_SoundEngine_LoadSoundList`) as a
  **required** `expected_input`; it is also the LLM reference body
  (`references/{gamever}/client/CClient_SoundEngine_LoadSoundList.{platform}.yaml`).

## How it is located

1. The owner artifact is reloaded and revalidated with
   `_direct_gv_common.inspect_owner_artifact`; `func_sig` must also resolve uniquely to the owner
   entry via `_find_unique_bytes`.
2. A deterministic `py_eval` scan walks the owner's instruction range for the sentence-table
   capacity guard: a `cmp dword ptr [reg+disp], imm` whose `disp` is a dword member displacement,
   whose immediate is the table capacity (MSVC `0x800`, GCC `0x7FF`), and whose **immediately
   following instruction** is the matching signed branch (`jge`/`jl` for `0x800`, `jg`/`jle` for
   `0x7FF`). Exactly one candidate must survive; the guard's offset, instruction VA, and rendered
   instruction text are the verified evidence.
3. That single instruction is passed to `preprocess_common_skill` as a `structmember` target with
   `LLM_DECOMPILE`, `expected_size: 4`, and an `instruction_rules` entry pinning the exact guard
   line, so the LLM cannot return any other member access.
4. After the artifact is written, the finder re-reads it and requires
   `struct_name`/`member_name`/`offset`/`size` to match the verified guard and `offset_sig_disp` to
   equal `guard_va - owner_va`, else it deletes the output and fails closed. No value is copied from
   another build or from an old artifact (`old_yaml_map=None`).

## Pitfalls

- **The member is a count, not a capacity.** It holds the number of loaded sentences and saturates at
  the 2048-entry table size; the capacity itself is the `0x800`/`0x7FF` immediate in the compared
  instruction. The name `m_iSentenceCount` reflects the source role. MetaHookSv CaptionMod consumes
  the same field as `ScClient_soundengine_maxsentences`, but that name is misleading — the
  patched-out consumer treats the member value as the loop bound in
  `ScClient_SoundEngine_GetSentenceByName`, iterating `this->sentences[i]` from the object base.
- **The Linux target disassembly must be normalized before export.** The client ELF has image base 0,
  so `0x11B09C` also lands inside `.text` and IDA renders the operand as a code label
  (`cmp dword ptr ds:loc_11B09C[edi], 7FFh`). The shared LLM validator extracts displacements from
  the instruction text and rejects a label-only operand
  (`struct_offset_mismatch: does not contain its offset displacement`), so the finder calls
  `ida_bytes.op_hex(ea, 0)` on the proven operand first. This mutates only the analyzer's warm,
  non-saved IDB session.
- The guard must be a dword member compare with the capacity immediate; a stack-local `o_displ`
  compare is rejected by the `dt_dword` + immediate + branch-pair requirements, and the scan demands a
  unique candidate so an unrelated 2048/2047 comparison cannot be selected.
- Two other members of the same object are touched by the same body and must not be confused with
  this one: `+0x11B0A0`, another dword capacity compared against `0x1000` (MSVC) / `0xFFF` (GCC) for
  the sound list, and the loading flag byte at `+0x11B012`. The scan rejects both by construction —
  `0x1000`/`0xFFF` are not in the accepted immediate set, and the byte flag is not a `dt_dword`
  member read.
- The owner body is reached through the `.part.N` split on Linux; the member access is inside that
  body (8948 Linux `0x11EBE9`, 10257 Linux `0xAFB09`). If a future build moves the check into the
  public wrapper, the finder fails closed rather than guessing.
