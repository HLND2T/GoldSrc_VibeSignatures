---
title: CClient_SoundEngine_LoadSoundList locator
type: note
permalink: goldsrc-vibesignatures/locators/cclient-soundengine-loadsoundlist
tags:
  - locator
  - client
  - func
  - svencoop
---

# CClient_SoundEngine_LoadSoundList

## Symbol

- **Name**: `CClient_SoundEngine_LoadSoundList`
- **Category**: `func`
- **Module**: client (`client.dll` / `client.so`)
- **Producer**: `ida_preprocessor_scripts/find-CClient_SoundEngine_LoadSoundList.py`

## Availability

- Declared in 2 configs: svencoop-10257, svencoop-8948 (client module only).
- Platforms: Windows + Linux (no `platform:` gate). Produced per platform:
  `CClient_SoundEngine_LoadSoundList.{platform}.yaml`.
- SvEngine-only. Sven Co-op's client ships its own FMOD `CClient_SoundEngine`; the
  `SENTENCELIST {` literal is absent from every other configured client binary (verified by a byte
  census across all `bin/*/client/*`), so no `hl-*` / `cstrike-*` / `czero-*` config declares it.
- Inlined / absent: the full body is always present, but on both Linux builds it is a **GCC split
  function**, so the artifact deliberately points at the body, not the public entry (see Pitfalls).

## Predecessors

- None. `find-CClient_SoundEngine_LoadSoundList` has no `expected_input`.
- It is the predecessor of `find-CClient_SoundEngine_LoadSoundList-decompiles`, which recovers
  `CClient_SoundEngine_m_iSentenceCount`.

## How it is located

1. `_sven_client_pic_common.preprocess_string_owner_skill_with_pic_fallback` is called with the
   exact literal `SENTENCELIST {`. The shared Pattern A path runs first (`xref_strings` with
   `FULLMATCH:`); on the image-base-0 Linux ELFs, where the literal is reached through
   `lea reg, [gotreg+disp32]` and IDA may create no xref, the helper's PIC fallback resolves the
   module GOT anchor and scans for the unique GOTOFF displacement site.
2. Exactly one owning function must remain. Both validated builds satisfy this: Windows keeps a
   single `__thiscall` body, and Linux keeps one `.part.N` body.
3. The owner is emitted as a function YAML. On Linux the `.part.N` body carries the `SENTENCELIST {`
   parse loop, while the public `LoadSoundList()` symbol is a small guard wrapper that tail-jumps
   into it; the finder anchors only the literal, so it lands on the body.
4. This function then feeds `find-CClient_SoundEngine_LoadSoundList-decompiles`, which recovers
   `CClient_SoundEngine_m_iSentenceCount` from the body's sentence-table capacity guard.

## Pitfalls

- **The Linux artifact is not the public entry.** `nm -C` on svencoop-8948 `client.so` shows
  `CClient_SoundEngine::LoadSoundList()` at `0x11f116` (loading-flag + map-time guard, tail-jump to
  the `[clone .part.9]` body at `0x11e894`). The artifact must keep pointing at the body, which is
  the control-flow root holding the parse loop — the same convention as `Mod_LoadModel`. Never
  "fix" it back to the wrapper.
- The ParseSentenceLine diagnostics (`Sentence length too long! Greater than %d characters!`) are
  **not** usable as this finder's anchor. They do own the sentence-table insertion on Windows, but on
  8948 Linux `ParseSentenceLine` calls `AddSentence` through the PLT, so the sentence-count access
  lives in a different function; anchoring there would not yield a count guard on every platform.
- `Deleting outdated sound list file '%s'. Scanned map name '%s' does not match current map '%s'.`
  is also owned by the LoadSoundList body and is an equally valid alternative literal. It is a
  substring of no other string on the validated builds; `SENTENCELIST {` was chosen because it also
  documents where the sentence table is consumed.
- Do not add a byte signature or reuse an old YAML: the exact literal is the only anchor, and the
  old-version reuse path is disabled (`old_yaml_map=None`).
