---
title: CGame_DrawStartupVideo locator
type: note
permalink: goldsrc-vibesignatures/locators/cgame-drawstartupvideo
tags:
  - locator
  - engine
  - func
---

# CGame_DrawStartupVideo

## Symbol

- **Name**: `CGame_DrawStartupVideo`
- **Category**: `func`
- **Module**: engine (`hw.dll` / `hw.so`)
- **Producer**: `ida_preprocessor_scripts/find-CGame_DrawStartupVideo.py`

## Availability

- Declared in 1 engine config: hl-10210 only.
- Platforms: Windows + Linux (no `platform:` gate; the hl-10210 finder runs against both `hw.dll` and `hw.so` and artifacts exist for both).
- Inlined / absent: HL25-only. It is an alias for the WebM startup player (`WebMPlayer::PlayVideo`, the MetaHook `DRAWSTARTUPVIDEO_HL25` role); older builds play the startup video through a different mechanism and do not register this symbol.

## Predecessors

- None. `find-CGame_DrawStartupVideo` has no `expected_input`.

## How it is located

1. Single positive anchor: `xref_strings: ["FULLMATCH:WebMPlayer::PlayVideo %s\n"]` — an exact C-string match on the diagnostic literal *including* the `%s` format specifier and the trailing newline. Owning functions of its xrefs form the candidate set.
2. `xref_gvs`, `xref_signatures`, `xref_funcs` are empty and there are no exclusion lists, so the anchor is the sole discriminator.
3. Owner recovery runs and the payload must contain exactly one candidate; ambiguity fails closed.
4. The survivor is emitted as `func_name`, `func_sig`, `func_va`, `func_rva`, `func_size`. No LLM, no byte scan.
5. The docstring states the literal has a single owner, which is why a plain string anchor is sufficient here — the opposite situation from `-novid`, which needed a vtable walk.

## Pitfalls

- The anchor is byte-exact: `FULLMATCH` compares the IDA string to `WebMPlayer::PlayVideo %s\n` in full. A build that drops the trailing newline, changes the `%s` to another specifier, or uses a different internal tag will lose the anchor. Do not loosen it to a substring unless the owner uniqueness is re-verified.
- If Hex-Rays/IDA has not materialized the string, or has it under a different string type, the candidate set is empty; `_string_items` applies the configured `string_min_length` and C-string type setup before matching, so a polluted or misconfigured shared string list can also hide it (see the repo note about custom finders polluting the shared IDB string list).
- The symbol name is an alias: the artifact name is the MetaHook role name `CGame_DrawStartupVideo`, not the native `WebMPlayer::PlayVideo` symbol, so downstream consumers must key on the artifact name rather than searching the binary for that identifier.
- Windows and Linux sizes differ substantially (hl-10210: `0xcf3` Windows, `0x1063` Linux) because the whole WebM player path is inlined into each; a size comparison across platforms is not a validity check.
