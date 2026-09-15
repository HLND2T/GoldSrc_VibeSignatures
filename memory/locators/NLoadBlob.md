---
title: NLoadBlob locator
type: note
permalink: goldsrc-vibesignatures/locators/nloadblob
tags:
  - locator
  - engine
  - func
---

# NLoadBlob

## Symbol

- **Name**: `NLoadBlob`
- **Category**: `func`
- **Module**: engine (`hw.dll`)
- **Producer**: `ida_preprocessor_scripts/find-NLoadBlob.py` (thin wrapper over
  `preprocess_common_skill`)

## Availability

- Declared in 9 configs: cof-5936, hl-10210, hl-3248, hl-3266, hl-3329, hl-3647, hl-4554,
  hl-6153, hl-8684.
- Platforms: **Windows-only**. The finder registration carries `platform: windows` on the
  both-platform configs (hl-10210, hl-8684) and every other declaring config is a Windows engine
  build anyway; the `NLoadBlob` symbol is declared `platform: windows` in every config.
- Inlined / absent: **Linux is native unsupported** — the `85 BC 32 7A` blob marker that anchors
  this function is absent from every `hw.so`. **svencoop-10257 is native unsupported** as well:
  it declares no `NLoadBlob` symbol and registers no finder (Sven Co-op has no blob load/unload).
  Both absences are capability facts recorded in the cvar/blob capability matrix, and must not be
  reported as missing artifacts.
- Also absent (by design) from cstrike/czero/czeror: those tags have no engine module in this
  repo and consume the matching `hl-*` engine by CRC64.

## Predecessors

- None. It is the root of the blob chain and feeds `find-NLoadBlobFile` via `expected_input`.

## How it is located

1. `FUNC_XREFS` declares two positive sources that `preprocess_common_skill` resolves through MCP
   and then **intersects**:
   - `xref_signatures: ["85 BC 32 7A", "6A 00 6A 01 6A 00"]`.
2. Each signature is first matched globally (`_find_byte_matches`); the first set becomes the
   candidate functions containing `85 BC 32 7A`. With that narrowed set in hand the second
   signature is applied as a *function-body* probe (`ida_bytes.find_bytes` inside
   `[func.start_ea, func.end_ea)`), which is the CS2 probe rule used when the narrowed set is
   non-empty and <= 256 functions.
3. The intersection must contain exactly one function.
4. Emits `func_name` / `func_va` / `func_rva` / `func_size` / `func_sig`. There is no
   across-boundary fallback variant for this finder.

## Pitfalls

- `85 BC 32 7A` is a 4-byte marker inside the blob loader, not a signature of the whole function;
  it is only meaningful on decrypted images. Never run it against the raw `bin/<tag>/engine/hw.dll`
  blob for hl-3248/hl-3266/hl-3329/hl-3647 — those are encrypted and a byte scan silently returns
  zero hits. The analysis target (and every artifact) is `hw.decrypt.dll`, while the config still
  says `module_windows: hw.dll`.
- Because the literal-absence check is only valid on a real PE/ELF, the Windows-only gating must
  not be re-litigated from a zero-hit scan of a blob file. Missing `hw.decrypt.dll` means "run the
  repo decryption step", not "the symbol does not exist".
- Blob engines may display the function as `sub_XXXXXXXX` in IDA. The finder does not depend on
  the display name, and downstream consumers must match by artifact `func_va`.
- Recovering a stale `NLoadBlob` artifact from an old YAML is not part of the contract: the finder
  passes `old_yaml_map=None` and re-derives the function every run.
