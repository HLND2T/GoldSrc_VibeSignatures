---
title: R_StudioDrawPlayer locator
type: note
permalink: goldsrc-vibesignatures/locators/r-studiodrawplayer
tags:
  - locator
  - engine
  - func
---

# R_StudioDrawPlayer

## Symbol

- **Name**: `R_StudioDrawPlayer`
- **Category**: `func`
- **Module**: engine (`hw.dll` / `hw.so`)
- **Producer**: `ida_preprocessor_scripts/find-R_StudioDrawPlayer.py`,
  `ida_preprocessor_scripts/find-R_StudioDrawPlayer-svencoop.py`
  (both delegate to `_studio_player_model_common.preprocess_studio_draw_player`)

## Availability

- Declared in 10 configs: cof-5936, hl-10210, hl-3248, hl-3266, hl-3329, hl-3647,
  hl-4554, hl-6153, hl-8684, svencoop-10257.
- Platforms: Windows + Linux (no `platform:` gating; cof is Windows-only by binary).
- Inlined / absent: always present as a standalone function start (it is stored in the
  static `r_studio_interface_t` object). GCC Linux can keep the *body* inside an
  `R_StudioDrawPlayer.part.N` cold clone and leave a short (`0x2b`–`0x44` byte) entry that
  tail-jumps into it; the located symbol is the entry, never the clone.

## Predecessors

- `studioapi_SetupPlayerModel.{platform}.yaml` (produced by `find-studioapi_SetupPlayerModel`
  or `-svencoop`, consumed via `expected_input`). Used as the format-string-owner
  cross-check target, not as a code anchor.

## How it is located

1. Find the unique ClientDLL_CheckStudioInterface diagnostic — HL family:
   `Couldn't get client .dll studio model rendering interface.  Version mismatch?\n`;
   SvEngine: `Couldn't get client library studio model rendering interface. Version mismatch?\n`.
   The locator requires exactly one exact `STRTYPE_C` match, else it aborts.
2. Collect the owning function(s) of that literal (data and code xrefs). On Linux there
   can be **two** string owners (DWARF names only one `ClientDLL_CheckStudioInterface`);
   both reference the same `&pStudioAPI`, so the locator collapses on the unique
   *candidate address* instead of the owner.
3. In each owner, scan every instruction for data operands:
   - absolute form — a 4-byte little-endian window anywhere in the instruction whose value
     `is_mapped()` and `is_writable_data()` (raw-byte scan restricted to mapped writable
     data, never to code/const);
   - PIC form (SvEngine Linux) — recover the GOT anchor from an `add ebx, imm32` (`81 C3`)
     in the first 10 instructions, then decode `lea/mov reg, [ebx+disp32]` (`mod==2`,
     `rm==3` or SIB-index `ebx`) and resolve `anchor + disp`.
4. Validate each candidate as `&pStudioAPI`: the candidate must be writable data; its
   **static image dword** must point at writable data (the `r_studio_interface_t studio`
   object); that object's `dword0` must be exactly `1` (`STUDIO_INTERFACE_VERSION`); its
   `+4` and `+8` slots must be non-zero, executable, and exact IDA function starts.
   `&engine_studio_api` fails (its first member is a code pointer, not a `1`-leading
   writable object) and `&cl_funcs` fields are zero in the image. Exactly one candidate
   must survive.
5. `R_StudioDrawPlayer` is `studio+8`.
6. Semantic gate (DAG cross-check): take the owner set of `models/player/%s/%s.mdl`, remove
   the entry family (`{draw_player} ∪ direct call/jmp targets of the entry` — this covers
   GCC `.part.N` clones), and require the single remaining owner to equal the verified
   `studioapi_SetupPlayerModel` artifact. A second gate requires the literal to be
   reachable from the entry itself or from one of its direct transfers.
7. Materialize the artifact through `_inspect_function_via_mcp` at `studio+8`, requiring
   `func_va == draw_ea`. If the strict-window signature is not unique, retry with
   `allow_across_function_boundary=True` and emit `func_sig_allow_across_function_boundary: true`.

## Pitfalls

- **GCC `.part.N` cold clone owns the string, not the entry**: on every Linux `hw.so` GCC
  moves the `Q_snprintf` block into `R_StudioDrawPlayer.part.9` and the interface entry only
  tail-jumps to it. Any locator that demands "the entry references the literal" must accept
  the literal on the entry *or* any direct call/jmp target — otherwise it names the clone
  instead of the `studio+8` entry. The short entry still yields a unique `func_sig` without
  the across-boundary fallback.
- Discovery never uses a byte signature or a prior artifact signature; only IDA operand
  structures feed the anchors.
- Both the candidate and the entry are rejected when below `image_base` (guards against
  ELF `is_exec(0)`-style address-0 artefacts).
- Linux PIC: on a `lea reg, [ebx+idx+disp32]` the raw o_displ value can land in writable
  data by chance; only the GOT-anchored resolution is the truth.

## Evidence

- Validated 2026-09-09/10: DWARF truth `0x136200` (hl-8684 `hw.so`), `0xd28b0`
  (hl-10210 `hw.so`); regression 13/13 binaries.
- `studio+8` cross-validated against `studio+4` on 2026-09-10: hl-10210 `hw.dll`
  `0x101F0580`, `hw.so` `0xD28B0`, hl-8684 `0x1D853B0`, hl-3248 `0x1D8EED0`,
  svencoop-10257 `hw.dll` `0x1D8A390`, cof-5936 `0x1DBF4F1`.
