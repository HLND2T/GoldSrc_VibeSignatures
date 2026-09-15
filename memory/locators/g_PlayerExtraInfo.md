---
title: g_PlayerExtraInfo locator
type: note
permalink: goldsrc-vibesignatures/locators/g-playerextrainfo
tags:
  - locator
  - client
  - gv
---

# g_PlayerExtraInfo

## Symbol

- **Name**: `g_PlayerExtraInfo`
- **Category**: `gv`
- **Module**: client (`client.dll` / `client.so`)
- **Producer**: `ida_preprocessor_scripts/find-ClientScoreInfoHandler-decompiles.py`

## Availability

- Declared in 8 configs: cstrike-10210, cstrike-3248, cstrike-3647, cstrike-4554, cstrike-6153, cstrike-8684, czero-10210, czero-8684.
- Platforms: Windows + Linux.
- Inlined / absent: none observed. The CS/CZ shared `CounterStrikeViewport` body has one explicit reference family, shared across its builds. CZDS is a separate symbol (`g_PlayerExtraInfo_CZDS`); HL/cof/Sven have no ScoreInfo handler.

## Predecessors

- `ClientScoreInfoHandler.{platform}.yaml` (produced by `find-client-ScoreInfo-handler`, consumed via `expected_input`, `dependency_policy: required`).

## How it is located

1. The predecessor's annotated body is the reference; the dedicated prompt `prompt/call_llm_scoreinfo.md` is used (not the generic decompile prompt), with reference YAML `references/cstrike-10210/client/ClientScoreInfoHandler.{platform}.yaml`.
2. **Windows**: anonymous operands need current-handler dataflow evidence. `_export_llm_function` dumps the predecessor, and `_scoreinfo_dataflow.windows_frags_instruction_rule` is run for each candidate stride. It parses the disassembly, requires the exact BEGIN_READ + player-byte + four-READ_SHORT header (6 prefix calls: 3 distinct callees for `BEGIN_READ`/`READ_BYTE`/first `READ_SHORT`, then four calls to one common `READ_SHORT`), then propagates the first-short value and the player index through register copies, `lea` address expressions, `add`/`sub`, `imul` and `shl`, meeting equal facts at control-flow merges. The single accepted store is `mov reg16, [player_index * stride + 0]` where the stored register holds the first `READ_SHORT` role (`("frags", 1, 0)`) and the global index is exactly `("player", stride, 0)`. Exactly one rule must survive across the accepted strides, otherwise the finder fails with `cannot prove one zero-offset frags store`.
3. **Linux**: Hex-Rays retains member names, so a text rule proves the zero member: `mov word ptr [ds:]g_PlayerExtraInfo.frags[index], reg16`.
4. The rule is handed to the LLM as an `instruction_rule` on the caller-specified prompt; the LLM remains the symbol-mapping step. Output fields include `gv_sig_allow_across_function_boundary:true`.

## Pitfalls

- **One frags store only.** The generic prompt requested every reference, and `ida_analyze_util._preprocess_llm_target` accepts the first resolvable entry — so `teamnumber`/`deaths` could become the alleged array base. Signature uniqueness proves runtime resolution, not semantic identity. The dedicated template requests exactly one zero-offset frags store; `analysis_sources.py` binds each declared prompt to its node's game version/module/platform.
- Strides are build-dependent: CS/CZ uses `0x74` or legacy `0x68`, CZDS is restricted to `0x1c`. Unknown strides, alternate members, ambiguous stores and family crossover fail closed.
- 3248/3647 legacy Windows clients use the `0x68` record; the old `LEA/LEA/SHL` form computes `13 * 8 = 104`.
- Reject `frags+2`, `deaths`, `playerclass`, `teamnumber`, interior-address arithmetic, comparisons and all loads.
- The 8684 Windows base was corrected in isolation from `0x1a2f44a` to `0x1a2f420` (anchor offset `0x65` -> `0x6d`); this is evidence, not a selector.
- The LLM must write `insn_va` as a quoted `0x`-prefixed string with no IDA segment prefix; bare hex / `.text:` labels are rejected by the scalar parser, so the template carries explicit quoted-`0x` examples.
- Stack-spilled field provenance and unknown compiler shapes are intentionally not inferred.
