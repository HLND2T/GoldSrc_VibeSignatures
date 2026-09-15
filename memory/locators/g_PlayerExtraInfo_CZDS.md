---
title: g_PlayerExtraInfo_CZDS locator
type: note
permalink: goldsrc-vibesignatures/locators/g-playerextrainfo-czds
tags:
  - locator
  - client
  - gv
---

# g_PlayerExtraInfo_CZDS

## Symbol

- **Name**: `g_PlayerExtraInfo_CZDS`
- **Category**: `gv`
- **Module**: client (`client.dll` / `client.so`)
- **Producer**: `ida_preprocessor_scripts/find-ClientScoreInfoHandler-decompiles.py`

## Availability

- Declared in 2 configs: czeror-10210, czeror-8684.
- Platforms: Windows + Linux.
- Inlined / absent: none observed. CZDS (Condition Zero Deleted Scenes) is the only consumer; plain CS/CZ uses `g_PlayerExtraInfo`.

## Predecessors

- `ClientScoreInfoHandler.{platform}.yaml` (produced by `find-client-ScoreInfo-handler`, consumed via `expected_input`, `dependency_policy: required`).

## How it is located

1. The producer picks the symbol by output declaration: `_output_for_symbol(expected_outputs, "g_PlayerExtraInfo_CZDS")` selects the CZDS name and `family = "czeror-10210"`, so the reference YAML is `references/czeror-10210/client/ClientScoreInfoHandler.{platform}.yaml`. The prompt is the dedicated `prompt/call_llm_scoreinfo.md`.
2. The CZDS handler is the distinct `TeamFortressViewport` body (neither it nor the CS handler exists in canonical Half-Life).
3. **Windows**: `windows_frags_instruction_rule` is evaluated with the single stride `CZDS_PLAYER_STRIDE = 0x1c`. The rule validates the BEGIN_READ / player-byte / four-READ_SHORT protocol, follows the first `READ_SHORT` result and the player index through register copies and affine stride arithmetic, meets equal facts at merges, and requires exactly one zero-member frags store. If no single rule is proven the finder prints `ScoreInfo: cannot prove one zero-offset frags store` and returns False.
4. **Linux**: the same text rule as the CS symbol is used, anchored on `g_PlayerExtraInfo_CZDS.frags[index]`.
5. Emits a GV YAML with `gv_sig_allow_across_function_boundary:true`.

## Pitfalls

- CZDS stride is restricted to `0x1c`; the CS strides `0x74`/`0x68` must never be accepted here, and vice versa (family crossover fails closed).
- CZDS uses a different viewport body and layout from CS/CZ — do not reuse the CS handler's call-interface global or object layout.
- The one-frags-store rule is the same anti-pattern guard as the CS symbol: the LLM must return exactly one `found_gv`, rejecting `frags+2`, `deaths`, `playerclass`, `teamnumber`, comparisons, loads and interior-address arithmetic, and must not copy reference addresses or anonymous IDA names.
- `insn_va` must be a quoted `0x`-prefixed hex string without an IDA segment prefix.
