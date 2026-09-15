---
title: cl_players_model locator
type: note
permalink: goldsrc-vibesignatures/locators/cl-players-model
tags:
  - locator
  - engine
  - gv
---

# cl_players_model

## Symbol

- **Name**: `cl_players_model` (`&cl.players[0].model`, `player_info_t players[MAX_CLIENTS]`
  embedded in `client_state_t cl`)
- **Category**: `gv`
- **Module**: engine (`hw.dll` / `hw.so`)
- **Producer**: `ida_preprocessor_scripts/find-cl_players_model.py`

## Availability

- Declared in 10 engine configs: hl-3248, hl-3266, hl-3329, hl-3647, hl-4554, hl-6153,
  hl-8684, hl-10210, cof-5936, svencoop-10257.
- Platforms: Windows + Linux.
- Inlined / absent: always present.

## Predecessors

- `studioapi_SetupPlayerModel` (produced by `find-studioapi_SetupPlayerModel{,-svencoop}`,
  consumed via `expected_input`) — the owner function whose body is scanned.

## How it is located

1. Load the verified `studioapi_SetupPlayerModel` artifact; require its `func_va` to be a
   function start.
2. Walk the body in instruction order while tracking the element **stride** of
   `playerindex` symbolically (`scale` map): `mov` from `[ebp/esp+..]` gives scale 1, `lea`
   accumulates `scale*index` (skipping frame registers), `imul` multiplies, `shl` multiplies
   by `1<<n`, `add` sums, and any other writing mnemonic clears the entry. `call` clobbers
   eax/ecx/edx.
3. A candidate is a `cmp`/`mov`/`movsx`/`lea` whose memory operand's bracket contains an
   index register with a known scale; the accumulated stride must be in
   `[MIN_STRIDE 0x170, MAX_STRIDE 0x400]` and not `DM_STRIDE 0x20C`.
4. The access must be a byte test of `model[0]`: either `cmp [..], 0` directly, or a `test`
   within the next two instructions.
5. Resolve the field: absolute address, or for SvEngine Linux PIC the effective address is
   `anchor + base_lea_disp + access_disp`, where the base register was defined by a
   GOT-anchored `lea reg, disp32[ebx]` recorded in `pic_base_defs`.
6. `gv_va` is `&cl.players[0].model` — exactly the address the anchor instruction's
   displacement (+ GOT base) resolves to, so `gv_inst_disp` resolves to `gv_va` like every
   other GV locator. Require exactly one candidate.

## Pitfalls

- **Stride** is 0x24C on WON-era builds (hl-3248..hl-3647) and 0x250 on hl-4554+, SvEngine and
  cof. Never 0x20C (that is `DM_PlayerState`).
- Reject the non-player `DM_RemapSkin` chains: their index never traces back to the
  `playerindex` stack argument, so the symbolic scale is unknown or absent.
- `player_info_t.model` sits at **+0x130** in every validated family (the leading fields
  `userid/userinfo[256]/name[32]/spectator/ping/packet_loss` never moved; DWARF-verified on
  both official `hw.so`), so the artifact is self-consistent: player `i`'s model is
  `gv_va + i*stride`, and the array head is `gv_va - 0x130`.
- The symbol was originally delivered as `cl_players` with `gv_va` = the array head and
  renamed to `cl_players_model` so the name, address and anchor instruction all agree. Do not
  reintroduce the head-relative form.
- SvEngine Linux PIC is a **two-hop** access: `lea edx, (X-2EE000h)[ebx]` then
  `[edx+eax+disp2]` → anchored as `anchor + D1 + D2` (and needs the PIC addend).
- WON-era SIB-scaled absolute operands (`lea edi, ds:...h[eax*4]` /
  `mov al, byte_X[eax*4]`) classify as `o_mem`, not `o_displ`, because the displacement
  carries the base label and the register is a pure index; both types must be accepted.
- Closure checks that must hold: hl-8684 linux `cl_resourcesonhand(0xc44744)-4 + players@0x1a40e0
  + 0x130 = 0xde8950`; hl-10210 linux `cl(nMax 0xc2fa80) + players@0x1a58e0 + model@0x130 =
  0xdd5490`. Addresses are evidence only.
- The locator requires the accepted instruction to lie in `[setup_va, setup_va + 0x400)`.
