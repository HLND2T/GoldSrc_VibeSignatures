---
title: S_LoadSound_to_FS_Open_callsite_0 locator
type: note
permalink: goldsrc-vibesignatures/locators/s-loadsound-to-fs-open-callsite-0
tags:
  - locator
  - engine
  - patch
---

# S_LoadSound_to_FS_Open_callsite_0

## Symbol

- **Name**: `S_LoadSound_to_FS_Open_callsite_0`
- **Category**: `patch`
- **Module**: engine (`hw.dll` / `hw.so`)
- **Producer**: `ida_preprocessor_scripts/find-S_LoadSound_to_FS_Open_callsites.py` (shared helper `ida_preprocessor_scripts/_func_to_func_callsites_common.py`)

## Availability

- Declared in 10 engine configs: cof-5936, hl-10210, hl-3248, hl-3266, hl-3329, hl-3647, hl-4554, hl-6153, hl-8684, svencoop-10257.
- Platforms: Windows + Linux (no `platform` gate). Linux engine modules exist only for hl-10210, hl-8684 and svencoop-10257.
- Inlined / absent: `engine/snd_mem.c` has exactly one `FS_Open(namebuffer, "rb")` in `S_LoadSound`, so the expected output set is exactly `callsite_0` on every validated build. No extra sites were observed across hl-3248..hl-10210, svencoop-10257 and cof-5936.
- Not applicable to cstrike/czero/czeror (no engine module in this repo).

## Predecessors

- `S_LoadSound.{platform}.yaml` (produced by `find-S_LoadSound`, consumed via `expected_input`).
- `FS_Open.{platform}.yaml` (produced by `find-Mod_LoadModel-decompiles`, consumed via `expected_input`).

## How it is located

Reuses the shared PR #78 owner→callee callsite pattern. Discovery is entirely address-based; **no byte signature participates in discovery** (the signature is generated only after the site is found).

1. Both predecessor YAMLs are loaded with `_function_artifact`: `func_name` must match the file and `func_va >= image_base`. Either miss fails the skill.
2. The owner is re-verified by `_inspect_function_via_mcp` on its `func_va` (honouring the owner's `func_sig_allow_across_function_boundary`) and the inspected VA must equal the artifact VA.
3. A single `py_eval` walks `FuncItems` of `S_LoadSound` and keeps each instruction that is a direct rel32 branch (`call`/`jmp`, first byte `E8`/`E9`, length >= 5) whose `XrefsFrom` code target resolves to a function whose start equals the `FS_Open` artifact VA. This is exactly the blob-engine contract: match on `func_va`, not on the IDA display name (`sub_XXXXXXXX` is fine).
4. Numbering is the owner-body instruction-address order starting at 0; the survivor set must have exactly as many entries as the expected contiguous output indexes (`callsite_0`, `callsite_1`, ...).
5. Signature generation for each site starts **at the branch instruction**: the branch's own bytes are literal (including the rel32 displacement), following instructions are appended with their operand encodings wildcarded until a boundary of at least `max(6, insn_len)` bytes is unique in executable segments (3-match early-exit cap, so anything ambiguous fails).
6. Post-checks before writing: `patch_ea >= owner_ea`, `patch_sig_disp == 0`, `insn_len > 0`, and `_find_unique_bytes(patch_sig)` must return `patch_ea`. Emits `patch_name / patch_va / patch_rva / patch_sig / patch_sig_disp`, and deliberately **no `patch_bytes`**.
7. Consumer contract: ResourceReplacer queries `S_LoadSound_to_FS_Open_callsite_0` .. `_N` and applies `MH_InlinePatchRedirectBranch` at each site to redirect to `S_LoadSound_FS_Open`, instead of hooking `FS_Open` globally.

## Pitfalls

- `patch_sig_disp` is always `0x0` because the signature starts at the branch; `patch_va`/`patch_rva` are therefore the *instruction* address, not a function address.
- The target instruction's rel32 is captured literally, so the signature is bound to that build's layout — regenerate rather than patch a signature by hand. Only the bytes of *following* instructions are wildcarded.
- Do **not** require a `push offset "rb"` before the branch. GCC/Linux writes `mov [esp+..], offset aRb` instead of a PUSH, and MetaHook's Windows-shaped `FindFSOpenCallSites` PUSH+window walk does not generalise. The production finder never looks at the argument setup.
- The owner must be a genuine function *start* (`get_func(va).start_ea == va`) and the IDB must be 32-bit; both are asserted inside the locator.
- A change in the *number* of matching sites fails closed (`found N callsites, expected M`) rather than emitting a partial set — which is what keeps the patch inventory honest.
