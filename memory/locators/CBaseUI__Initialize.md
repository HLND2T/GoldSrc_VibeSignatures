---
title: CBaseUI__Initialize locator
type: note
permalink: goldsrc-vibesignatures/locators/cbaseui-initialize
tags:
  - locator
  - engine
  - func
---

# CBaseUI__Initialize

## Symbol

- **Name**: `CBaseUI__Initialize`
- **Category**: `func`
- **Module**: engine (`hw.dll` / `hw.so`)
- **Producer**: `ida_preprocessor_scripts/find-CBaseUI__Initialize.py`

## Availability

- Declared in 10 engine configs: cof-5936, hl-10210, hl-3248, hl-3266, hl-3329, hl-3647, hl-4554, hl-6153, hl-8684, svencoop-10257.
- Platforms: metadata records this finder as Windows-only, and that is literal only for svencoop-10257 (the only config that writes `platform: windows`). The other nine configs register it with no platform gate, and the finder itself does not branch on `platform`; `bin_artifacts/hl-10210/engine/CBaseUI__Initialize.linux.yaml` and `bin_artifacts/hl-8684/engine/CBaseUI__Initialize.linux.yaml` exist. Treat it as Windows + Linux, with svencoop-10257 pinned to Windows.
- Inlined / absent: never absent, but the standalone entry differs by ABI. Windows builds keep the `if (staticGameUIFuncs) return;` guard inside the same function, so the artifact is the whole ABI-complete entry (`0x1022c130`, size `0x18e` on hl-10210). GCC outlines that guard on Linux into the cdecl ABI/vtable entry `_ZN7CBaseUI10InitializeEPPFPvPKcPiEi` at `0x1c1e90` (hl-10210), so the artifact points at the usercall hot body at `0x1c1cf0` (`this@eax`, `factories@edx`) and not at the outlined ABI entry.

## Predecessors

- None. `find-CBaseUI__Initialize` has no `expected_input`.

## How it is located

1. Single positive anchor: `xref_strings: ["FULLMATCH:VClientVGUI001"]`. `FULLMATCH:` makes `_string_candidates` require an exact C-string equality (not a substring), then collect the owning functions of every xref to those string items.
2. No other positive sources: `xref_gvs`, `xref_signatures`, `xref_funcs` are all empty, so the candidate set is exactly the set of `VClientVGUI001` owners.
3. No exclusions (`exclude_funcs` / `exclude_strings` / `exclude_gvs` / `exclude_signatures` empty).
4. Standard owner recovery (`_FUNCTION_OWNER_RECOVERY_PY_EVAL`) is injected, then the payload must contain exactly one candidate; more than one owner fails closed and nothing is written.
5. The surviving owner is renamed `CBaseUI__Initialize` with `SN_FORCE` and emitted with `func_name`, `func_sig` (generated from the recovered body), `func_va`, `func_rva`, `func_size`. There is no byte-signature anchor, no `xref_gvs` anchor, and no LLM_DECOMPILE in this finder.

## Pitfalls

- Keep the recorded `func_va`. On Linux it must stay on the usercall body (`0x1c1cf0` for hl-10210): `VClientVGUI001` is referenced from that body, and both the VClientVGUI vtable and `g_pClientFactory.{platform}.yaml` `gv_sig_va` are keyed off it. Returning the outlined cdecl ABI entry at `0x1c1e90` would silently move the consumer anchor.
- The guard's read target `staticGameUIFuncs` lives in `.bss`, and on Linux it sat inside an oversized `dword_82442C` `int[977565]` array. Splitting it needs the full sequence `ida_name.del_global_name` → `create_dword` → `force_name` (temporary unique name) → `force_name` (real name) → `SetType` → `ida_auto.auto_wait()` before trusting names; `make_data` alone can return ok with `size: 0` and leave the giant array intact, and a split that leaves items without `FF_NAME` still renders as `MEMORY[addr]` in Hex-Rays.
- Naming `stack_chk_fail` makes Hex-Rays hide the GS canary check from pseudocode even though the instructions remain; do not read pseudocode as evidence that the canary is absent.
- hl-10210's Linux/client path is a 24-byte copy of `valve/cl_dlls/gameui.so` with no `Q_snprintf` / `COM_ExpandFilename`, and `staticCareerUI` / `CareerUI001` is live; the client factory comes from `Sys_GetFactory(hClientDLL)` after *testing* `cl_funcs.pClientFactory`, not from calling it. Do not expect the local official-source revision to match line for line.
- svencoop-10257 pins the finder to `platform: windows` even though `bin/svencoop-10257/engine/hw.so` exists, so no svencoop Linux artifact is produced. That restriction is config-level, not script-level.
- Validation reference: `server_health` on `bin/hl-10210/engine/hw.so.i64`; `decompile` at `0x1c1cf0` must contain no `MEMORY[` and no `VGuiWrap2_Startup_0`.
