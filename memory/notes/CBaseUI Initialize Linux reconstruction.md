---
title: CBaseUI Initialize Linux reconstruction
type: note
permalink: goldsrc-vibesignatures/notes/cbase-ui-initialize-linux-reconstruction
tags:
- cbaseui
- linux
- ida
- reconstruction
---

# CBaseUI::Initialize Linux reconstruction

## Trigger

Linux `hw.so` Hex-Rays still shows `VGuiWrap2_Startup_0` / `MEMORY[0x...]` after the Windows `CBaseUI__Initialize` restore.

## Facts

- Official source: `CBaseUI::Initialize` in `engine/vgui2/BaseUI_Interface.cpp`.
- `VGuiWrap2_Startup` at `0x193ed0` is a different wrapper that calls `IBaseUI::Initialize` virtually.
- GCC outlined `if (staticGameUIFuncs) return;` into the cdecl ABI/vtable entry `_ZN7CBaseUI10InitializeEPPFPvPKcPiEi` at `0x1c1e90`.
- The hot body is the usercall function at `0x1c1cf0` (`this@eax`, `factories@edx`). Finder artifact `CBaseUI__Initialize` must keep this body address because `VClientVGUI001` and `g_pClientFactory.linux.yaml` `gv_sig_va` live there.

## BSS split pitfall

`staticGameUIFuncs` and siblings sat inside an oversized `dword_82442C` `int[977565]` covering `.bss`. After splitting, names remained in the nlist but item flags lacked `FF_NAME`, so Hex-Rays still emitted `MEMORY[addr]`.

Correct sequence:

1. `ida_name.del_global_name(ea)`
2. `create_dword`
3. `force_name` a temporary unique name
4. `force_name` the real name
5. `SetType`
6. `ida_auto.auto_wait()` before trusting names

`make_data` alone can return ok with `size: 0` and leave the giant array intact.

## Other binary vs source mismatches (hl-10210)

- Path is a 24-byte copy of `valve/cl_dlls/gameui.so`; no `Q_snprintf` / `COM_ExpandFilename`.
- `staticCareerUI` / `CareerUI001` is live.
- Client factory is `Sys_GetFactory(hClientDLL)` after testing `cl_funcs.pClientFactory`, not `cl_funcs.pClientFactory()`.
- Naming `stack_chk_fail` makes Hex-Rays hide the GS canary check in pseudocode; the instructions remain.

## Validation

- `server_health` on `bin/hl-10210/engine/hw.so.i64`
- `analyze_function` / `decompile` at `0x1c1cf0` has no `MEMORY[` and no `VGuiWrap2_Startup_0`
- Reference: `ida_preprocessor_scripts/references/hl-10210/engine/CBaseUI__Initialize.linux.yaml`