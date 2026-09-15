---
title: locator_summary
type: note
permalink: goldsrc-vibesignatures/locator-summary
---

# Symbol Locator Summary

所有符号定位说明的索引，覆盖 `memory/locators/` 下全部 locator 文件，按**主要定位机制**分组。
分类依据是每个 finder 的主要发现锚；部分符号实际会组合多种机制（例如先字符串锚定 owning function，再读表槽），
此处归入其决定性的一步。**Summary** 列摘自各 locator 文件 `## How it is located` 的首段。

共 **203** 个 locator；模块 engine 166，client 37。

| 定位机制 | 数量 |
| --- | --- |
| 字符串锚 | 59 |
| 浮点常量锚 | 3 |
| 表 / 结构 / 数据段扫描 | 34 |
| 确定性 xref 交集锚 | 5 |
| 前驱产物复用（下游确定性恢复） | 20 |
| LLM_DECOMPILE 定位 | 47 |
| vtable / vfunc 槽恢复 | 10 |
| 数值 scalar 提取 | 9 |
| 调用点 patch | 16 |

---

## 字符串锚 (59)

| Symbol | Module | Category | Predecessors | Summary |
| --- | --- | --- | --- | --- |
| [CBaseUI__Initialize](locators/CBaseUI__Initialize.md) | engine | func | — | Single positive anchor: xref_strings: ["FULLMATCH:VClientVGUI001"]. FULLMATCH: makes _string_candidates require an exact C-string equality (not a substring), then… |
| [CL_InitTEnts](locators/CL_InitTEnts.md) | engine | func | — | FUNC_XREFS anchors the function on FULLMATCH:sprites/shellchrome.spr — the chrome shell sprite CL_InitTEnts precaches at the very end of the function (immediately… |
| [CL_PrecacheResources](locators/CL_PrecacheResources.md) | engine | func | — | Pattern A (preprocess_func_xrefs_via_mcp) string xref, with a SvEngine-specific anchor set selected by the binary directory name (Path(new_binary_dir).parent.name == |
| [CL_ReallocateDynamicData](locators/CL_ReallocateDynamicData.md) | engine | func | — | Pattern A string xref with an exclusion set, in FUNC_XREFS: Positive: xref_strings: ["FULLMATCH:CL_Reallocate cl_entities\n"] — exact equality |
| [CL_RegisterResources](locators/CL_RegisterResources.md) | engine | func | — | Pattern A string xref in FUNC_XREFS: xref_strings: ["FULLMATCH:Setting up renderer...\n"] — exact equality. The docstring |
| [CL_Set_ServerExtraInfo](locators/CL_Set_ServerExtraInfo.md) | engine | func | `cl_parsefuncs` | Loads cl_parsefuncs.{platform}.yaml from the new binary dir and reads its gv_va as the table base TABLE_EA. If the predecessor is missing the finder returns False. |
| [CVideoMode_Common_Init](locators/CVideoMode_Common_Init.md) | engine | func | — | FUNC_XREFS_SPECS is an ordered list of two complete anchor sets, tried in order; the first that yields a single owner wins (preprocess_common_skill is called per… |
| [Cache_Alloc](locators/Cache_Alloc.md) | engine | func | — | xref_strings = ["FULLMATCH:Cache_Alloc: size %i"] — exact-match C string lookup (_string_candidates requires text == needle), then XrefsTo maps each referencing… |
| [ClientDLL_CheckStudioInterface](locators/ClientDLL_CheckStudioInterface.md) | engine | func | — | Source (engine/cdll_int.c): c R_ResetStudio(); cl_funcs.pStudioInterface = (HUD_STUDIO_INTERFACE_FUNC)GetProcAddress(hClientDLL, "HUD_GetStudioModelInterface"); |
| [ClientDLL_HudInit](locators/ClientDLL_HudInit.md) | engine | func | — | xref_strings: ["FULLMATCH:cl_righthand"] — exact-string match (not substring). The literal is used *inside* the target function (Cvar_FindVar("cl_righthand") at the… |
| [ClientDLL_Init](locators/ClientDLL_Init.md) | engine | func | — | xref_strings: ["FULLMATCH:ScreenShake"] — exact match on the literal passed to HookServerMsg("ScreenShake", ...) *inside* ClientDLL_Init. |
| [ClientPortalManager_CreateInvisiblePortalTextures](locators/ClientPortalManager_CreateInvisiblePortalTextures.md) | client | func | — | Single anchor literal: "Invalid GL_ACTIVE_TEXTURE, unable to reset. Couldn't create invisible texture for portals.\n" (note the wording: *invisible texture*… |
| [ClientPortalManager_EnableClipPlane](locators/ClientPortalManager_EnableClipPlane.md) | client | func | — | Anchor literal: "Error: Too many clip planes on portal! Maximum: 6 (Too many surfaces on brush?)\n" — owned by exactly one function on the validated 10257 client. |
| [ClientPortalManager_RenderPortals](locators/ClientPortalManager_RenderPortals.md) | client | func | — | The only semantic anchor is the exact diagnostic literal "Invalid GL_ACTIVE_TEXTURE, unable to reset. Portal not drawn.\n" (this wording is unique to |
| [ClientPortalManager_ResetAll](locators/ClientPortalManager_ResetAll.md) | client | func | `ClientPortalManager_CreateInvisiblePortalTextures` | The predecessor YAML is read from the run's new_binary_dir and its func_name must equal ClientPortalManager_CreateInvisiblePortalTextures; otherwise the finder… |
| [ClientPortal_CreateTexture](locators/ClientPortal_CreateTexture.md) | client | func | — | The finder delegates to _sven_client_pic_common.preprocess_string_owner_skill_with_pic_fallback with the exact literal |
| [Cvar_DirectSet](locators/Cvar_DirectSet.md) | engine | func | — | xref_strings: ["FULLMATCH:*PROTECTED*"] — exact literal, not substring. _string_candidates unions the owning functions of every matching string item; |
| [Cvar_Set](locators/Cvar_Set.md) | engine | func | `Cvar_DirectSet` | Find every exact Cvar_Set: variable %s not found\n string item in the live IDB. Collect the owning function of every data/code xref to those items. |
| [DT_LoadDetailTexture](locators/DT_LoadDetailTexture.md) | engine | func | — | preprocess_common_skill with a single func_xrefs entry: FULLMATCH:Detail texture map load failed: %s\n (exact C-string equality, not a |
| [D_FillRect](locators/D_FillRect.md) | engine | func | `SCR_UpdateScreen_RenderBody`, `Sys_Error`, `cl_enginefuncs` | Primary path (literal present): Collect every xref site to the C string Downloading %s. For each reference site take its *unit* — the IDA function that owns it, or… |
| [DispatchDirectUserMsg](locators/DispatchDirectUserMsg.md) | engine | func | — | FUNC_XREFS anchors on FULLMATCH:UserMsg: No pfn %s %d\n. That literal has two code xrefs — DispatchUserMsg and DispatchDirectUserMsg. The spec therefore declares… |
| [Draw_DecalTexture](locators/Draw_DecalTexture.md) | engine | func | — | preprocess_common_skill with one func_xrefs entry and a single exact-match string: FULLMATCH:Failed to load custom decal for player #%i:%s using default decal 0.\n |
| [Draw_Frame](locators/Draw_Frame.md) | engine | func | — | Draw_Frame is the shared callee of the three sprite-frame renderers, so it is found by triangulation over the three SPR_Draw* diagnostic literals rather than by its… |
| [Draw_MiptexTexture](locators/Draw_MiptexTexture.md) | engine | func | — | preprocess_common_skill with one func_xrefs entry: FULLMATCH:Draw_MiptexTexture: Bad cached wad %s\n — exact C-string equality, validated |
| [Draw_Pic](locators/Draw_Pic.md) | engine | func | `SCR_UpdateScreen_RenderBody`, `Sys_Error`, `cl_enginefuncs` | Primary path (HL/CoF, literal present): Collect every xref site to Draw_TransPic: bad coordinates. For each reference site, take its unit — the owning IDA function… |
| [Draw_SpriteFrameAdditive](locators/Draw_SpriteFrameAdditive.md) | engine | func | — | owners("Client.dll SPR_DrawAdditive error: invalid frame\n") — functions referencing that exact literal (two spaces after error:). |
| [Draw_SpriteFrameAdditive_SvEngine](locators/Draw_SpriteFrameAdditive_SvEngine.md) | engine | func | — | refs("SPR_DrawAdditive: Invalid frame %d\n") — exact SvEngine diagnostic string. family_union converts each reference site into a unit: the IDA function when the… |
| [Draw_SpriteFrameGeneric](locators/Draw_SpriteFrameGeneric.md) | engine | func | — | owners("Client.dll SPR_DrawGeneric error: invalid frame\n") — exact-match literal owner(s). Unlike the HOLES / ADDITIVE literals this one has a single space after |
| [Draw_SpriteFrameGeneric_SvEngine](locators/Draw_SpriteFrameGeneric_SvEngine.md) | engine | func | — | refs("SPR_DrawGeneric: Invalid frame %d\n") — exact SvEngine diagnostic. family_union maps each reference site to its unit: the owning IDA function, or the |
| [Draw_SpriteFrameHoles](locators/Draw_SpriteFrameHoles.md) | engine | func | — | owners("Client.dll SPR_DrawHoles error: invalid frame\n") — functions that reference the exact literal (note the two spaces after error:). Some builds have two… |
| [Draw_SpriteFrameHoles_SvEngine](locators/Draw_SpriteFrameHoles_SvEngine.md) | engine | func | — | refs("SPR_DrawHoles: Invalid frame %d\n") — the SvEngine diagnostic, exact string match. SvEngine keeps engine/cl_draw.c SPR_DrawHoles with this wording; it has no |
| [GL_Init](locators/GL_Init.md) | engine | func | — | Two string specs are tried in order, each with xref_strings and the FULLMATCH: exact-text prefix; the first spec that yields a single-owner match wins: |
| [GL_LoadFilterTexture](locators/GL_LoadFilterTexture.md) | engine | func | — | The function owns no diagnostic string, so the anchor is its constant pair: an 8*8*3 (0xC0) byte RGB (0x1907) buffer in engine/gl_draw.c. |
| [GL_SelectPixelFormat](locators/GL_SelectPixelFormat.md) | engine | func | — | Single exact-match string anchor: FULLMATCH:ChoosePixelFormat failed through xref_strings. On every legacy Windows build this MessageBox diagnostic has exactly one… |
| [GL_SetMode](locators/GL_SetMode.md) | engine | func | — | Two string specs tried in order, each with xref_strings and the FULLMATCH: exact-text prefix; the first spec yielding a single-owner match wins: |
| [GL_SetModeLegacy](locators/GL_SetModeLegacy.md) | engine | func | — | Single exact-match string anchor: FULLMATCH:Error initializing gl driver, check that the GL driver file opengl32.dll exists through xref_strings. The legacy build… |
| [GL_Shutdown](locators/GL_Shutdown.md) | engine | func | — | GL_Shutdown (engine/gl_vidnt.c, Windows) owns no diagnostic string, so the anchor is the TRACESHUTDOWN literal Sys_Shutdown() from sys_dll2.cpp. |
| [Host_ClearMemory](locators/Host_ClearMemory.md) | engine | func | — | xref_strings = ["FULLMATCH:Clearing memory\n"] — exact-match C string including the trailing newline, so the engine/host.c memory-scrub report does not collide with… |
| [Mod_FindName](locators/Mod_FindName.md) | engine | func | — | Pattern A string xref in FUNC_XREFS: xref_strings: ["FULLMATCH:Mod_FindName: NULL name"] — exact equality. The docstring |
| [Mod_LoadModel](locators/Mod_LoadModel.md) | engine | func | — | Plain preprocess_common_skill with two FUNC_XREF_ALTERNATIVES, tried in order; the first alternative that yields a single-owner match wins. Each alternative is an… |
| [Mod_LoadSpriteModel](locators/Mod_LoadSpriteModel.md) | engine | func | — | preprocess_common_skill with two FUNC_XREFS_SPECS tried in order; the first spec that produces a single-owner exact match wins: |
| [Mod_LoadStudioModel](locators/Mod_LoadStudioModel.md) | engine | func | — | preprocess_common_skill with a single exact string xref: FULLMATCH:bogus — the literal the studio loader passes to Sys_Error when the studio header fails its length… |
| [Mod_PointInLeaf](locators/Mod_PointInLeaf.md) | engine | func | — | preprocess_common_skill with a single exact string xref: FULLMATCH:Mod_PointInLeaf: bad model — the null-node guard (if (!model->nodes) Sys_Error(...)) inside the… |
| [NLoadBlob](locators/NLoadBlob.md) | engine | func | — | FUNC_XREFS declares two positive sources that preprocess_common_skill resolves through MCP and then intersects: |
| [NLoadBlobFile](locators/NLoadBlobFile.md) | engine | func | `NLoadBlob` | FUNC_XREFS declares three sources handled by preprocess_common_skill: xref_funcs: ["NLoadBlob"] — resolved to a func_va through the predecessor artifact's |
| [R_DrawTEntitiesOnList](locators/R_DrawTEntitiesOnList.md) | engine | func | — | FUNC_XREFS anchors on FULLMATCH:Non-sprite set to glow!\n — the diagnostic guarded by the glow render mode inside the transparent-entity loop. |
| [R_GetSpriteFrame](locators/R_GetSpriteFrame.md) | engine | func | — | preprocess_common_skill with a single exact string xref: FULLMATCH:Sprite: no pSprite!!!\n — the engine/cl_tent.c diagnostic printed when the frame lookup is asked… |
| [R_LoadSkys](locators/R_LoadSkys.md) | engine | func | — | preprocess_common_skill with a single exact string xref: FULLMATCH:SKY: — the engine/gl_warp.c banner printed before the six sky faces are loaded. The needle has… |
| [R_RenderView](locators/R_RenderView.md) | engine | func | — | xref_strings = ["R_RenderView: NULL worldmodel"] is the anchor: the candidate set is every function that references that literal (substring match over the IDB's… |
| [R_StudioCalcAttachments](locators/R_StudioCalcAttachments.md) | engine | func | `R_StudioDrawModel` | The finder declares a single func_xrefs entry with xref_strings: ["FULLMATCH:Too many attachments on %s\n"] — the attachment-count |
| [R_StudioSetupBones](locators/R_StudioSetupBones.md) | engine | func | — | The finder declares a single func_xrefs entry for R_StudioSetupBones with xref_strings: ["FULLMATCH:Bip01 Spine"] — no GV, signature or function xrefs. |
| [SCR_UpdateScreen_RenderBody](locators/SCR_UpdateScreen_RenderBody.md) | engine | func | — | Single string anchor: FULLMATCH:load failed.\n via xref_strings, owned by the per-frame rendering body after the loading-plaque check in engine/gl_screen.c… |
| [SV_SendServerinfo](locators/SV_SendServerinfo.md) | engine | func | — | *Generic (find-SV_SendServerinfo) xref_strings = ["BUILD %d SERVER (%i CRC)"] — substring string match (no FULLMATCH: prefix). |
| [S_LoadSound](locators/S_LoadSound.md) | engine | func | — | preprocess_common_skill with a single exact string xref: FULLMATCH:S_LoadSound: Couldn't load %s\n — the Con_DPrintf that engine/snd_mem.c emits when the sound file… |
| [SkyboxCommand](locators/SkyboxCommand.md) | engine | func | — | preprocess_common_skill with a single exact string xref: FULLMATCH:No skybox name specified\n — the usage message the SvEngine skybox console command prints when… |
| [Sys_Error](locators/Sys_Error.md) | engine | func | — | xref_strings = ["FATAL ERROR (shutting down): %s"] — substring match (the note records the anchor with a trailing \n, the script does not require it). XrefsTo on… |
| [Sys_InitMemory](locators/Sys_InitMemory.md) | engine | func | — | Both producers use the same Pattern A machinery (preprocess_common_skill → preprocess_func_xrefs_via_mcp): one FULLMATCH: string anchor, XrefsTo → owning function… |
| [VideoMode_Create](locators/VideoMode_Create.md) | engine | func | — | Single positive anchor: xref_strings: ["FULLMATCH:-fullscreen"] — exact C-string match on the fullscreen command-line literal, then the owning functions of its… |
| [g_pClientFactory](locators/g_pClientFactory.md) | engine | gv | `CBaseUI__Initialize` | Despite the -decompiles suffix this finder is not LLM-based: it runs one direct py_eval locator (LOCATE_PY) inside the owner function and fails closed on any… |

## 浮点常量锚 (3)

| Symbol | Module | Category | Predecessors | Summary |
| --- | --- | --- | --- | --- |
| [BuildGammaTable](locators/BuildGammaTable.md) | engine | func | — | xref_floats = ["1023.0", "0.075", "0.875"] is the *sole* positive source (positive_sets stays empty, so the float set becomes the candidate set). |
| [R_DrawParticles](locators/R_DrawParticles.md) | engine | func | — | xref_floats = ["20.0", "0.004"] is the sole positive source; the candidate set is every function whose body references both constants. |
| [R_GlowBlend](locators/R_GlowBlend.md) | engine | func | `R_DrawTEntitiesOnList` | xref_floats = ["19000.0", "0.005", "0.05"] is the sole positive source, combined with exclude_funcs = ["R_DrawTEntitiesOnList"]. |

## 表 / 结构 / 数据段扫描 (34)

| Symbol | Module | Category | Predecessors | Summary |
| --- | --- | --- | --- | --- |
| [CGame_DrawStartupVideo](locators/CGame_DrawStartupVideo.md) | engine | func | — | Single positive anchor: xref_strings: ["FULLMATCH:WebMPlayer::PlayVideo %s\n"] — an exact C-string match on the diagnostic literal *including* the %s format… |
| [CL_CreateVisibleEntity](locators/CL_CreateVisibleEntity.md) | engine | func | `cl_enginefuncs` | Load cl_enginefuncs.{platform}.yaml, read gv_va, and compute entry = gv_va + 61 * 4 — SDK cl_enginefunc_t slot 61 is CL_CreateVisibleEntity. |
| [CL_IsThirdPerson](locators/CL_IsThirdPerson.md) | client | func | — | Primary path: exactly one idautils.Entries() entry named CL_IsThirdPerson whose ida_funcs.get_func(ea).start_ea == ea. |
| [CVideoMode_Common_PlayStartupSequence](locators/CVideoMode_Common_PlayStartupSequence.md) | engine | func | `VideoMode_Create` | A plain string xref cannot select this function: the -novid literal has two raw owners. The finder therefore walks the VideoMode vtables instead: |
| [ClientPortal_Constructor](locators/ClientPortal_Constructor.md) | client | func | `ClientPortalManager_RenderPortals` | The RenderPortals YAML must exist, have func_name == ClientPortalManager_RenderPortals, and yield a parsable func_va; otherwise the finder returns False. |
| [DM_PlayerState](locators/DM_PlayerState.md) | engine | gv | `studioapi_SetupPlayerModel` | Load the verified studioapi_SetupPlayerModel artifact and require its func_va to be an exact function start in the current IDB. |
| [DT_Initialize](locators/DT_Initialize.md) | engine | func | `SCR_UpdateScreen_RenderBody`, `Sys_Error`, `cl_enginefuncs` | Enumerate every idautils.Functions() entry and decode its instructions; keep the functions whose body carries an immediate operand equal to GL_RGB_SCALE (0x8573). |
| [Draw_FillRGBA](locators/Draw_FillRGBA.md) | engine | func | `SCR_UpdateScreen_RenderBody`, `Sys_Error`, `cl_enginefuncs` | Read cl_enginefuncs's gv_va and compute the slot address table + 11 * 4 (cl_enginefunc_t field order, engine/APIProxy.h). |
| [Draw_FillRGBABlend](locators/Draw_FillRGBABlend.md) | engine | func | `SCR_UpdateScreen_RenderBody`, `Sys_Error`, `cl_enginefuncs` | Slot address = cl_enginefuncs.gv_va + 130 * 4 (cl_enginefunc_t field order, engine/APIProxy.h). The dword at the slot must be a function start, otherwise |
| [HUD_GetStudioModelInterface](locators/HUD_GetStudioModelInterface.md) | client | func | — | Primary path: idautils.Entries() must contain exactly one entry named HUD_GetStudioModelInterface whose ida_funcs.get_func(ea).start_ea == ea (an exact |
| [PVSNode](locators/PVSNode.md) | engine | func | — | Structurally identify the engine triangleapi_t table (engine/r_triangle.c) in data segments: a dword 1 (TRI_API_VERSION) followed by 19 consecutive dwords that are… |
| [R_GLStudioDrawPoints](locators/R_GLStudioDrawPoints.md) | engine | func | `studioapi_GetCurrentEntity`, `studioapi_SetChromeOrigin`, `studioapi_SetRenderModel`, `studioapi_StudioSetHeader` | Load all four studioapi artifacts; a missing one aborts. Locate engine_studio_api_t by scanning data segments for the stored studioapi_GetCurrentEntity pointer… |
| [R_StudioCheckBBox](locators/R_StudioCheckBBox.md) | engine | func | — | For each diagnostic string in (HL_STUDIO_STRING, SVC_STUDIO_STRING) — the ClientDLL_CheckStudioInterface interface-mismatch wording, HL vs SvEngine — call the |
| [R_StudioDrawModel](locators/R_StudioDrawModel.md) | engine | func | `R_StudioDrawPlayer` | Re-run the same &pStudioAPI locator as R_StudioDrawPlayer: unique ClientDLL_CheckStudioInterface diagnostic (HL wording for the generic finder, SvEngine |
| [R_StudioDrawPlayer](locators/R_StudioDrawPlayer.md) | engine | func | `studioapi_SetupPlayerModel` | Find the unique ClientDLL_CheckStudioInterface diagnostic — HL family: Couldn't get client .dll studio model rendering interface. Version mismatch?\n; |
| [SDL_InitGL](locators/SDL_InitGL.md) | engine | func | — | Single exact-match string anchor: FULLMATCH:glAccum through xref_strings — the GL procedure name with no trailing newline. |
| [VGui_ViewportPaintBackground](locators/VGui_ViewportPaintBackground.md) | engine | func | `cl_enginefuncs` | Load cl_enginefuncs.{platform}.yaml, read gv_va, compute entry = gv_va + 78 * 4 — SDK cl_enginefunc_t slot 78 is VGui_ViewportPaintBackground. |
| [V_CalcRefdef](locators/V_CalcRefdef.md) | client | func | — | Primary path: exactly one idautils.Entries() entry named V_CalcRefdef whose ida_funcs.get_func(ea).start_ea == ea. Sven's client.so/client.dll exports it |
| [cl_parsefuncs](locators/cl_parsefuncs.md) | engine | gv | — | Find the unique FULLMATCH:svc_bad C string. It is unique in every current engine binary and lives inside the table, never in a function body. |
| [cl_resourcesonhand](locators/cl_resourcesonhand.md) | engine | gv | `CL_PrecacheResources` | The sentinel is &cl.resourcesonhand. CL_PrecacheResources walks that circular list: pResource = cl.resourcesonhand.pNext loads through [sentinel+0x80], and the loop… |
| [currententity](locators/currententity.md) | engine | gv | — | The engine_studio_api table is recovered first (see studioapi_GetCurrentEntity), then fixed slot 0x18 names the accessor. |
| [engine](locators/engine.md) | engine | gv | — | Find the exact literal "Sys_InitArgv( OrigCmd )" (owned by RunListenServer, engine/sys_dll2.cpp) and require exactly one function owner. |
| [g_ChromeOrigin](locators/g_ChromeOrigin.md) | engine | gv | — | Recover the engine_studio_api table and fixed slot 0x9C. cluster_bases folds the accessor's writable refs into clusters; VectorCopy(r_origin, |
| [g_pGameStudioRenderer](locators/g_pGameStudioRenderer.md) | client | gv | `HUD_GetStudioModelInterface` | Same root as the renderer vtable: the exported HUD_GetStudioModelInterface body yields the returned r_studio_interface_t (version == 1), whose [studio+4, studio+8]… |
| [g_ppStudioInterfaceCall](locators/g_ppStudioInterfaceCall.md) | engine | gv | — | Recommended chain (source engine/cdll_int.c; cl_funcs.pStudioInterface(STUDIO_INTERFACE_VERSION, &pStudioAPI, &engine_studio_api)): |
| [pstudiohdr](locators/pstudiohdr.md) | engine | gv | — | Recover the engine_studio_api table (see studioapi_StudioSetHeader) and fixed slot 0x8C. The accessor must write exactly one writable global and read none; that… |
| [r_model](locators/r_model.md) | engine | gv | — | Recover the engine_studio_api table and fixed slot 0x90. The accessor must write exactly one writable global and read none; that store target is |
| [r_origin](locators/r_origin.md) | engine | gv | — | Recover the engine_studio_api table and fixed slot 0x9C. In the accessor body, group writable-data refs into clusters (cluster_bases, values |
| [studioapi_GetCurrentEntity](locators/studioapi_GetCurrentEntity.md) | engine | func | — | Same root as studioapi_SetupPlayerModel: the unique studio-interface diagnostic (client .dll wording for GoldSrc/HL25/CoF, client library for SvEngine) → owning |
| [studioapi_SetChromeOrigin](locators/studioapi_SetChromeOrigin.md) | engine | func | — | Unique studio-interface diagnostic → owning function(s) → unique engine_studio_api table. Read ABI slot SLOT_OFF = 0x9C; must be a function start. |
| [studioapi_SetRenderModel](locators/studioapi_SetRenderModel.md) | engine | func | — | Unique studio-interface diagnostic → owning function(s) → unique engine_studio_api table. Read ABI slot SLOT_OFF = 0x90; must be a function start. |
| [studioapi_SetupPlayerModel](locators/studioapi_SetupPlayerModel.md) | engine | func | — | Find the exact ClientDLL_CheckStudioInterface interface-mismatch literal and require exactly one hit. GoldSrc/HL25/CoF wording is |
| [studioapi_StudioSetHeader](locators/studioapi_StudioSetHeader.md) | engine | func | — | Unique studio-interface diagnostic → owning function(s) → unique engine_studio_api table (validate_table_run; SvEngine 47/48 entries). |
| [studioapi_StudioSetRenderamt](locators/studioapi_StudioSetRenderamt.md) | engine | func | — | Find the exact studio-interface diagnostic literal: HL_STUDIO_STRING ("Couldn't get client .dll studio model rendering interface. Version mismatch?\n") for… |

## 确定性 xref 交集锚 (5)

| Symbol | Module | Category | Predecessors | Summary |
| --- | --- | --- | --- | --- |
| [CL_Parse_SetView](locators/CL_Parse_SetView.md) | engine | func | `cl_parsefuncs` | Load cl_parsefuncs.{platform}.yaml and take TABLE_EA = gv_va. Return {} for 64-bit databases. Walk up to 80 entries of 12 bytes each (svc_func_t = {opcode, pszname… |
| [NET_DrawRect](locators/NET_DrawRect.md) | engine | func | — | Pure disassembly walk over idautils.Functions(); no byte pattern is used anywhere (find-R124 style byte-pattern hints are explicitly not the anchor). |
| [R_StudioDrawPlayerBody](locators/R_StudioDrawPlayerBody.md) | engine | func | `R_StudioDrawPlayer` | Load R_StudioDrawPlayer.{platform}.yaml; abort if absent. Start target = func_va of that entry. Walk the *unique external tail jump* chain. For the current target… |
| [R_StudioRenderModel](locators/R_StudioRenderModel.md) | engine | func | `R_StudioCalcAttachments`, `R_StudioDrawModel`, `R_StudioDrawPlayer`, `R_StudioSetupBones`, `cl_sprite_shell`, `g_ChromeOrigin` | The func_xrefs entry declares xref_gvs: ["cl_sprite_shell", "g_ChromeOrigin"] and no strings/signatures/functions: the candidate is the function that intersects the… |
| [V_StartPitchDrift](locators/V_StartPitchDrift.md) | client | func | — | _client_registration_common.REGISTRATION_QUERY is invoked with the label centerview. The helper collects strings whose NUL-terminated bytes end with the label |

## 前驱产物复用（下游确定性恢复） (20)

| Symbol | Module | Category | Predecessors | Summary |
| --- | --- | --- | --- | --- |
| [CL_FxBlend](locators/CL_FxBlend.md) | engine | func | `studioapi_StudioSetRenderamt` | Load the predecessor artifact; require func_name == studioapi_StudioSetRenderamt and func_va >= image_base (fails closed on a missing or malformed dependency). |
| [CVideoMode_Common_DrawStartupGraphic](locators/CVideoMode_Common_DrawStartupGraphic.md) | engine | func | `CVideoMode_Common_Init`, `CVideoMode_Common_PlayStartupSequence` | This is an LLM_DECOMPILE finder (found_call) whose *reference* is branched by build family while the *target* is always the current build's predecessor: |
| [ClientDLL_Shutdown](locators/ClientDLL_Shutdown.md) | engine | func | `ClientDLL_Init` | Load the ClientDLL_Init.{platform}.yaml artifact from the new binary dir and re-verify it in the live IDB with _inspect_function_via_mcp (function start plus… |
| [ClientScoreInfoHandler](locators/ClientScoreInfoHandler.md) | client | func | — | _client_registration_common.REGISTRATION_QUERY recovers cdecl registration arguments for the message name ScoreInfo. Candidate strings are those whose… |
| [Host_IsSinglePlayerGame](locators/Host_IsSinglePlayerGame.md) | engine | func | `studioapi_SetupPlayerModel` | Source: qboolean Host_IsSinglePlayerGame(void) { if (sv.active) return svs.maxclients == 1; else return cl.maxclients == 1; } (engine/host.c); it is consumed by |
| [Mod_UnloadSpriteTextures](locators/Mod_UnloadSpriteTextures.md) | engine | func | `ClientDLL_Shutdown` | Graph walk below the predecessor, not a string anchor and no byte signature participates in discovery: Load ClientDLL_Shutdown.{platform}.yaml and take its func_va. |
| [R_AnimateLight](locators/R_AnimateLight.md) | engine | func | `R_CheckVariables` | Load the R_CheckVariables artifact func_va; missing artifact or missing func_va fails closed. Find every caller of R_CheckVariables (CodeRefsTo -> owning function).… |
| [R_BeamDrawList](locators/R_BeamDrawList.md) | engine | func | `R_DrawParticles` | Load the R_DrawParticles artifact func_va; the walk covers only that function's body. Enumerate the renderer's internal direct calls (exact function starts, size >… |
| [R_CheckVariables](locators/R_CheckVariables.md) | engine | func | `GL_LoadFilterTexture` | xref_funcs = ["GL_LoadFilterTexture"]: resolve the dependency artifact's func_va into the IDB, then build the candidate set as every function that has any xref to… |
| [R_ForceCVars](locators/R_ForceCVars.md) | engine | func | `R_CheckVariables` | Load the R_CheckVariables artifact func_va. Require exactly one caller host of R_CheckVariables (R_SetupFrame, or R_RenderScene with R_SetupFrame inlined). |
| [R_FreeDeadParticles](locators/R_FreeDeadParticles.md) | engine | func | `R_DrawParticles` | Load the R_DrawParticles artifact func_va; the walk covers only the renderer body and its direct callees. Seed the candidate pool from two sources: |
| [R_ResetLatched](locators/R_ResetLatched.md) | engine | func | — | Find the unique NUL-terminated C string "Tried to link edict %i without model\n" in non-executable segments, then collect the owners of every data reference to it.… |
| [R_StudioChangePlayerModel](locators/R_StudioChangePlayerModel.md) | engine | func | `studioapi_SetupPlayerModel` | Load the verified studioapi_SetupPlayerModel artifact; require its func_va to be a function start in the current IDB. |
| [R_StudioSaveBones](locators/R_StudioSaveBones.md) | engine | func | `R_StudioCalcAttachments`, `R_StudioDrawModel`, `R_StudioDrawPlayer`, `R_StudioDrawPlayerBody`, `R_StudioMergeBones`, `R_StudioSetupBones`, `cached_bonename`, `cached_numbones` | Deterministic intersection locator (no LLM): Load all eight predecessor artifacts and read cached_numbones.gv_va, |
| [R_TracerDraw](locators/R_TracerDraw.md) | engine | func | `R_DrawParticles` | Load the R_DrawParticles artifact func_va; the walk covers only that function's body. Enumerate the renderer's internal direct calls (exact function starts, size >… |
| [S_ExtraUpdate](locators/S_ExtraUpdate.md) | engine | func | `R_CheckVariables`, `R_RenderView` | Load both predecessor func_va values; either missing fails closed. Recover R_RenderScene without a stored artifact. Primary path: the unique function that is both a… |
| [cl_players_model](locators/cl_players_model.md) | engine | gv | `studioapi_SetupPlayerModel` | Load the verified studioapi_SetupPlayerModel artifact; require its func_va to be a function start. Walk the body in instruction order while tracking the element… |
| [cvar_hooks](locators/cvar_hooks.md) | engine | gv | `Cvar_DirectSet`, `Cvar_Set` | Load both predecessor artifacts from the new binary dir, resolve their func_va, and confirm Cvar_Set still verifies in the live IDB via _inspect_function_via_mcp… |
| [g_PlayerExtraInfo](locators/g_PlayerExtraInfo.md) | client | gv | `ClientScoreInfoHandler` | The predecessor's annotated body is the reference; the dedicated prompt prompt/call_llm_scoreinfo.md is used (not the generic decompile prompt), with reference YAML… |
| [g_PlayerExtraInfo_CZDS](locators/g_PlayerExtraInfo_CZDS.md) | client | gv | `ClientScoreInfoHandler` | The producer picks the symbol by output declaration: _output_for_symbol(expected_outputs, "g_PlayerExtraInfo_CZDS") selects the CZDS name and family =… |

## LLM_DECOMPILE 定位 (47)

| Symbol | Module | Category | Predecessors | Summary |
| --- | --- | --- | --- | --- |
| [CL_TempEntInit](locators/CL_TempEntInit.md) | engine | func | `CL_InitTEnts` | Requires the current CL_InitTEnts.{platform}.yaml; if it is missing the finder returns False (no fallback until then). |
| [FS_Open](locators/FS_Open.md) | engine | func | `Mod_LoadModel` | LLM_DECOMPILE, not a string anchor — FS_Open has no single-owner literal of its own. find-Mod_LoadModel must have produced Mod_LoadModel.{platform}.yaml; its… |
| [FreeBlob](locators/FreeBlob.md) | engine | func | `ClientDLL_Init`, `ClientDLL_Shutdown` | Both variants use the LLM_DECOMPILE chain with expected_result_sections: ["found_call"]: The predecessor YAML supplies an annotated disassembly/pseudocode reference: |
| [GL_BeginRendering](locators/GL_BeginRendering.md) | engine | func | `SCR_UpdateScreen_RenderBody` | LLM_DECOMPILE spec, symbol_name = GL_BeginRendering, reference references/{gamever}/engine/SCR_UpdateScreen_RenderBody.{platform}.yaml, prompt… |
| [GL_Bind](locators/GL_Bind.md) | engine | func | `GL_BuildLightmaps` | One LLM_DECOMPILE spec, symbol_name = GL_Bind, reference references/{gamever}/engine/GL_BuildLightmaps.{platform}.yaml, prompt prompt/call_llm_decompile.md… |
| [GL_BuildLightmaps](locators/GL_BuildLightmaps.md) | engine | func | `R_NewMap` | The branch is chosen from the current (gamever, platform) tag; unknown tags fall back to the R_NewMap chain. Addresses, byte patterns and call ordinals are never… |
| [GL_EndRendering](locators/GL_EndRendering.md) | engine | func | `SCR_UpdateScreen_RenderBody` | LLM_DECOMPILE spec, symbol_name = GL_EndRendering, reference references/{gamever}/engine/SCR_UpdateScreen_RenderBody.{platform}.yaml, prompt… |
| [GL_Finish2D](locators/GL_Finish2D.md) | engine | func | `SCR_UpdateScreen_RenderBody` | LLM_DECOMPILE spec, symbol_name = GL_Finish2D, reference references/{gamever}/engine/SCR_UpdateScreen_RenderBody.{platform}.yaml, prompt… |
| [GL_LoadTexture2](locators/GL_LoadTexture2.md) | engine | func | `DT_LoadDetailTexture`, `Draw_MiptexTexture` | *A. find-GL_LoadTexture2 (string waterfall). Two specs tried in order, each xref_strings with the FULLMATCH: exact-text prefix; the first single-owner match wins: |
| [GL_SelectTexture](locators/GL_SelectTexture.md) | engine | func | `GL_BuildLightmaps` | Same finder and same reference body as GL_Bind: an LLM_DECOMPILE spec with symbol_name = GL_SelectTexture, reference… |
| [GL_Set2D](locators/GL_Set2D.md) | engine | func | `SCR_UpdateScreen_RenderBody` | LLM_DECOMPILE spec, symbol_name = GL_Set2D, reference references/{gamever}/engine/SCR_UpdateScreen_RenderBody.{platform}.yaml, prompt prompt/call_llm_decompile.md… |
| [GL_UnloadTextures](locators/GL_UnloadTextures.md) | engine | func | `R_NewMap` | -decompiles (LLM) finder — no deterministic anchor of its own: Load the required predecessor R_NewMap.{platform}.yaml, export that function from the |
| [Hunk_AllocName](locators/Hunk_AllocName.md) | engine | func | `Mod_LoadSpriteModel` | *Windows / general path (find-Hunk_AllocName) xref_strings = ["FULLMATCH:Hunk_Alloc: bad size: %i"] — exact-match C string. The finder docstring |
| [Mod_LoadBrushModel](locators/Mod_LoadBrushModel.md) | engine | func | `Mod_LoadModel` | Two producers, split by family/platform: Windows (all 10 configs) and classic Linux — find-Mod_LoadBrushModel uses the exact string xref… |
| [R_CullBox](locators/R_CullBox.md) | engine | func | `R_StudioCheckBBox` | Pure LLM_DECOMPILE finder (no deterministic anchor of its own): Load the required predecessor R_StudioCheckBBox.{platform}.yaml. |
| [R_LoadSkyBox_SvEngine](locators/R_LoadSkyBox_SvEngine.md) | engine | func | `SkyboxCommand` | Two producers, split by platform: Windows (svencoop-10257) — find-R_LoadSkyBox_SvEngine uses the exact string xref FULLMATCH:desert. The outer loader gates on the… |
| [R_NewMap](locators/R_NewMap.md) | engine | func | `CL_RegisterResources` | Two independent paths: find-R_NewMap (HL / CoF families) — Pattern A string xref: xref_strings: ["FULLMATCH:window02_1"] (exact literal; the map reset searches |
| [R_StudioMergeBones](locators/R_StudioMergeBones.md) | engine | func | `R_StudioDrawPlayerBody` | This is a pure preprocess_common_skill *LLM_DECOMPILE* finder — there is no deterministic anchor chain of its own: |
| [R_StudioRenderFinal](locators/R_StudioRenderFinal.md) | engine | func | `R_StudioRenderModel` | Pure LLM_DECOMPILE finder (no deterministic anchor of its own): Load the required predecessor R_StudioRenderModel.{platform}.yaml. |
| [V_RenderView](locators/V_RenderView.md) | engine | func | `VGui_ViewportPaintBackground` | Requires the current VGui_ViewportPaintBackground.{platform}.yaml; returns False without it. LLM_DECOMPILE spec: symbol V_RenderView, prompt… |
| [allow_cheats](locators/allow_cheats.md) | engine | gv | `CL_Set_ServerExtraInfo` | Uses the generic preprocess_common_skill LLM_DECOMPILE path with prompt/call_llm_decompile.md and reference YAML… |
| [build_number](locators/build_number.md) | engine | func | `SV_SendServerinfo` | This is a Pattern E (-decompiles) finder: a symbolic LLM_DECOMPILE spec instead of a string anchor. TARGET_FUNCTION_NAMES = ["build_number"], no FUNC_XREFS. The… |
| [cached_bonename](locators/cached_bonename.md) | engine | gv | `R_StudioMergeBones` | -decompiles (LLM) finder, run in the same batch as cached_numbones: Load the required predecessor R_StudioMergeBones.{platform}.yaml. |
| [cached_numbones](locators/cached_numbones.md) | engine | gv | `R_StudioMergeBones` | -decompiles (LLM) finder — no deterministic anchor of its own: Load the required predecessor R_StudioMergeBones.{platform}.yaml. |
| [cl_enginefuncs](locators/cl_enginefuncs.md) | engine | gv | `ClientDLL_HudInit`, `ClientDLL_Init` | ### find-ClientDLL_HudInit-decompiles (HL and SvEngine Windows, HL Linux) Load ClientDLL_Init.{platform}.yaml, re-verify the owner in the live IDB |
| [cl_entities](locators/cl_entities.md) | engine | gv | `CL_ReallocateDynamicData` | -decompiles (LLM) finder — no deterministic anchor of its own: Load the required predecessor CL_ReallocateDynamicData.{platform}.yaml, export that |
| [cl_frames](locators/cl_frames.md) | engine | gv | `CL_ReallocateDynamicData` | -decompiles (LLM) finder — no deterministic anchor of its own: Load the required predecessor CL_ReallocateDynamicData.{platform}.yaml, export that |
| [cl_funcs](locators/cl_funcs.md) | engine | gv | `ClientDLL_HudInit`, `ClientDLL_Init` | _write_direct_globals first loads ClientDLL_Init.{platform}.yaml and re-verifies the owner in the live IDB (_inspect_function_via_mcp, honouring the artifact's |
| [cl_max_edicts](locators/cl_max_edicts.md) | engine | gv | `CL_ReallocateDynamicData` | -decompiles (LLM) finder — no deterministic anchor of its own: Load the required predecessor CL_ReallocateDynamicData.{platform}.yaml, export that |
| [cl_numvisedicts](locators/cl_numvisedicts.md) | engine | gv | `CL_CreateVisibleEntity` | Requires the current CL_CreateVisibleEntity.{platform}.yaml; returns False without it. LLM_DECOMPILE spec: symbol cl_numvisedicts, prompt… |
| [cl_parsecount](locators/cl_parsecount.md) | engine | gv | `R_DrawTEntitiesOnList` | Load R_DrawTEntitiesOnList.{platform}.yaml, read func_va, and export the function via _export_llm_function (disassembly + pseudocode). |
| [cl_sprite_shell](locators/cl_sprite_shell.md) | engine | gv | `CL_InitTEnts` | Requires the current CL_InitTEnts.{platform}.yaml and returns False without it. LLM_DECOMPILE spec: symbol cl_sprite_shell, prompt prompt/call_llm_decompile.md… |
| [cl_viewentity](locators/cl_viewentity.md) | engine | gv | `CL_Parse_SetView` | Requires the current CL_Parse_SetView.{platform}.yaml; returns False without it. LLM_DECOMPILE spec: symbol cl_viewentity, prompt prompt/call_llm_decompile.md… |
| [cl_visedicts](locators/cl_visedicts.md) | engine | gv | `CL_CreateVisibleEntity` | Requires the current CL_CreateVisibleEntity.{platform}.yaml; returns False without it. LLM_DECOMPILE spec: symbol cl_visedicts, prompt prompt/call_llm_decompile.md… |
| [cl_worldmodel](locators/cl_worldmodel.md) | engine | gv | `R_NewMap` | -decompiles (LLM) finder — no deterministic anchor of its own: Load the required predecessor R_NewMap.{platform}.yaml, export that function from the |
| [gClientUserMsgs](locators/gClientUserMsgs.md) | engine | gv | `DispatchDirectUserMsg` | Requires the current DispatchDirectUserMsg.{platform}.yaml; returns False without it. LLM_DECOMPILE spec: symbol gClientUserMsgs, prompt… |
| [gTempEnts](locators/gTempEnts.md) | engine | gv | `CL_InitTEnts`, `CL_TempEntInit` | Both routes are LLM found_gv specs fed an annotated predecessor reference: find-CL_InitTEnts-decompiles: LLM_DECOMPILE symbol gTempEnts, prompt… |
| [g_ViewEntityIndex_SCClient](locators/g_ViewEntityIndex_SCClient.md) | client | gv | `GameStudioRenderer_StudioDrawPlayer` | The producer calls preprocess_common_skill with gv_names = ["g_ViewEntityIndex_SCClient"], llm_decompile_specs pointing at the Sven |
| [g_bRenderingPortals_SCClient](locators/g_bRenderingPortals_SCClient.md) | client | gv | `V_CalcRefdef` | preprocess_common_skill runs the generic LLM_DECOMPILE path with prompt/call_llm_decompile.md and reference YAML |
| [g_iUser1](locators/g_iUser1.md) | client | gv | `CL_IsThirdPerson` | TARGET_GLOBAL_NAMES = ["g_iUser1", "g_iUser2"] are recovered together by preprocess_common_skill using the generic prompt/call_llm_decompile.md and reference |
| [g_iUser2](locators/g_iUser2.md) | client | gv | `CL_IsThirdPerson` | Recovered together with g_iUser1 — TARGET_GLOBAL_NAMES = ["g_iUser1", "g_iUser2"] produces one LLM_DECOMPILE spec per name, both against |
| [g_phClientModule](locators/g_phClientModule.md) | engine | gv | `ClientDLL_HudInit`, `ClientDLL_Init` | This symbol is the LLM_DECOMPILE half of find-ClientDLL_HudInit-decompiles; it runs only after the deterministic _write_direct_globals phase has successfully emitted |
| [g_pitchdrift](locators/g_pitchdrift.md) | client | gv | `V_StartPitchDrift` | _prepare_llm_context resolves the predecessor reference YAML references/svencoop-10257/client/V_StartPitchDrift.{platform}.yaml; exactly one target |
| [mod_known](locators/mod_known.md) | engine | gv | `Mod_FindName` | -decompiles (LLM) finder — no deterministic anchor of its own: Load the required predecessor Mod_FindName.{platform}.yaml, export that function from |
| [mod_numknown](locators/mod_numknown.md) | engine | gv | `Mod_FindName` | -decompiles (LLM) finder — no deterministic anchor of its own: Load the required predecessor Mod_FindName.{platform}.yaml, export that function from |
| [r_worldentity](locators/r_worldentity.md) | engine | gv | `R_NewMap` | -decompiles (LLM) finder — no deterministic anchor of its own: Load the required predecessor R_NewMap.{platform}.yaml and export that function from the |
| [videomode](locators/videomode.md) | engine | gv | `VideoMode_Create` | This is a real LLM_DECOMPILE finder (found_gv, with the annotated predecessor as reference): _prepare_llm_dependency_contract loads… |

## vtable / vfunc 槽恢复 (10)

| Symbol | Module | Category | Predecessors | Summary |
| --- | --- | --- | --- | --- |
| [GameStudioRenderer_StudioCalcAttachments](locators/GameStudioRenderer_StudioCalcAttachments.md) | client | vfunc | `GameStudioRenderer_StudioDrawModel`, `GameStudioRenderer_vtable` | preprocess_common_skill with this name in func_names and func_vtable_relations = ("GameStudioRenderer_StudioCalcAttachments", "GameStudioRenderer"). |
| [GameStudioRenderer_StudioDrawModel](locators/GameStudioRenderer_StudioDrawModel.md) | client | vfunc | `HUD_GetStudioModelInterface` | HUD_GetStudioModelInterface supplies func_va (the client's public studio entry export). The finder requires 32-bit x86 and an exact function start; anything else… |
| [GameStudioRenderer_StudioDrawPlayer](locators/GameStudioRenderer_StudioDrawPlayer.md) | client | vfunc | `GameStudioRenderer_StudioDrawModel`, `GameStudioRenderer_vtable` | The producer runs preprocess_common_skill with the six renderer virtuals as func_names, func_vtable_relations = (name, "GameStudioRenderer") for each, and… |
| [GameStudioRenderer_StudioMergeBones](locators/GameStudioRenderer_StudioMergeBones.md) | client | vfunc | `GameStudioRenderer_StudioDrawModel`, `GameStudioRenderer_vtable` | preprocess_common_skill with this name in func_names and func_vtable_relations = ("GameStudioRenderer_StudioMergeBones", "GameStudioRenderer"). |
| [GameStudioRenderer_StudioRenderFinal](locators/GameStudioRenderer_StudioRenderFinal.md) | client | vfunc | `GameStudioRenderer_StudioRenderModel`, `GameStudioRenderer_vtable` | preprocess_common_skill with func_names = ["GameStudioRenderer_StudioRenderFinal"] and func_vtable_relations = ("GameStudioRenderer_StudioRenderFinal"… |
| [GameStudioRenderer_StudioRenderModel](locators/GameStudioRenderer_StudioRenderModel.md) | client | vfunc | `GameStudioRenderer_StudioDrawModel`, `GameStudioRenderer_vtable` | Produced by the DrawModel decompile finder — not by find-GameStudioRenderer_StudioRenderModel-decompiles, which consumes this artifact as its |
| [GameStudioRenderer_StudioSaveBones](locators/GameStudioRenderer_StudioSaveBones.md) | client | vfunc | `GameStudioRenderer_StudioDrawModel`, `GameStudioRenderer_vtable` | preprocess_common_skill with this name in func_names and func_vtable_relations = ("GameStudioRenderer_StudioSaveBones", "GameStudioRenderer"). |
| [GameStudioRenderer_StudioSetupBones](locators/GameStudioRenderer_StudioSetupBones.md) | client | vfunc | `GameStudioRenderer_StudioDrawModel`, `GameStudioRenderer_vtable` | preprocess_common_skill with this name in func_names and func_vtable_relations = ("GameStudioRenderer_StudioSetupBones", "GameStudioRenderer"). |
| [GameStudioRenderer__StudioDrawPlayer](locators/GameStudioRenderer__StudioDrawPlayer.md) | client | vfunc | `GameStudioRenderer_StudioDrawPlayer`, `GameStudioRenderer_vtable` | Load the outer wrapper's func_va from the GameStudioRenderer_StudioDrawPlayer artifact and the entry map from GameStudioRenderer_vtable. |
| [GameStudioRenderer_vtable](locators/GameStudioRenderer_vtable.md) | client | vtable | `HUD_GetStudioModelInterface` | The finder first proves the renderer object: from the exported HUD_GetStudioModelInterface body it locates the returned r_studio_interface_t (version == 1, +4/+8… |

## 数值 scalar 提取 (9)

| Symbol | Module | Category | Predecessors | Summary |
| --- | --- | --- | --- | --- |
| [ClientPortalManager_vector_begin_offset](locators/ClientPortalManager_vector_begin_offset.md) | client | scalar | `ClientPortalManager_EnableClipPlane`, `ClientPortalManager_RenderPortals`, `ClientPortal_Constructor` | RenderPortals' YAML is read from new_binary_dir; func_name must match and func_va must be >= image_base, else the finder fails closed. |
| [ClientPortalManager_vector_end_offset](locators/ClientPortalManager_vector_end_offset.md) | client | scalar | `ClientPortalManager_EnableClipPlane`, `ClientPortalManager_RenderPortals`, `ClientPortal_Constructor` | Identical anchor chain to ClientPortalManager_vector_begin_offset; the two values are always recovered as one candidate pair by… |
| [ClientPortalSource_mode_offset](locators/ClientPortalSource_mode_offset.md) | client | scalar | `ClientPortalManager_EnableClipPlane`, `ClientPortalManager_RenderPortals`, `ClientPortal_Constructor` | The finder loads all three predecessor YAMLs, requires each func_name to match, and parses their func_vas (constructor, clip, render). |
| [ClientPortal_angles_offset](locators/ClientPortal_angles_offset.md) | client | scalar | `ClientPortalManager_EnableClipPlane`, `ClientPortalManager_RenderPortals`, `ClientPortal_Constructor` | Same chain as ClientPortal_origin_offset — both values come from a single _portal_layout.constructor_offsets call inside one run_layout_walk: |
| [ClientPortal_origin_offset](locators/ClientPortal_origin_offset.md) | client | scalar | `ClientPortalManager_EnableClipPlane`, `ClientPortalManager_RenderPortals`, `ClientPortal_Constructor` | The finder validates ClientPortal_Constructor.{platform}.yaml (func_name match, func_va >= image_base) and runs a second run_layout_walk in the worker: |
| [ClientPortal_texture_height_offset](locators/ClientPortal_texture_height_offset.md) | client | scalar | `ClientPortal_CreateTexture` | *Windows (_client_portal_offsets.recover_portal_offsets → _texture_candidates): the texture guard's member (cmp [portal+disp], 0 whose exact address is taken by a… |
| [ClientPortal_texture_id_offset](locators/ClientPortal_texture_id_offset.md) | client | scalar | `ClientPortal_CreateTexture` | *Windows — find-ClientPortal-offsets-decompiles (_client_portal_offsets.recover_portal_offsets): After the vector pair is proven, the whole RenderPortals body is… |
| [ClientPortal_texture_width_offset](locators/ClientPortal_texture_width_offset.md) | client | scalar | `ClientPortal_CreateTexture` | *Windows (_client_portal_offsets._texture_candidates, driven from recover_portal_offsets): the member proven as the texture guard (cmp [portal+disp], 0 followed by |
| [size_of_frame](locators/size_of_frame.md) | engine | scalar | `R_DrawTEntitiesOnList` | Same predecessor export and ESP-displacement probe as cl_parsecount (see that file, steps 1-2). recover_masked_index_stride traces the masked-index coefficient… |

## 调用点 patch (16)

| Symbol | Module | Category | Predecessors | Summary |
| --- | --- | --- | --- | --- |
| [CL_LinkPacketEntities_to_R_ResetLatched_callsite_0](locators/CL_LinkPacketEntities_to_R_ResetLatched_callsite_0.md) | engine | patch | — | find-R_ResetLatched first recovers both endpoints (owner of "Tried to link edict %i without model\n", and the doubly-called latched-reset candidate), writing the… |
| [CL_LinkPacketEntities_to_R_ResetLatched_callsite_1](locators/CL_LinkPacketEntities_to_R_ResetLatched_callsite_1.md) | engine | patch | — | find-R_ResetLatched recovers both endpoints first, writing the R_ResetLatched function artifact. locate_callsites(owner_ea, callee_ea) walks CL_LinkPacketEntities's… |
| [CL_LinkPacketEntities_to_R_ResetLatched_callsite_2](locators/CL_LinkPacketEntities_to_R_ResetLatched_callsite_2.md) | engine | patch | — | The same walk as the other call sites: locate_callsites(owner_ea, callee_ea) enumerates CL_LinkPacketEntities's instructions in address order and keeps direct rel32… |
| [Cvar_Set_to_Cvar_DirectSet_callsite_0](locators/Cvar_Set_to_Cvar_DirectSet_callsite_0.md) | engine | patch | `Cvar_DirectSet`, `Cvar_Set` | _expected_callsite_outputs reads the finder's expected_outputs. Every stem must match Cvar_Set_to_Cvar_DirectSet_callsite_<digit>, indexes must be unique and form a… |
| [GL_SetMode_call_qwglCreateContext](locators/GL_SetMode_call_qwglCreateContext.md) | engine | patch | `GL_SelectPixelFormat`, `GL_SetMode`, `GL_SetModeLegacy` | The consumer redirects the indirect call that creates the GL context inside GL_SetMode / GL_SetModeLegacy (mov reg,[reg2]; push reg; call dword ptr… |
| [Mod_LoadModel_to_FS_Open_callsite_0](locators/Mod_LoadModel_to_FS_Open_callsite_0.md) | engine | patch | `FS_Open`, `Mod_LoadModel` | Reuses the shared PR #78 owner→callee callsite pattern. Discovery is entirely address-based; no byte signature participates in discovery (the signature is generated… |
| [S_LoadSound_to_FS_Open_callsite_0](locators/S_LoadSound_to_FS_Open_callsite_0.md) | engine | patch | `FS_Open`, `S_LoadSound` | Reuses the shared PR #78 owner→callee callsite pattern. Discovery is entirely address-based; no byte signature participates in discovery (the signature is generated… |
| [Sys_InitMemory_HeapLimitPatches_0](locators/Sys_InitMemory_HeapLimitPatches_0.md) | engine | patch | `Sys_InitMemory` | The patch series is enumerated per body, not anchored per site: the predecessor gives the owner, and every qualifying instruction inside its [start, end) range… |
| [Sys_InitMemory_HeapLimitPatches_1](locators/Sys_InitMemory_HeapLimitPatches_1.md) | engine | patch | `Sys_InitMemory` | Same enumeration as the rest of the series: the predecessor supplies the owner function, py_eval collects every mov/cmp with a two-operand form whose second operand… |
| [Sys_InitMemory_HeapLimitPatches_2](locators/Sys_InitMemory_HeapLimitPatches_2.md) | engine | patch | `Sys_InitMemory` | The series is enumerated, not anchored: the predecessor fixes the owner, and py_eval walks the owner's instruction list keeping mov/cmp with exactly two operands… |
| [Sys_InitMemory_HeapLimitPatches_3](locators/Sys_InitMemory_HeapLimitPatches_3.md) | engine | patch | `Sys_InitMemory` | The predecessor fixes the owner; py_eval then walks the owner's instructions and keeps mov/cmp with exactly two operands whose second is an immediate in {0x2000000… |
| [Sys_InitMemory_HeapLimitPatches_4](locators/Sys_InitMemory_HeapLimitPatches_4.md) | engine | patch | `Sys_InitMemory` | The predecessor fixes the owner function; py_eval walks the owner's instruction list and keeps mov/cmp instructions with exactly two operands whose second is an… |
| [Sys_InitMemory_HeapLimitPatches_5](locators/Sys_InitMemory_HeapLimitPatches_5.md) | engine | patch | `Sys_InitMemory` | Sites are not anchored individually: the predecessor fixes the owner, and py_eval enumerates the owner's instructions keeping mov/cmp with exactly two operands… |
| [Sys_InitMemory_HeapLimitPatches_6](locators/Sys_InitMemory_HeapLimitPatches_6.md) | engine | patch | `Sys_InitMemory` | The predecessor fixes the owner function; py_eval walks the owner's instructions and keeps every mov/cmp with exactly two operands whose second is an immediate… |
| [studioapi_SetupPlayerModel_to_R_StudioChangePlayerModel_callsite_0](locators/studioapi_SetupPlayerModel_to_R_StudioChangePlayerModel_callsite_0.md) | engine | patch | `R_StudioChangePlayerModel`, `studioapi_SetupPlayerModel` | Parse expected_outputs into a contiguous, zero-based index list (expected_callsite_outputs); a gap or a duplicate name fails the finder. |
| [studioapi_SetupPlayerModel_to_R_StudioChangePlayerModel_callsite_1](locators/studioapi_SetupPlayerModel_to_R_StudioChangePlayerModel_callsite_1.md) | engine | patch | `R_StudioChangePlayerModel`, `studioapi_SetupPlayerModel` | Identical chain to callsite_0: expected_callsite_outputs parses the declared outputs into a contiguous zero-based index |

