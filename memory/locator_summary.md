---
title: locator_summary
type: note
permalink: goldsrc-vibesignatures/locator-summary
---

# Symbol Locator Summary

所有符号定位说明的索引，覆盖 `memory/locators/` 下全部 locator 文件，按**主要定位机制**分组。
分类依据是每个 finder 的主要发现锚；部分符号实际会组合多种机制（例如先字符串锚定 owning function，再读表槽），
此处归入其决定性的一步。

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

| Symbol | Module | Category | Predecessors |
| --- | --- | --- | --- |
| [CBaseUI__Initialize](locators/CBaseUI__Initialize.md) | engine | func | — |
| [CL_InitTEnts](locators/CL_InitTEnts.md) | engine | func | — |
| [CL_PrecacheResources](locators/CL_PrecacheResources.md) | engine | func | — |
| [CL_ReallocateDynamicData](locators/CL_ReallocateDynamicData.md) | engine | func | — |
| [CL_RegisterResources](locators/CL_RegisterResources.md) | engine | func | — |
| [CL_Set_ServerExtraInfo](locators/CL_Set_ServerExtraInfo.md) | engine | func | `cl_parsefuncs` |
| [CVideoMode_Common_Init](locators/CVideoMode_Common_Init.md) | engine | func | — |
| [Cache_Alloc](locators/Cache_Alloc.md) | engine | func | — |
| [ClientDLL_CheckStudioInterface](locators/ClientDLL_CheckStudioInterface.md) | engine | func | — |
| [ClientDLL_HudInit](locators/ClientDLL_HudInit.md) | engine | func | — |
| [ClientDLL_Init](locators/ClientDLL_Init.md) | engine | func | — |
| [ClientPortalManager_CreateInvisiblePortalTextures](locators/ClientPortalManager_CreateInvisiblePortalTextures.md) | client | func | — |
| [ClientPortalManager_EnableClipPlane](locators/ClientPortalManager_EnableClipPlane.md) | client | func | — |
| [ClientPortalManager_RenderPortals](locators/ClientPortalManager_RenderPortals.md) | client | func | — |
| [ClientPortalManager_ResetAll](locators/ClientPortalManager_ResetAll.md) | client | func | `ClientPortalManager_CreateInvisiblePortalTextures` |
| [ClientPortal_CreateTexture](locators/ClientPortal_CreateTexture.md) | client | func | — |
| [Cvar_DirectSet](locators/Cvar_DirectSet.md) | engine | func | — |
| [Cvar_Set](locators/Cvar_Set.md) | engine | func | `Cvar_DirectSet` |
| [DT_LoadDetailTexture](locators/DT_LoadDetailTexture.md) | engine | func | — |
| [D_FillRect](locators/D_FillRect.md) | engine | func | `SCR_UpdateScreen_RenderBody`, `Sys_Error`, `cl_enginefuncs` |
| [DispatchDirectUserMsg](locators/DispatchDirectUserMsg.md) | engine | func | — |
| [Draw_DecalTexture](locators/Draw_DecalTexture.md) | engine | func | — |
| [Draw_Frame](locators/Draw_Frame.md) | engine | func | — |
| [Draw_MiptexTexture](locators/Draw_MiptexTexture.md) | engine | func | — |
| [Draw_Pic](locators/Draw_Pic.md) | engine | func | `SCR_UpdateScreen_RenderBody`, `Sys_Error`, `cl_enginefuncs` |
| [Draw_SpriteFrameAdditive](locators/Draw_SpriteFrameAdditive.md) | engine | func | — |
| [Draw_SpriteFrameAdditive_SvEngine](locators/Draw_SpriteFrameAdditive_SvEngine.md) | engine | func | — |
| [Draw_SpriteFrameGeneric](locators/Draw_SpriteFrameGeneric.md) | engine | func | — |
| [Draw_SpriteFrameGeneric_SvEngine](locators/Draw_SpriteFrameGeneric_SvEngine.md) | engine | func | — |
| [Draw_SpriteFrameHoles](locators/Draw_SpriteFrameHoles.md) | engine | func | — |
| [Draw_SpriteFrameHoles_SvEngine](locators/Draw_SpriteFrameHoles_SvEngine.md) | engine | func | — |
| [GL_Init](locators/GL_Init.md) | engine | func | — |
| [GL_LoadFilterTexture](locators/GL_LoadFilterTexture.md) | engine | func | — |
| [GL_SelectPixelFormat](locators/GL_SelectPixelFormat.md) | engine | func | — |
| [GL_SetMode](locators/GL_SetMode.md) | engine | func | — |
| [GL_SetModeLegacy](locators/GL_SetModeLegacy.md) | engine | func | — |
| [GL_Shutdown](locators/GL_Shutdown.md) | engine | func | — |
| [Host_ClearMemory](locators/Host_ClearMemory.md) | engine | func | — |
| [Mod_FindName](locators/Mod_FindName.md) | engine | func | — |
| [Mod_LoadModel](locators/Mod_LoadModel.md) | engine | func | — |
| [Mod_LoadSpriteModel](locators/Mod_LoadSpriteModel.md) | engine | func | — |
| [Mod_LoadStudioModel](locators/Mod_LoadStudioModel.md) | engine | func | — |
| [Mod_PointInLeaf](locators/Mod_PointInLeaf.md) | engine | func | — |
| [NLoadBlob](locators/NLoadBlob.md) | engine | func | — |
| [NLoadBlobFile](locators/NLoadBlobFile.md) | engine | func | `NLoadBlob` |
| [R_DrawTEntitiesOnList](locators/R_DrawTEntitiesOnList.md) | engine | func | — |
| [R_GetSpriteFrame](locators/R_GetSpriteFrame.md) | engine | func | — |
| [R_LoadSkys](locators/R_LoadSkys.md) | engine | func | — |
| [R_RenderView](locators/R_RenderView.md) | engine | func | — |
| [R_StudioCalcAttachments](locators/R_StudioCalcAttachments.md) | engine | func | `R_StudioDrawModel` |
| [R_StudioSetupBones](locators/R_StudioSetupBones.md) | engine | func | — |
| [SCR_UpdateScreen_RenderBody](locators/SCR_UpdateScreen_RenderBody.md) | engine | func | — |
| [SV_SendServerinfo](locators/SV_SendServerinfo.md) | engine | func | — |
| [S_LoadSound](locators/S_LoadSound.md) | engine | func | — |
| [SkyboxCommand](locators/SkyboxCommand.md) | engine | func | — |
| [Sys_Error](locators/Sys_Error.md) | engine | func | — |
| [Sys_InitMemory](locators/Sys_InitMemory.md) | engine | func | — |
| [VideoMode_Create](locators/VideoMode_Create.md) | engine | func | — |
| [g_pClientFactory](locators/g_pClientFactory.md) | engine | gv | `CBaseUI__Initialize` |

## 浮点常量锚 (3)

| Symbol | Module | Category | Predecessors |
| --- | --- | --- | --- |
| [BuildGammaTable](locators/BuildGammaTable.md) | engine | func | — |
| [R_DrawParticles](locators/R_DrawParticles.md) | engine | func | — |
| [R_GlowBlend](locators/R_GlowBlend.md) | engine | func | `R_DrawTEntitiesOnList` |

## 表 / 结构 / 数据段扫描 (34)

| Symbol | Module | Category | Predecessors |
| --- | --- | --- | --- |
| [CGame_DrawStartupVideo](locators/CGame_DrawStartupVideo.md) | engine | func | — |
| [CL_CreateVisibleEntity](locators/CL_CreateVisibleEntity.md) | engine | func | `cl_enginefuncs` |
| [CL_IsThirdPerson](locators/CL_IsThirdPerson.md) | client | func | — |
| [CVideoMode_Common_PlayStartupSequence](locators/CVideoMode_Common_PlayStartupSequence.md) | engine | func | `VideoMode_Create` |
| [ClientPortal_Constructor](locators/ClientPortal_Constructor.md) | client | func | `ClientPortalManager_RenderPortals` |
| [DM_PlayerState](locators/DM_PlayerState.md) | engine | gv | `studioapi_SetupPlayerModel` |
| [DT_Initialize](locators/DT_Initialize.md) | engine | func | `SCR_UpdateScreen_RenderBody`, `Sys_Error`, `cl_enginefuncs` |
| [Draw_FillRGBA](locators/Draw_FillRGBA.md) | engine | func | `SCR_UpdateScreen_RenderBody`, `Sys_Error`, `cl_enginefuncs` |
| [Draw_FillRGBABlend](locators/Draw_FillRGBABlend.md) | engine | func | `SCR_UpdateScreen_RenderBody`, `Sys_Error`, `cl_enginefuncs` |
| [HUD_GetStudioModelInterface](locators/HUD_GetStudioModelInterface.md) | client | func | — |
| [PVSNode](locators/PVSNode.md) | engine | func | — |
| [R_GLStudioDrawPoints](locators/R_GLStudioDrawPoints.md) | engine | func | `studioapi_GetCurrentEntity`, `studioapi_SetChromeOrigin`, `studioapi_SetRenderModel`, `studioapi_StudioSetHeader` |
| [R_StudioCheckBBox](locators/R_StudioCheckBBox.md) | engine | func | — |
| [R_StudioDrawModel](locators/R_StudioDrawModel.md) | engine | func | `R_StudioDrawPlayer` |
| [R_StudioDrawPlayer](locators/R_StudioDrawPlayer.md) | engine | func | `studioapi_SetupPlayerModel` |
| [SDL_InitGL](locators/SDL_InitGL.md) | engine | func | — |
| [VGui_ViewportPaintBackground](locators/VGui_ViewportPaintBackground.md) | engine | func | `cl_enginefuncs` |
| [V_CalcRefdef](locators/V_CalcRefdef.md) | client | func | — |
| [cl_parsefuncs](locators/cl_parsefuncs.md) | engine | gv | — |
| [cl_resourcesonhand](locators/cl_resourcesonhand.md) | engine | gv | `CL_PrecacheResources` |
| [currententity](locators/currententity.md) | engine | gv | — |
| [engine](locators/engine.md) | engine | gv | — |
| [g_ChromeOrigin](locators/g_ChromeOrigin.md) | engine | gv | — |
| [g_pGameStudioRenderer](locators/g_pGameStudioRenderer.md) | client | gv | `HUD_GetStudioModelInterface` |
| [g_ppStudioInterfaceCall](locators/g_ppStudioInterfaceCall.md) | engine | gv | — |
| [pstudiohdr](locators/pstudiohdr.md) | engine | gv | — |
| [r_model](locators/r_model.md) | engine | gv | — |
| [r_origin](locators/r_origin.md) | engine | gv | — |
| [studioapi_GetCurrentEntity](locators/studioapi_GetCurrentEntity.md) | engine | func | — |
| [studioapi_SetChromeOrigin](locators/studioapi_SetChromeOrigin.md) | engine | func | — |
| [studioapi_SetRenderModel](locators/studioapi_SetRenderModel.md) | engine | func | — |
| [studioapi_SetupPlayerModel](locators/studioapi_SetupPlayerModel.md) | engine | func | — |
| [studioapi_StudioSetHeader](locators/studioapi_StudioSetHeader.md) | engine | func | — |
| [studioapi_StudioSetRenderamt](locators/studioapi_StudioSetRenderamt.md) | engine | func | — |

## 确定性 xref 交集锚 (5)

| Symbol | Module | Category | Predecessors |
| --- | --- | --- | --- |
| [CL_Parse_SetView](locators/CL_Parse_SetView.md) | engine | func | `cl_parsefuncs` |
| [NET_DrawRect](locators/NET_DrawRect.md) | engine | func | — |
| [R_StudioDrawPlayerBody](locators/R_StudioDrawPlayerBody.md) | engine | func | `R_StudioDrawPlayer` |
| [R_StudioRenderModel](locators/R_StudioRenderModel.md) | engine | func | `R_StudioCalcAttachments`, `R_StudioDrawModel`, `R_StudioDrawPlayer`, `R_StudioSetupBones`, `cl_sprite_shell`, `g_ChromeOrigin` |
| [V_StartPitchDrift](locators/V_StartPitchDrift.md) | client | func | — |

## 前驱产物复用（下游确定性恢复） (20)

| Symbol | Module | Category | Predecessors |
| --- | --- | --- | --- |
| [CL_FxBlend](locators/CL_FxBlend.md) | engine | func | `studioapi_StudioSetRenderamt` |
| [CVideoMode_Common_DrawStartupGraphic](locators/CVideoMode_Common_DrawStartupGraphic.md) | engine | func | `CVideoMode_Common_Init`, `CVideoMode_Common_PlayStartupSequence` |
| [ClientDLL_Shutdown](locators/ClientDLL_Shutdown.md) | engine | func | `ClientDLL_Init` |
| [ClientScoreInfoHandler](locators/ClientScoreInfoHandler.md) | client | func | — |
| [Host_IsSinglePlayerGame](locators/Host_IsSinglePlayerGame.md) | engine | func | `studioapi_SetupPlayerModel` |
| [Mod_UnloadSpriteTextures](locators/Mod_UnloadSpriteTextures.md) | engine | func | `ClientDLL_Shutdown` |
| [R_AnimateLight](locators/R_AnimateLight.md) | engine | func | `R_CheckVariables` |
| [R_BeamDrawList](locators/R_BeamDrawList.md) | engine | func | `R_DrawParticles` |
| [R_CheckVariables](locators/R_CheckVariables.md) | engine | func | `GL_LoadFilterTexture` |
| [R_ForceCVars](locators/R_ForceCVars.md) | engine | func | `R_CheckVariables` |
| [R_FreeDeadParticles](locators/R_FreeDeadParticles.md) | engine | func | `R_DrawParticles` |
| [R_ResetLatched](locators/R_ResetLatched.md) | engine | func | — |
| [R_StudioChangePlayerModel](locators/R_StudioChangePlayerModel.md) | engine | func | `studioapi_SetupPlayerModel` |
| [R_StudioSaveBones](locators/R_StudioSaveBones.md) | engine | func | `R_StudioCalcAttachments`, `R_StudioDrawModel`, `R_StudioDrawPlayer`, `R_StudioDrawPlayerBody`, `R_StudioMergeBones`, `R_StudioSetupBones`, `cached_bonename`, `cached_numbones` |
| [R_TracerDraw](locators/R_TracerDraw.md) | engine | func | `R_DrawParticles` |
| [S_ExtraUpdate](locators/S_ExtraUpdate.md) | engine | func | `R_CheckVariables`, `R_RenderView` |
| [cl_players_model](locators/cl_players_model.md) | engine | gv | `studioapi_SetupPlayerModel` |
| [cvar_hooks](locators/cvar_hooks.md) | engine | gv | `Cvar_DirectSet`, `Cvar_Set` |
| [g_PlayerExtraInfo](locators/g_PlayerExtraInfo.md) | client | gv | `ClientScoreInfoHandler` |
| [g_PlayerExtraInfo_CZDS](locators/g_PlayerExtraInfo_CZDS.md) | client | gv | `ClientScoreInfoHandler` |

## LLM_DECOMPILE 定位 (47)

| Symbol | Module | Category | Predecessors |
| --- | --- | --- | --- |
| [CL_TempEntInit](locators/CL_TempEntInit.md) | engine | func | `CL_InitTEnts` |
| [FS_Open](locators/FS_Open.md) | engine | func | `Mod_LoadModel` |
| [FreeBlob](locators/FreeBlob.md) | engine | func | `ClientDLL_Init`, `ClientDLL_Shutdown` |
| [GL_BeginRendering](locators/GL_BeginRendering.md) | engine | func | `SCR_UpdateScreen_RenderBody` |
| [GL_Bind](locators/GL_Bind.md) | engine | func | `GL_BuildLightmaps` |
| [GL_BuildLightmaps](locators/GL_BuildLightmaps.md) | engine | func | `R_NewMap` |
| [GL_EndRendering](locators/GL_EndRendering.md) | engine | func | `SCR_UpdateScreen_RenderBody` |
| [GL_Finish2D](locators/GL_Finish2D.md) | engine | func | `SCR_UpdateScreen_RenderBody` |
| [GL_LoadTexture2](locators/GL_LoadTexture2.md) | engine | func | `DT_LoadDetailTexture`, `Draw_MiptexTexture` |
| [GL_SelectTexture](locators/GL_SelectTexture.md) | engine | func | `GL_BuildLightmaps` |
| [GL_Set2D](locators/GL_Set2D.md) | engine | func | `SCR_UpdateScreen_RenderBody` |
| [GL_UnloadTextures](locators/GL_UnloadTextures.md) | engine | func | `R_NewMap` |
| [Hunk_AllocName](locators/Hunk_AllocName.md) | engine | func | `Mod_LoadSpriteModel` |
| [Mod_LoadBrushModel](locators/Mod_LoadBrushModel.md) | engine | func | `Mod_LoadModel` |
| [R_CullBox](locators/R_CullBox.md) | engine | func | `R_StudioCheckBBox` |
| [R_LoadSkyBox_SvEngine](locators/R_LoadSkyBox_SvEngine.md) | engine | func | `SkyboxCommand` |
| [R_NewMap](locators/R_NewMap.md) | engine | func | `CL_RegisterResources` |
| [R_StudioMergeBones](locators/R_StudioMergeBones.md) | engine | func | `R_StudioDrawPlayerBody` |
| [R_StudioRenderFinal](locators/R_StudioRenderFinal.md) | engine | func | `R_StudioRenderModel` |
| [V_RenderView](locators/V_RenderView.md) | engine | func | `VGui_ViewportPaintBackground` |
| [allow_cheats](locators/allow_cheats.md) | engine | gv | `CL_Set_ServerExtraInfo` |
| [build_number](locators/build_number.md) | engine | func | `SV_SendServerinfo` |
| [cached_bonename](locators/cached_bonename.md) | engine | gv | `R_StudioMergeBones` |
| [cached_numbones](locators/cached_numbones.md) | engine | gv | `R_StudioMergeBones` |
| [cl_enginefuncs](locators/cl_enginefuncs.md) | engine | gv | `ClientDLL_HudInit`, `ClientDLL_Init` |
| [cl_entities](locators/cl_entities.md) | engine | gv | `CL_ReallocateDynamicData` |
| [cl_frames](locators/cl_frames.md) | engine | gv | `CL_ReallocateDynamicData` |
| [cl_funcs](locators/cl_funcs.md) | engine | gv | `ClientDLL_HudInit`, `ClientDLL_Init` |
| [cl_max_edicts](locators/cl_max_edicts.md) | engine | gv | `CL_ReallocateDynamicData` |
| [cl_numvisedicts](locators/cl_numvisedicts.md) | engine | gv | `CL_CreateVisibleEntity` |
| [cl_parsecount](locators/cl_parsecount.md) | engine | gv | `R_DrawTEntitiesOnList` |
| [cl_sprite_shell](locators/cl_sprite_shell.md) | engine | gv | `CL_InitTEnts` |
| [cl_viewentity](locators/cl_viewentity.md) | engine | gv | `CL_Parse_SetView` |
| [cl_visedicts](locators/cl_visedicts.md) | engine | gv | `CL_CreateVisibleEntity` |
| [cl_worldmodel](locators/cl_worldmodel.md) | engine | gv | `R_NewMap` |
| [gClientUserMsgs](locators/gClientUserMsgs.md) | engine | gv | `DispatchDirectUserMsg` |
| [gTempEnts](locators/gTempEnts.md) | engine | gv | `CL_InitTEnts`, `CL_TempEntInit` |
| [g_ViewEntityIndex_SCClient](locators/g_ViewEntityIndex_SCClient.md) | client | gv | `GameStudioRenderer_StudioDrawPlayer` |
| [g_bRenderingPortals_SCClient](locators/g_bRenderingPortals_SCClient.md) | client | gv | `V_CalcRefdef` |
| [g_iUser1](locators/g_iUser1.md) | client | gv | `CL_IsThirdPerson` |
| [g_iUser2](locators/g_iUser2.md) | client | gv | `CL_IsThirdPerson` |
| [g_phClientModule](locators/g_phClientModule.md) | engine | gv | `ClientDLL_HudInit`, `ClientDLL_Init` |
| [g_pitchdrift](locators/g_pitchdrift.md) | client | gv | `V_StartPitchDrift` |
| [mod_known](locators/mod_known.md) | engine | gv | `Mod_FindName` |
| [mod_numknown](locators/mod_numknown.md) | engine | gv | `Mod_FindName` |
| [r_worldentity](locators/r_worldentity.md) | engine | gv | `R_NewMap` |
| [videomode](locators/videomode.md) | engine | gv | `VideoMode_Create` |

## vtable / vfunc 槽恢复 (10)

| Symbol | Module | Category | Predecessors |
| --- | --- | --- | --- |
| [GameStudioRenderer_StudioCalcAttachments](locators/GameStudioRenderer_StudioCalcAttachments.md) | client | vfunc | `GameStudioRenderer_StudioDrawModel`, `GameStudioRenderer_vtable` |
| [GameStudioRenderer_StudioDrawModel](locators/GameStudioRenderer_StudioDrawModel.md) | client | vfunc | `HUD_GetStudioModelInterface` |
| [GameStudioRenderer_StudioDrawPlayer](locators/GameStudioRenderer_StudioDrawPlayer.md) | client | vfunc | `GameStudioRenderer_StudioDrawModel`, `GameStudioRenderer_vtable` |
| [GameStudioRenderer_StudioMergeBones](locators/GameStudioRenderer_StudioMergeBones.md) | client | vfunc | `GameStudioRenderer_StudioDrawModel`, `GameStudioRenderer_vtable` |
| [GameStudioRenderer_StudioRenderFinal](locators/GameStudioRenderer_StudioRenderFinal.md) | client | vfunc | `GameStudioRenderer_StudioRenderModel`, `GameStudioRenderer_vtable` |
| [GameStudioRenderer_StudioRenderModel](locators/GameStudioRenderer_StudioRenderModel.md) | client | vfunc | `GameStudioRenderer_StudioDrawModel`, `GameStudioRenderer_vtable` |
| [GameStudioRenderer_StudioSaveBones](locators/GameStudioRenderer_StudioSaveBones.md) | client | vfunc | `GameStudioRenderer_StudioDrawModel`, `GameStudioRenderer_vtable` |
| [GameStudioRenderer_StudioSetupBones](locators/GameStudioRenderer_StudioSetupBones.md) | client | vfunc | `GameStudioRenderer_StudioDrawModel`, `GameStudioRenderer_vtable` |
| [GameStudioRenderer__StudioDrawPlayer](locators/GameStudioRenderer__StudioDrawPlayer.md) | client | vfunc | `GameStudioRenderer_StudioDrawPlayer`, `GameStudioRenderer_vtable` |
| [GameStudioRenderer_vtable](locators/GameStudioRenderer_vtable.md) | client | vtable | `HUD_GetStudioModelInterface` |

## 数值 scalar 提取 (9)

| Symbol | Module | Category | Predecessors |
| --- | --- | --- | --- |
| [ClientPortalManager_vector_begin_offset](locators/ClientPortalManager_vector_begin_offset.md) | client | scalar | `ClientPortalManager_EnableClipPlane`, `ClientPortalManager_RenderPortals`, `ClientPortal_Constructor` |
| [ClientPortalManager_vector_end_offset](locators/ClientPortalManager_vector_end_offset.md) | client | scalar | `ClientPortalManager_EnableClipPlane`, `ClientPortalManager_RenderPortals`, `ClientPortal_Constructor` |
| [ClientPortalSource_mode_offset](locators/ClientPortalSource_mode_offset.md) | client | scalar | `ClientPortalManager_EnableClipPlane`, `ClientPortalManager_RenderPortals`, `ClientPortal_Constructor` |
| [ClientPortal_angles_offset](locators/ClientPortal_angles_offset.md) | client | scalar | `ClientPortalManager_EnableClipPlane`, `ClientPortalManager_RenderPortals`, `ClientPortal_Constructor` |
| [ClientPortal_origin_offset](locators/ClientPortal_origin_offset.md) | client | scalar | `ClientPortalManager_EnableClipPlane`, `ClientPortalManager_RenderPortals`, `ClientPortal_Constructor` |
| [ClientPortal_texture_height_offset](locators/ClientPortal_texture_height_offset.md) | client | scalar | `ClientPortal_CreateTexture` |
| [ClientPortal_texture_id_offset](locators/ClientPortal_texture_id_offset.md) | client | scalar | `ClientPortal_CreateTexture` |
| [ClientPortal_texture_width_offset](locators/ClientPortal_texture_width_offset.md) | client | scalar | `ClientPortal_CreateTexture` |
| [size_of_frame](locators/size_of_frame.md) | engine | scalar | `R_DrawTEntitiesOnList` |

## 调用点 patch (16)

| Symbol | Module | Category | Predecessors |
| --- | --- | --- | --- |
| [CL_LinkPacketEntities_to_R_ResetLatched_callsite_0](locators/CL_LinkPacketEntities_to_R_ResetLatched_callsite_0.md) | engine | patch | — |
| [CL_LinkPacketEntities_to_R_ResetLatched_callsite_1](locators/CL_LinkPacketEntities_to_R_ResetLatched_callsite_1.md) | engine | patch | — |
| [CL_LinkPacketEntities_to_R_ResetLatched_callsite_2](locators/CL_LinkPacketEntities_to_R_ResetLatched_callsite_2.md) | engine | patch | — |
| [Cvar_Set_to_Cvar_DirectSet_callsite_0](locators/Cvar_Set_to_Cvar_DirectSet_callsite_0.md) | engine | patch | `Cvar_DirectSet`, `Cvar_Set` |
| [GL_SetMode_call_qwglCreateContext](locators/GL_SetMode_call_qwglCreateContext.md) | engine | patch | `GL_SelectPixelFormat`, `GL_SetMode`, `GL_SetModeLegacy` |
| [Mod_LoadModel_to_FS_Open_callsite_0](locators/Mod_LoadModel_to_FS_Open_callsite_0.md) | engine | patch | `FS_Open`, `Mod_LoadModel` |
| [S_LoadSound_to_FS_Open_callsite_0](locators/S_LoadSound_to_FS_Open_callsite_0.md) | engine | patch | `FS_Open`, `S_LoadSound` |
| [Sys_InitMemory_HeapLimitPatches_0](locators/Sys_InitMemory_HeapLimitPatches_0.md) | engine | patch | `Sys_InitMemory` |
| [Sys_InitMemory_HeapLimitPatches_1](locators/Sys_InitMemory_HeapLimitPatches_1.md) | engine | patch | `Sys_InitMemory` |
| [Sys_InitMemory_HeapLimitPatches_2](locators/Sys_InitMemory_HeapLimitPatches_2.md) | engine | patch | `Sys_InitMemory` |
| [Sys_InitMemory_HeapLimitPatches_3](locators/Sys_InitMemory_HeapLimitPatches_3.md) | engine | patch | `Sys_InitMemory` |
| [Sys_InitMemory_HeapLimitPatches_4](locators/Sys_InitMemory_HeapLimitPatches_4.md) | engine | patch | `Sys_InitMemory` |
| [Sys_InitMemory_HeapLimitPatches_5](locators/Sys_InitMemory_HeapLimitPatches_5.md) | engine | patch | `Sys_InitMemory` |
| [Sys_InitMemory_HeapLimitPatches_6](locators/Sys_InitMemory_HeapLimitPatches_6.md) | engine | patch | `Sys_InitMemory` |
| [studioapi_SetupPlayerModel_to_R_StudioChangePlayerModel_callsite_0](locators/studioapi_SetupPlayerModel_to_R_StudioChangePlayerModel_callsite_0.md) | engine | patch | `R_StudioChangePlayerModel`, `studioapi_SetupPlayerModel` |
| [studioapi_SetupPlayerModel_to_R_StudioChangePlayerModel_callsite_1](locators/studioapi_SetupPlayerModel_to_R_StudioChangePlayerModel_callsite_1.md) | engine | patch | `R_StudioChangePlayerModel`, `studioapi_SetupPlayerModel` |