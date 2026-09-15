---
title: issue-124 renderer engine finders
type: note
permalink: goldsrc-vibesignatures/issues/issue-124-renderer-engine-finders
tags:
- issue-124
- finders
- renderer
- engine
- floats-anchor
- engine-studio-api
---

# Issue #124 Renderer engine private symbols — implementation notes

Task 1 方案 + Task 2 实施(2026-09-15)。14 个 engine 符号、11 个 finder、10 个 gamever configs、`-allgamever` 零失败。

## 符号与锚(已验证)

- `R_CheckVariables` = GL_LoadFilterTexture(已有 artifact)的唯一 caller。SvEngine Linux 上该调用被内联但 xref_funcs 仍可定位。
- `R_ForceCVars` / `R_AnimateLight` = R_CheckVariables 宿主(R_SetupFrame 或内联它的 R_RenderScene)callseq 中紧邻的前/后内部 call。SvEngine Linux 布局把 ForceCVars 移出宿主(force_absent),config 用 expected_output_windows 拆分。
- `S_ExtraUpdate` = R_RenderView ∩ R_RenderScene callees 的小函数交集;须先按 size≤700 过滤(R_ForceCVars 717B 会因内联 R_Clear 同时被两者调用而混入交集)。
- `PVSNode` = 数据段扫描 triangleapi_t(dword 1 + 19 函数指针)→ slot16 BoxInPVS → 唯一自递归 callee。8684 布局在 HL25/SvEngine 10257 未漂移。
- `R_DrawParticles` = `xref_floats ["20.0","0.004"]`(scale hack)。0.004 以 **f64** 存储(C 字面量 double);MSVC f64、GCC f32 混合由 helper 按 dtype 自适应。
- `R_FreeDeadParticles` / `R_TracerDraw` / `R_BeamDrawList` 从 R_DrawParticles body 提取:Beam=唯一 caller 的 250-900B 且 callee 含大函数;Tracer=≥900B 唯一 caller(GCC Linux 内联→absent);FreeDead=共 call 或内联时体内 count≥3。
- `R_GlowBlend` = `xref_floats ["19000.0","0.005","0.05"]` + exclude R_DrawTEntitiesOnList;19000 全平台唯一 owner;HL25/SvEngine Windows 内联(config platform: linux)。
- `R_ResetLatched` = "Tried to link edict %i without model\n" owner 的双调候选中额外 caller 数最少者;callsite 数量平台不同(8684 Linux 3 个,用 expected_output_linux)。
- `R_GLStudioDrawPoints` = engine_studio_api(common/r_studioint.h)slot25(StudioDrawPoints);表用 4 个 studioapi artifact 槽(6/35/36/39)校验,ELF 上 DataRefsTo 不可靠须段扫描;slot25 需追逐转发链(E9 thunk、call 链、双尾 jmp wrapper、单分支老版本、call IsATISmoothing+尾 jmp);slot29(SetupSkin)是带分支 wrapper,验证时并入其 jmp 目标。
- `Mod_UnloadSpriteTextures` = ClientDLL_Shutdown(仅老版本 Windows)depth-2 唯一 callee。HL25/SvEngine 内联 ClientDLL_Shutdown,未覆盖。
- `NET_DrawRect` = SvEngine Windows 专属;MSVC /OPT:ICF 与 D_FillRect 合并为同一地址;指令序列锚(mov esi,mem;cmp 0x400;cmp 1 + 无内部 callee)。SvEngine Linux 无此形态。

## 共享 helper 改动

- `xref_floats` 的 spec 值必须是**字符串**(normalize 先做 isinstance(str) 检查,传 float 对象静默返回 None)。
- `_function_matches_float_filters` 增加 GOT fallback:SvEngine Linux 是 -fPIC,常量经 `(flt-GOT)[ebx]` 加载,operand_value 解不出;fallback 对未命中常量按 f32/f64 扫 .rdata/.rodata 实例并取 DataRefsTo 的 owner 集合。**必须模块级缓存**(每常量一次),否则逐函数全段扫描会把 worker 拖死并留下 .id0 锁。
- py_eval 模板(r"""...""")内新增代码**禁止 docstring**(提前闭合外层 raw 模板)。
- 测试按 helpers 名单从模板 AST 提取片段:新增 helper/模块级常量都要进 tests/test_ida_skill_preprocessor.py 的提取集合与 fake namespace。

## 平台 gating 矩阵(config)

- R_GlowBlend:hl-10210/svencoop → linux only。
- find-R_DrawParticles-calls:hl-10210 → windows only(GCC chunk 归属错乱);R_TracerDraw 全部 windows only(GCC 内联)。
- R_ForceCVars:svencoop → windows only(SvEngine Linux 布局)。
- NET_DrawRect:svencoop → windows only。
- hl-8684 callsite_2:expected_output_linux。

## 排查教训

- 驱动脚本遇 "Strict restored IDA database identity verification failed" → 老版本 IDB 未 warm,用 `ida_analyze_bin.py -gamever X -modules engine` 正式路径跑(自动 warm)。
- lifecycle 停止阶段 TaskGroup 崩溃 + .id0 残留 = worker 卡死信号(见上述缓存教训);清理 `bin/*/engine/*.id0`(确认无进程后)。