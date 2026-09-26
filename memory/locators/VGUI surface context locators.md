---
title: VGUI surface context locators
type: note
permalink: goldsrc-vibesignatures/locators/vgui-surface-context-locators
tags:
- engine
- vgui2
- anchors
---

# VGUI surface context locators

## Overview
Issue #251 在 [[VGUI PaintTraverse Anchor Chain]] 上扩展 13 个 engine 目标。真实 Linux 符号是 `vgui2::BuildGroup::DrawRulers()`；配置和 slot-only 产物使用 `vgui2_BuildGroup_DrawRulers`，不能把它当成 Panel 的方法。

## Responsibilities
- 从当前 PaintTraverse 的接收者、VPANEL、useInsets 与绘制控制流恢复 surface push/pop 槽和 BuildGroup 成员/槽。
- 沿 BaseUISurface 与 EngineSurface 当前主虚表继承接口槽，恢复纹理缓存和软件 scissor 存储。
- 保留 x86 ABI、ELF PIC、编译器拆分主体、标量/SSE 存储差异；多候选和未知数据流停止输出。

## Involved Files & Symbols
- `ida_preprocessor_scripts/find-vgui2_Panel_PaintTraverse-context.py`：Panel::_buildGroup、BuildGroup::DrawRulers、ISurface Push/PopMakeCurrent。
- `ida_preprocessor_scripts/find-BaseUISurface-context.py`：继承 BaseUISurface 两个实现。
- `ida_preprocessor_scripts/find-BaseUISurface-context-dependencies.py`：m_iCurrentTexture 和 IEngineSurface 两槽。
- `ida_preprocessor_scripts/find-EngineSurface-context.py`：继承 EngineSurface 两个实现。
- `ida_preprocessor_scripts/find-EngineSurface-context-globals.py`：分组 LLM_DECOMPILE 提取 g_bScissor、g_ScissorRect；独立检查 push 置真/pop 清零同一字节以及矩形的完整 16 字节写入覆盖。
- `_vgui_context_common.py`：成员签名写入和共享继承包装；`_x86_vcall_flow.py`、`_vgui_paint_common.py`：寄存器/栈参数来源和当前 IDA CFG 适配。
- `ida_analyze_util.py`：短继承函数签名的显式跨边界回退、窄立即数与地址操作数的区分。
- `tests/test_x86_vcall_flow.py`、`tests/test_ida_skill_preprocessor.py`：共享行为回归。

## Architecture
1. 复用现有 Panel PaintTraverse 和主表。纯成员 getter 由当前表/函数体核验；false/true 的两种 push 都必须通过 CFG 到达同一 pop 槽，中间包含 Panel paint 调用。
2. control-group 返回值必须被 overlay 循环消费；同一 Panel 成员接收者在循环外执行另一虚调用，确定 BuildGroup::DrawRulers。
3. INHERIT_VFUNCS 从 BaseUISurface 主表继承 ISurface 槽。push 中三个不同栈数组必须各有上游查询，inset 查询须位于 useInsets 正分支；最终向同一 engine-surface 成员转交三个数组和 false。唯一四字节 this 清零字段是纹理缓存。
4. INHERIT_VFUNCS 从 EngineSurface 主表继承 IEngineSurface 槽。已验证 push 为 GV owner；参考由 generate_reference_yaml.py 导出，HL25 与 SvEngine 各有 Windows/Linux 参考。

## Dependencies
- engine 配置覆盖 hl-3248/3266/3329/3647/4554/6153/8684/10210、cof-5936、svencoop-8948/10257，共 15 个声明的平台组合。旧四版使用 hw.decrypt.dll；其他未声明的 Linux 平台不强行匹配。
- 已有 BaseUISurface_vtable、EngineSurface_vtable 和跨模块 PaintTraverse 前置 DAG；没有新增 CS-only client 目标。
- 官方源码：`D:/HLND2T_official/vgui2/controls/Panel.cpp:366–463`、`engine/vgui2/BaseUISurface.cpp:962–988`、`engine/VGUI_EngineSurface.cpp:714–799`。源码说明角色，当前机器码决定布局和调用形式。
- [[idalib-mcp]]：当前实现使用 restored_strict、save_on_success=False 的 owned worker；参考准备也只在已绑定的自有 worker 中修改分析元数据。

## Notes
- 触发：Windows 的 GetVPanel 看似接收 useInsets/几何数组，循环校正后栈深度不一致。根因：IDA 把提前压栈参数的清理归给 getter。做法：读取实际 getter RET，把错归的清理量转给消费其返回值的间接调用；随后重新核验 CFG、参数来源与成对绘制调用。验证：合成循环和真实旧 BLOB/CoF/HL25 输入。适用：此类提前压栈的 x86 thiscall 调用链。
- 触发：Linux PaintTraverse 入口没有绘制调用。根因：hot part 拆分，this/布尔值经寄存器传递。做法：沿已验证直接尾边传递当前寄存器/栈值，不创造默认参数；父函数栈指针必须与子函数参数栈区分。验证：混合寄存器参数和未知参数的合成测试，加当前拆分主体核验。适用：x86 编译器生成的函数拆分。
- 触发：HL25 的 useInsets guard 消失。根因：比较和跳转之间的 SIMD 清零/搬运不改整数 EFLAGS，旧模型却清除了条件来源。做法：对明确不改 EFLAGS 的 SIMD 指令保留条件，未知指令仍保守处理。验证：cmp→pxor/movdqu→jz 合成测试和真实 BaseUISurface 输入。
- 触发：短 PopMakeCurrent 的入口签名不唯一。根因：继承 helper 忽略了已有的允许跨边界选项。做法：只在调用者显式允许且函数内签名失败时扩展签名，并输出对应标记。验证：许可开启/关闭的行为回归；继续要求唯一匹配。
- 触发：SvEngine Linux 的 bool GV 出现地址 1 的第二候选。根因：ELF 从 0 映射，byte-store 的立即数 1 也落在映射区。做法：小于运行时指针宽度的编码立即数不能充当完整地址；保留真实 PIC 数据引用与 gv_pic_addend。验证：映射头部中的立即数合成回归。适用：x86 ELF 的立即数/地址区分。
- 触发：旧式四次 scissor 写入扫描在 Sven Linux 失败。根因：矩形通过一次 16 字节 SIMD 写入，布局还包含 lane 重排。做法：提取 clipRect 计算产生的整个对象，再验证完整写入覆盖；不能按写入次数、成员顺序或 flag 邻接位置猜测。

2026-09-26 验证记录：完整 A–E bounded batch 强制执行 75 个节点，覆盖 11 个 engine 标签、15 个平台组合，15 个工作项全部 succeeded，退出码 0。195 份产物逐份核验身份、32 位 VA/RVA、4 字节槽宽、slot-only 字段边界、成员签名及继承虚表目标一致性；运行时签名由 analyzer 在当前 IDB 校验。最终 unit 运行 1196 项，成功，5 项跳过；repository-contract 14 项成功，format check 和 git diff --check 成功。新增产物需先暂存到 Git 索引，再运行 tracked inventory 门禁；未暂存时会报告清单缺失。

## Callers
- Panel::PaintTraverse → ISurface::PushMakeCurrent/PopMakeCurrent。
- BaseUISurface::PushMakeCurrent/PopMakeCurrent → IEngineSurface::pushMakeCurrent/popMakeCurrent。
- Panel::PaintTraverse → _buildGroup->DrawRulers()。
