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

每个符号的定位锚已迁移到 `memory/locators/`。本节只保留与共享 helper、config gating 和排查相关的经验。

## 共享 helper 改动

- `xref_floats` 的 spec 值必须是**字符串**(normalize 先做 isinstance(str) 检查,传 float 对象静默返回 None)。
- `_function_matches_float_filters` 增加 GOT fallback:SvEngine Linux 是 -fPIC,常量经 `(flt-GOT)[ebx]` 加载,operand_value 解不出;fallback 对未命中常量按 f32/f64 扫 .rdata/.rodata 实例并取 DataRefsTo 的 owner 集合。**必须模块级缓存**(每常量一次),否则逐函数全段扫描会把 worker 拖死并留下 .id0 锁。
- GOT fallback 语义加固(PR review P2):xref 指令本身必须是以**匹配存储宽度**的标量浮点内存读(共享 `_float_read_width`:SSE 按 mnemonic+xmm,x87 按 decoded dtype),否则 f64 常量的全零低字会被 f32 扫描误记为 float 0.0 引用(`fld qword [double_1023]` ≠ 引用 float 0.0);excluded 常量与 required 走同一 fallback,禁止常量经 GOT 引用时同样能排除候选。
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
