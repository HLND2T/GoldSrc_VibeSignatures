---
title: 'Trans-object globals: layout and symbol names differ per engine family'
type: note
permalink: goldsrc-vibesignatures/lessons/trans-object-globals-layout-and-symbol-names-differ-per-engine-family
tags:
- lesson
- anchor
- preprocessor
- renderer
- layout
- metahooksv
---

# Trans-object globals: layout and symbol names differ per engine family

## 触发信号（Trigger）

- 为 `transObjects` / `maxTransObjs` / `numTransObjs`（透明对象子系统）或其 owning function 设计 finder；
- 准备照抄 MetaHookSv `Engine_FillAddress_R_AllocTransObjectsVars` 的
  `numTransObjs = maxTransObjs - sizeof(int)` 推导；
- 准备按"so 里的真实符号名"给符号定名，但目标同时覆盖多个 engine family。

## 根因 / 约束（Root cause / constraints）

1. **`numTransObjs = maxTransObjs - 4` 是 Windows-only 的布局假设。** 实测三种排布：
   - `hl-10210 hw.dll`：0x10530C78 / 0x10530C7C / 0x10530C80（递减）
   - `hl-8684 hw.so`：0x959520 / 0x959510 / 0x959500（相邻元素相隔 16 字节）
   - `svencoop-8948 hw.dll`：0x8DF618C / 0x8DF6190 / 0x8DF6194（递增）
   在 Linux / SvEngine 上做该推导会取到错误地址。MetaHookSv 只跑 Windows，所以从未暴露。
   同理，"三者在 .data 里相邻" 一律不可作为锚点。
2. **函数真实名跨 family 不同。** Linux `hw.so` 保留符号表：GoldSrc(hl-*) 是 `R_AllocObjects`，
   SvEngine(svencoop-*) 是 `_Z19R_AllocTransObjectsi`（`R_AllocTransObjects`）。三个 globals 名一致。
   Windows 无符号，只能取源级名。
3. **老 tag 的 `hw.dll` 是加密 blob**，直接字符串扫描静默返回 0 命中；必须扫 `hw.<...>.decrypt.dll`
   （见 [[goldsrc-vibesignatures/notes/old-tag-blob-binaries-need-hw.decrypt.dll-for-byte-level-checks]]）。
   四个 WON 老 tag 其实都有 `"Transparent objects reallocate\n"`。

## 正确做法（Correct approach）

- 函数锚点：`xref_strings: ["FULLMATCH:Transparent objects reallocate\n"]`，全 15 个
  (tag, platform) 节点上字面量恰好 1 次、唯一 data xref 落在唯一 owning function。
- `transObjects` / `maxTransObjs`：在 owner 函数体内，**依指令顺序的绝对地址可写全局写入**，
  第 1 条 = transObjects，第 2 条 = maxTransObjs（要求恰好 2 条，否则 fail closed）。
- `numTransObjs`：owner 换成已 cover 的 `R_DrawTEntitiesOnList`（owner 函数不引用它），
  取该函数内**唯一一条把"可证明为 0 的值"写入绝对地址可写全局**的指令
  （立即数 0，或前置 `xor r,r` / `mov r,0` 的寄存器），并要求该全局在同函数内至少被引用两次
  （计数器必然被读），否则 fail closed。
- 交叉验证抓手：`hl-10210` / `hl-8684` / `svencoop-8948` 的 Linux `hw.so` 有真实符号，
  IDA 反汇编直接显示 `ds:numTransObjs`，可与规则选出的地址逐字节对齐。

## 验证方式（Verification）

2026-09-23 在全部 15 个节点（Windows 11 个：hl-3248/3266/3329/3647/4554/6153/8684/10210、
svencoop-8948/10257、cof-5936；Linux 4 个：hl-8684/10210、svencoop-8948/10257）上
`-allgamever -modules engine` 运行 `find-R_AllocTransObjects` 与 `find-R_AllocTransObjects-globals`，
15/15 成功、0 失败，产出地址与独立 IDA 探测逐字节一致。

## 适用范围（Scope）

GoldSrc / SvEngine renderer-private globals 的 finder 设计；任何引用 MetaHookSv 偏移/布局推导
的判断；给跨 family 符号定名时。
