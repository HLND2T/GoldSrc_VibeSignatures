---
title: cl_resourcesonhand locator
type: reference
permalink: goldsrc-vibesignatures/notes/cl-resourcesonhand-locator
tags:
- locator
- cl_resourcesonhand
- precache
- gv
- hl-10210
---

# cl_resourcesonhand locator

## Trigger
需要客户端 on-hand 资源链表哨兵（MetaHook `PrecacheManager` 的 `cl_resourcesonhand`，即 `&cl.resourcesonhand`）在 `hw.dll` / `hw.so` 中的地址，或为其落地 gv finder / gamedata 迁移。

## Facts（hl-10210，2026-09-06 IDA MCP 实测 + DWARF/symtab 三方交叉）

- **真实名称**：不是独立全局，是全局 `cl`（`client_state_t`）的成员 `resourcesonhand`，偏移 **+4**。
  - hw.so `.symtab`：`cl` LOCAL OBJECT @ 0xC2FA80，size 0x1b0e68，section `.bss`；DWARF `DW_TAG_variable "cl"`（DW_AT_external，DW_OP_addr 0xc2fa80，decl cl_main.c），类型经 `client_state_t` typedef → 匿名 struct（byte_size 0x1b0e68）。
- **gv 地址**：hw.dll **0x11257F64**（.data，RVA 0x1257F64，image base 0x10000000，`cl`=0x11257F60 反推）；hw.so **0xC2FA84**（.bss，base 0x0）。
- **Owning function `CL_PrecacheResources` 已被项目 cover**：`find-CL_PrecacheResources.py`（锚 `#GameUI_PrecachingResources`；svencoop 用 `FULLMATCH:begin CL_PrecacheResources()`），产物在 `bin_artifacts/<tag>/engine/`。hl-10210 函数体：hw.dll [0x101A44C0, 0x101A4793)，hw.so [0x136BE0, 0x136FC1)（与 symtab size 993 逐字节吻合）。
- **字符串锚**：`#GameUI_PrecachingResources` 在两 binary 各出现 1 次（dll .rdata:0x102B6384 / so .rodata:0x254EC7），唯一代码 xref → 唯一函数。Windows 引用形态是 `push imm32` @ 0x101A44C4；**Linux 是 `mov [esp+3Ch], imm32` @ 0x136BEC**（原插件 stage2 的 `68 ?? ?? ?? ?? E8` 在 Linux 必然 miss）。
- **配对引用恢复规则（两平台唯一收敛）**：函数内值 V 同时被 `cmp reg, V`（o_imm，哨兵比较；dll @0x101A4550 / so @0x136C35）和 `[V+0x80]` 的 load（o_mem，`pResource = cl.resourcesonhand.pNext`；dll `mov esi,[0x11257FE4]` @0x101A4537 / so `mov ebx,[0xC2FB04]` @0x136C2A）引用，V ∈ 可写数据段。
- **引擎私有 `resource_s` ABI**：`szFileName`+0(64B)、`type`+0x40、`nIndex`+0x44、`ucFlags`+0x4C、`pNext`+0x80、`pPrev`+0x84，sizeof 0x88=136（DWARF：resourcesneeded@cl+140、resourcelist@cl+276 递进吻合）。MetaHook 插件 `privatehook.h` 再声明一致（rguc_reserved 撑到 128 对齐）。
- **IDA 命名陷阱**：hw.so.i64 里 IDA 把 0xC2FA80 显示为 `nMax`（类型 `client_state_t_9`）——symtab/DWARF/官方源码/仓库配置中均无 `nMax`，是 IDA 侧产物；但其成员路径 `nMax.resourcesonhand`(+4) 与 DWARF 一致。

## Correct approach
1. 生产 finder 已落地（2026-09-06，commit `feat(preprocessor): add find-cl_resourcesonhand`，dev 分支）：`ida_preprocessor_scripts/find-cl_resourcesonhand.py`，注册于全部 10 个 configs（hl-3248/3266/3329/3647/4554/6153/8684/10210、svencoop-10257、cof-5936），`expected_input: CL_PrecacheResources.{platform}.yaml` → `cl_resourcesonhand.{platform}.yaml`，gamesymbol `cl_resourcesonhand / category: gv`。
2. 恢复规则（-allgamever 13/13 全绿）：owner 函数内配对引用——V 被 cmp 引用（或 lea 取址且 ≤6 条指令内 cmp 使用其寄存器），且 V+0x80 被 mov-load 引用，V 在可写数据段，候选唯一才通过。地址提取必须**双通道并集**：操作数层（o_imm value / o_mem addr）+ DataRefsFrom（覆盖 GOTOFF/PIC）。仅用 DataRefsFrom 会在结构化 IDB（hl-8684 hw.so）上因 xref 归一到结构基址（cl）而零候选失败。
3. 产物地址总表（gv_va）：hl-3248/3266=0x2DB64E4、hl-3329=0x2D82E04、hl-3647=0x2D81CA4、hl-4554=0x2D2BDC4、hl-6153=0x2D5CDC4、hl-8684=0x2D602E4(w)/0xC44744(l)、hl-10210=0x11257F64(w)/0xC2FA84(l)、svencoop=0x21092D4(w)/0x15D7D64(l)、cof-5936=0x2DD5A84。全部为 `&cl.resourcesonhand`（cl+4）。
4. 引用指令形态四类（finder 全部覆盖）：`cmp reg, imm`（hl 系/sven-win）、`cmp [ebp+x], imm`（cof）、GOTOFF `lea reg,[ebx+V-GOT]` + `cmp reg,reg`（sven-linux）、结构化 `(offset m1+4)`（hl-8684-linux，操作数层解码）。

## Open items
- MetaHook 侧 gamedata 迁移仍未做（见 metahooksv/privatevars/precache-manager-privatevars）；迁移时直接消费本仓库 `cl_resourcesonhand` 产物即可。
- cstrike/czero/czeror 系列 engine 模块未在本仓库分析范围（无 hw 模块 config），不适用本 finder。

