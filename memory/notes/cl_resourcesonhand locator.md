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
1. 不要重复字符串发现 owning function：config 声明 `expected_input: CL_PrecacheResources.{platform}.yaml`，以 `find-CBaseUI__Initialize-decompiles.py` 为模板（读产物 func_va → `_inspect_function_via_mcp` 当前 IDB 重校验 → 函数内确定性恢复 → `write_gv_yaml`，`gv_sig` 沿用 owner func_sig + `gv_inst_offset/length/disp`）。
2. 恢复逻辑用上述配对引用规则（确定性、无 LLM）；0x80 是 `pNext` 偏移，勿按公开 HLSDK custom.h 的 96/104 布局理解。
3. gamesymbol 清单登记 `cl_resourcesonhand / category: gv`。

## Open items
- finder 未落地（截至 2026-09-06 仅分析结论）；MetaHook 侧 gamedata 迁移同样未做（见 metahooksv/privatevars/precache-manager-privatevars）。
- 其余游戏版本的地址未逐一验证；复用链依赖 `CL_PrecacheResources` 产物先行生成，owner finder 失败时 fail closed。
