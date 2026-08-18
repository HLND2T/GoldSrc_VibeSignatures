---
title: metahook-studio-interface-transaction
type: note
permalink: goldsrc-vibesignatures/notes/metahook-studio-interface-transaction
---

# MetaHook Studio 接口初始化事务：定位结论与改进建议

日期：2026-08-18  
读者：MetaHook 引擎加载 / hook 事务实现  
来源：GoldSrc_VibeSignatures 对 `hw.dll` / `hw.so` 的 IDA 实测，对照 `D:\HLND2T_official` 与当前 `src/metahook.cpp`

本文只记录已经核对过的事实，以及据此能站住的结论。未扫到的引擎版本会单独标明。

---

## 1. 需求（已对齐）

目标不是“贴着 `cl_funcs.pStudioInterface` 的那条 call 指令打补丁”，而是：

> `cl_funcs.pStudioInterface(...)` **里面**发生的 MetaHook hook（典型是 `MH_InlineHook` / DetourAttach）必须进事务，等到这次函数指针调用**返回之后**再 `Commit` 生效。

因此事务窗口只需满足：

```text
Begin  发生在进入 pStudioInterface 之前
Commit 发生在这次函数指针调用返回之后
```

Begin 可以更早，Commit 可以更晚，只要这次调用落在窗口里。  
不要求 Begin/Commit 紧挨着 call 指令。  
也不要求窗口 exclusive 到只覆盖这一条指令——但窗口越大，越容易把无关 hook（例如 `HUD_Init` 里装的）一起推迟。

当前 trampoline 已经是最小正确窗口：

```text
MH_TransactionHookBegin();
r = pfn ? pfn(1, g_pStudioAPI, g_pEngineStudioAPI) : 0;
MH_TransactionHookCommit();
```

见 `src/metahook.cpp` 的 `CheckStudioInterfaceTrampoline`。

---

## 2. 引擎侧真实对象

MetaHook 本地名与引擎真实对象的对应关系：

| MetaHook 本地名 | 引擎真实对象 | 说明 |
| --- | --- | --- |
| `g_ppStudioInterfaceCall` | `&cl_funcs.pStudioInterface` | `cldll_func_t` 成员槽，偏移 `+0x9C` |
| `g_pStudioAPI` | `pStudioAPI` | `r_studio_interface_t **`，回调第 2 参 |
| `g_pEngineStudioAPI` | `engine_studio_api` | `engine_studio_api_s *`，回调第 3 参 |
| `g_StudioInterfaceCall` | 上述调用的 **call-site 指令地址** | 不是函数入口 |
| （无本地函数指针） | `ClientDLL_CheckStudioInterface` | 源码拥有函数；二进制上经常被内联 |

`hl-10210` 的 `hw.so` 带 DWARF，成员名、结构体名、独立函数名均可直接读到：

- 全局：`cl_funcs`，类型 `cldll_func_t`
- 槽：`cl_funcs.pStudioInterface`，类型约为 `int (__cdecl *)(_DWORD, _DWORD, _DWORD)`
- 独立函数符号：`ClientDLL_CheckStudioInterface(HINSTANCE)`
- 同函数内另外两个立即数：`pStudioAPI`、`engine_studio_api`

官方源码角色（`engine/cdll_int.c`）：

```c
void ClientDLL_CheckStudioInterface( HINSTANCE hClientDLL )
{
    R_ResetStudio();
    cl_funcs.pStudioInterface =
        (HUD_STUDIO_INTERFACE_FUNC)GetProcAddress(hClientDLL, "HUD_GetStudioModelInterface");
    if ( cl_funcs.pStudioInterface )
    {
        if ( cl_funcs.pStudioInterface(STUDIO_INTERFACE_VERSION, &pStudioAPI, &engine_studio_api) )
            return;
        Con_DPrintf("Couldn't get client .dll studio model rendering interface.  Version mismatch?\n");
        R_ResetSvBlending();
    }
}
```

`ClientDLL_HudInit` 在 `cl_funcs.pHudInitFunc()` 之后调用它，然后再 `Cvar_FindVar("cl_righthand")`。  
`ClientDLL_HudInit` 本身由 `cl_main.c` 的 `CL_Init` 调用；二者不在同一编译单元。

`STUDIO_INTERFACE_VERSION` 在已核对的 HL25 构建里编译为立即数 `1`。

---

## 3. 关键实测：函数经常不是入口，调用点还在

### 3.1 `hl-10210` Windows `hw.dll`

- SHA-256：`9ba9a2db5e07598fd59afa35507a98c86162e4e15b3835177b78c11842cd2295`
- 映像基址：`0x10000000`
- 诊断字符串 1 次：`0x102b4418`  
  `Couldn't get client .dll studio model rendering interface.  Version mismatch?\n`
- 代码 xref **1** 个 → `ClientDLL_HudInit` `0x10196e50` / RVA `0x196e50` / size `0xd2`
- **没有**独立的 `ClientDLL_CheckStudioInterface` 入口；整段被内联进 `HudInit`

调用形态是直接调用，不是 `FF 15 [slot]`：

```text
10196E87  push    "HUD_GetStudioModelInterface"
10196E8D  call    ds:GetProcAddress          ; 这是 IAT 的 FF 15，不是目标槽
10196E93  mov     eax, cl_funcs.pStudioInterface   ; A1 DC EF 45 11
10196E98  test    eax, eax
10196E9C  push    offset engine_studio_api         ; 0x1031C1E0
10196EA1  push    offset pStudioAPI                ; 0x1031C0F0
10196EA6  push    1
10196EA8  call    eax                              ; FF D0
10196EB1  push    aCouldnTGetClie                  ; 诊断字符串
```

| 项 | 值 |
| --- | --- |
| `cl_funcs` | `0x1145EF40`（`.data`） |
| `cl_funcs.pStudioInterface` | `0x1145EFDC` = `cl_funcs+0x9C`，RVA `0x145EFDC` |
| 槽引用指令 | `0x10196E93`，`A1 DC EF 45 11`，len 5，disp 1 |
| MetaHook `g_ppStudioInterfaceCall` | 按现逻辑应保持 **NULL**（无 `FF 15 [slot]`） |

`GetProcAddress` 的返回值在该构建里没有写回槽；槽沿用 `ClientDLL_Init` 阶段已经填好的值。定位应读 `cl_funcs.pStudioInterface`，不要把 IAT 当成目标。

### 3.2 `hl-10210` Linux `hw.so`（DWARF）

- SHA-256：`fca6628b5a4d76a945e11b9796f327004edc65420d9f9cc23f883143508edd78`
- 映像基址：`0x0`
- 同一诊断字符串 1 次：`0x259620`
- 代码 xref **2** 个，解出**同一个槽**：
  1. `ClientDLL_HudInit` `0x159020` / size `0x105`（内联副本，xref `0x1590F9`）
  2. 独立 `ClientDLL_CheckStudioInterface` `0x1593F0` / size `0x6E`（xref `0x159449`）

`HudInit` 走的是内联块（`0x1590B8` 起），**并不 call** `0x1593F0`。  
独立副本是 gcc 留下的 out-of-line 符号，HUD 初始化热路径用不到。

内联副本：

```text
1590C9  mov     eax, ds:cl_funcs.pStudioInterface   ; A1 1C 80 F7 00
1590CE  test    eax, eax
1590D6  mov     edx, offset engine_studio_api       ; 0x2BD3C0
1590DB  mov     ecx, offset pStudioAPI              ; 0x2BD39C
1590E8  mov     [esp], 1
1590EF  call    eax                                 ; FF D0
1590F9  mov     [esp], offset aCouldnTGetClie
```

独立函数里同一条 load：`0x159421` `A1 1C 80 F7 00`。

| 项 | 值 |
| --- | --- |
| `cl_funcs` | `0xF77F80`（`.bss`） |
| `cl_funcs.pStudioInterface` | `0xF7801C` = `cl_funcs+0x9C` |
| 调用形态 | 同样是 `call eax`，`g_ppStudioInterfaceCall` 应保持 NULL |

### 3.3 已有 `ClientDLL_HudInit` 产物（是否被内联进 `CL_Init`）

仓库里用 `FULLMATCH:cl_righthand` 锚到的 `ClientDLL_HudInit` 全部是独立小函数，体积完全不像巨大的 `CL_Init`：

| 构建 | 平台 | `func_size` | 备注 |
| --- | --- | --- | --- |
| hl-3248 … hl-8684 | Windows | `0x3F` | 独立；随后 `E8` 调用独立的 `CheckStudioInterface` |
| cof-5936 | Windows | `0x46` | 独立 |
| svencoop-10257 | Windows | `0x84` | 独立 |
| hl-8684 | Linux | `0xA5` | 独立 |
| hl-10210 | Windows / Linux | `0xD2` / `0x105` | 独立，但 studio 检查已被内联进来 |

Sven Linux 没有 `ClientDLL_HudInit` 产物，未验证。

老 Windows 的 `0x3F` 函数体形态（示意）是：

```text
mov eax, [pHudInitFunc]
test / Sys_Error
call dword ptr [pHudInitFunc]     ; HUD_Init
push hClientDLL
call ClientDLL_CheckStudioInterface
push "cl_righthand"
call Cvar_FindVar
```

也就是：**旧构建上 `CheckStudioInterface` 仍是独立 callee；HL25 上被内联进 `HudInit`。**

---

## 4. 当前 MetaHook 实现在做什么

`MH_LoadEngine_FindStudioInterface`（`src/metahook.cpp` 约 2175–2273）：

1. 按引擎类型取诊断串子串：  
   GoldSrc `"Couldn't get client .dll studio model rendering"`  
   SvEngine `"Couldn't get client library studio model rendering"`
2. 找 `push imm32; call; add esp,4`
3. 在该点前 `0x50` 字节里匹配两种形态：
   - 直接：`test eax / push / push / push 1 / call r32 / add esp,0C`
   - 间接：`cmp [slot],0 / jz / push / push / push 1 / FF 15 [slot] / add esp,0C`
4. 间接形态才填写 `g_ppStudioInterfaceCall`（`FF 15` 的 imm32）
5. `MH_LoadEngine` 用 21 字节覆盖 call-site，改成进 `CheckStudioInterfaceTrampoline`

这套实现的**意图是对的**：拦截真正执行到的调用点，而不是依赖源码函数名。  
弱点是定位启发式偏编译形态（`0x50` + `FF 15` / 固定位移抽 `pStudioAPI`），不是“字符串 → 拥有代码 → 用参数验证槽”。

---

## 5. 结论：不该改成 hook 哪个函数

### 5.1 不要把主策略改成 hook `ClientDLL_CheckStudioInterface`

即使用户只要求“包住这次函数指针调用”，这个符号也**经常不是运行时入口**：

| 构建 | 真正执行路径 | hook 独立 `ClientDLL_CheckStudioInterface` |
| --- | --- | --- |
| `hl-10210` `hw.dll` | 内联在 `ClientDLL_HudInit` | 没有入口 |
| `hl-10210` `hw.so` | `HudInit` 里的内联副本 | 独立符号存在，但 HudInit **不调用它** |
| 旧 Windows（size `0x3F`） | `HudInit` 里 `E8` 调用它 | 这时可以 hook，但不能当成所有版本都如此 |

Linux gcc 常见“内联一份 + 再留一份 out-of-line”。只 hook DWARF 名字会对准没人走的副本，事务根本套不上真正的 `pStudioInterface`。

整函数 hook 还会把 `R_ResetStudio`、`GetProcAddress`/`dlsym`、失败路径的打印/reset 包进事务。需求允许窗口偏大，但这些并不是事务要保护的对象。

### 5.2 不要靠替换 `cl_funcs.pStudioInterface` 槽

官方是先 `GetProcAddress` 再赋值再调用。提前包一层会被赋值盖掉。  
`hl-10210` 把这次赋值优化掉了，其它版本不会。比 call-site 更脆。

### 5.3 `ClientDLL_HudInit` 不能保证永不被内联

源码上它跨编译单元、非 `static`，**没有 LTO 时不可能**被吃进 `CL_Init`。  
已覆盖的引擎上也**还没有**被吞进 `CL_Init` 的例子（HL25 反而是把更小的 `CheckStudioInterface` 内联进 `HudInit`）。

但不能写成不变量：

1. 它只有一个调用点、也不导出；开 LTO/LTCG 的未来构建理论上可以内联进 `CL_Init`。
2. 现有 finder 用 `cl_righthand`。若真被内联，字符串会落到巨大的 `CL_Init` 上，产物仍可能叫 `ClientDLL_HudInit`，hook 会包住后面所有 `Cmd_AddCommand` 等。
3. 老 Windows 只有 `0x3F` 字节，Detour 5 字节入口勉强够（第一条常是 `A1`），不能当成任意版本都好 hook。
4. 即使它始终独立，hook 整段 `HudInit` 也会把前面的 `HUD_Init`（`cl_funcs.pHudInitFunc`）和后面的 `cl_righthand` / joystick cvar 一起推迟。需求允许“Commit 更晚”，但 `HUD_Init` 里装的 hook 也会被推迟，这是行为变化，不是更正确的事务语义。

Sven Linux 的 `HudInit` 未在本仓库验证。

### 5.4 调用点仍然是跨版本最稳的拦截面

无论 `CheckStudioInterface` 是否被内联、调用编码是 `call eax` 还是 `FF 15 [slot]`，**那次函数指针调用都还在**。  
现有 21 字节 patch + trampoline 是为了命中执行路径，不是为了“贴得更紧”。  
需求放宽之后，这个理由仍然成立。

---

## 6. 给 MetaHook 的改进建议

按优先级：

### A. 保持“拦截实际调用点 + trampoline 里 Begin / 调 pfn / Commit”（推荐）

不要为了少改指令去 hook `ClientDLL_CheckStudioInterface`。

定位建议改成：

1. 精确字符串，不要只靠子串：  
   - GoldSrc：`Couldn't get client .dll studio model rendering interface.  Version mismatch?\n`  
   - SvEngine：`Couldn't get client library studio model rendering interface. Version mismatch?\n`  
     （注意句号后空格：GoldSrc 两个空格，Sven 一个。）
2. 收集该串全部代码 xref。允许 1～2 个拥有函数，但必须收敛到**同一个**槽地址。
3. 在xref 附近识别把指针当作 `(1, &pStudioAPI, &engine_studio_api)` 调用的那条指令。  
   不要用“字符串前 `0x50` 字节里第一条 `FF 15`”——HL25 上那条 `FF 15` 是 `GetProcAddress`。
4. 槽 = 被 `test`/`cmp` 然后调用的那个绝对地址，应等于 `cl_funcs+0x9C`（在结构布局未变的版本上）。
5. 编码当实现细节：  
   - `FF 15 [slot]` → 填 `g_ppStudioInterfaceCall`，现有间接补丁  
   - `mov r32,[slot]; call r32` → `g_ppStudioInterfaceCall` 保持空，现有直接补丁  
6. 补丁仍须保住后面的 `test eax,eax`（直接形态 `static_assert` 的 21 字节约束保留）。

### B. 若坚持函数级 hook：只能当“有独立 callee 时的可选路径”

伪逻辑：

```text
若 HudInit 里存在对独立 CheckStudioInterface 的直接 call
    且该 callee 不是“仅 DWARF 残留、热路径不走”的副本
    → 可以 MH_InlineHook(CheckStudioInterface)
否则
    → 必须退回调用点 patch
```

HL25 Windows/Linux 会走 fallback。不能把函数 hook 当唯一路径。

### C. hook `ClientDLL_HudInit` 仅在明确接受更宽窗口时考虑

只有在产品上接受下面两点时才值得用它去掉指令补丁：

- `HUD_Init` 里登记的 hook 也延迟到整个 `HudInit` 返回才生效
- 每次加载都验证 `cl_righthand` 的拥有函数体积/角色仍是 HudInit，而不是 `CL_Init`

这不是更正确的事务语义，只是实现更简单、窗口更大。

---

## 7. 稳健定位用的锚点（给实现，不是给扫描器当字节特征）

优先顺序：

1. 诊断字符串（函数内字面量，不是 caller 字符串）。  
2. 同函数内的 `"HUD_GetStudioModelInterface"`。  
3. 调用参数：`1`、`pStudioAPI`、`engine_studio_api`。  
4. 槽地址与 `cl_funcs` 基址的 `+0x9C` 关系（布局不变时作校验，不要当唯一依据）。

不要用：

- 原始 VA/RVA 当跨版本锚点
- 单独的 `"studio model rendering"` 子串
- MetaHook 现有 `pattern2`/`pattern3` 当唯一发现手段（可作回归，不可作定位）

---

## 8. 未覆盖 / 不要外推的部分

- Sven Linux `ClientDLL_HudInit` / `CheckStudioInterface` 是否内联：本仓库无产物。
- `cldll_func_t` 在极老 client 上若少字段，`pStudioInterface` 偏移可能不是 `0x9C`。已核对的 HL25 是 `0x9C`。
- 官方公开树与 `hl-10210` 不完全一致：目标多了 `fClientLoaded` 守卫，joystick cvar 缓存，且 Windows 上 `CheckStudioInterface` 被内联；以二进制为准。
- 本文没有改 MetaHook 代码，也没有为 `g_ppStudioInterfaceCall` 落地生产 finder。

---

## 9. 一句话交给实现的决策

> 事务要包的是**真正执行到的** `cl_funcs.pStudioInterface(...)`。  
> 源码函数名 `ClientDLL_CheckStudioInterface` 在 HL25 上不可作为 hook 入口。  
> `ClientDLL_HudInit` 目前独立，但不能保证永远独立，且窗口会吞掉 `HUD_Init`。  
> 继续拦截调用点；把定位从 `0x50`/`FF 15` 启发式改成诊断字符串 + 调用参数验证。