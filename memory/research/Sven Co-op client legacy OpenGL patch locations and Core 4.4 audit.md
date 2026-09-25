---
title: Sven Co-op client legacy OpenGL patch locations and Core 4.4 audit
type: report
permalink: goldsrc-vibesignatures/research/sven-co-op-client-legacy-open-gl-patch-locations-and-core-4.4-audit
source_file: /tmp/svencoop_client_legacy_gl_patch_locations.md
audit_date: '2026-09-25'
builds:
- '10257'
- '8948'
validation: static-only
tags:
- svencoop
- opengl
- core-profile
- renderer
- binary-analysis
---

# Sven Co-op client 中的 Legacy OpenGL 补丁位置

分析来源：`/home/hztest2/MetaHookSv/Plugins/Renderer/gl_hooks.cpp:1393-1665` 的 11 个 `R_RedirectSCClientLegacyOpenGLCall_*`。目标二进制来自 `/home/hztest2/GoldSrc_VibeSignatures/bin/svencoop-{10257,8948}/client/`。以下地址均指**原始、未修改的二进制**。

## 地址约定与结论

- `client.dll`：表内 `VA` 采用 PE 首选 ImageBase `0x10000000`；运行时启用 ASLR 后应使用模块实际基址加 `RVA`。两版 `.text` 都从 `RVA 0x1000`、文件偏移 `0x400` 开始，因此下表 `FO = RVA - 0xC00`。
- `client.so`：表内为 ELF 静态虚拟地址；所列指令都在 `.text`，两版 `.text` 的地址与文件偏移相同，因此 `FO = VA`。运行时地址为模块装载基址加表内地址。
- DLL 表是按源码模式逐字节扫描 `.text`（`2A` 为通配字节），加上源码中的 `pFound` 位移，再以 `objdump -d -M intel` 核对指令边界与目标。SO 表是以 `gl*@plt`、实参常量、所在函数及 8948 ELF 符号核对出的**语义对应指令**。11 条原始 Windows 模式在两版 SO 文件中均为零命中，因此这些 SO 地址不是该源码直接 patch 的地址。
- `glEnable_GeneratePortalTexture` 在每版 DLL 命中两处；源码循环会处理两处。`glDisable_ClipPlane` 修改的是 `mov esi, [glDisable]` 的 4 字节地址操作数（指令起点 `+2`），不是修改 `glDisable` 调用。`glClear_ClipPlane` 的实际目标是 `glClear(GL_COLOR_BUFFER_BIT)`。

## 10257 `client.dll`

SHA-256：`f40e74b7a703d193188d628066660ff0ac4be2b09613ae4b7f8d2c671991e7d6`

| 源码后缀 | VA | RVA | FO | 原始指令字节与含义 |
|---|---:|---:|---:|---|
| `glTexEnvf` | `0x10045C6E` | `0x45C6E` | `0x4506E` | `FF 15 9C A1 11 10`，`call [glTexEnvf]`；前有 `0x8501, 0x8500` |
| `glBegin` | `0x10049D75` | `0x49D75` | `0x49175` | `FF 15 94 A1 11 10`，`call [glBegin]`；前有 `push 6` |
| `glEnd` | `0x1004A14F` | `0x4A14F` | `0x4954F` | `FF 15 2C A2 11 10`，`call [glEnd]` |
| `glColor4f_DrawParticle` | `0x10049ED7` | `0x49ED7` | `0x492D7` | `FF 15 98 A1 11 10`，`call [glColor4f]`；`CParticleSystem::ParticleDraw` 对应代码 |
| `glColor4f_DrawPortal` | `0x1004F1F4` | `0x4F1F4` | `0x4E5F4` | `FF 15 98 A1 11 10`，`call [glColor4f]`；其后三个 RGB 实参为 `1.0f` |
| `glEnable_GenerateInvisibleTexture` | `0x1004C986` | `0x4C986` | `0x4BD86` | `FF 15 08 A2 11 10`，`call [glEnable]`，实参 `GL_TEXTURE_2D` |
| `glEnable_GeneratePortalTexture` ① | `0x1004EA52` | `0x4EA52` | `0x4DE52` | `FF 15 08 A2 11 10`，`call [glEnable]`；位于 `ClientPortalManager::RenderPortals` |
| `glEnable_GeneratePortalTexture` ② | `0x10075567` | `0x75567` | `0x74967` | `FF 15 08 A2 11 10`，`call [glEnable]`；门户纹理创建路径 |
| `glDisable_FOG` | `0x1005BB15` | `0x5BB15` | `0x5AF15` | `FF 15 A4 A1 11 10`，`call [glDisable]`，实参 `GL_FOG = 0xB60` |
| `glDisable_ClipPlane` | `0x1004EBDA` | `0x4EBDA` | `0x4DFDA` | `8B 35 A4 A1 11 10`，`mov esi, [glDisable]`；**实际写入操作数** `VA 0x1004EBDC` / `FO 0x4DFDC` |
| `glCopyTexSubImage2D_RenderPortals` | `0x1004EFD3` | `0x4EFD3` | `0x4E3D3` | `FF 15 10 A2 11 10`，`call [glCopyTexSubImage2D]` |
| `glClear_ClipPlane` | `0x1004ED1B` | `0x4ED1B` | `0x4E11B` | `FF 15 20 A2 11 10`，`call [glClear]`，实参 `0x4000` |

## 10257 `client.so`

SHA-256：`50580344e1c59b3c77e8e4e52ed9f185fcec7da2da936873ec122f12c735a022`

| 源码后缀 | ELF VA = FO | 原始指令与对应依据 |
|---|---|---|
| `glTexEnvf` | `0xECF34` | `E8 A7 D2 FA FF`，`call glTexEnvf@plt`；前有 `0x8501, 0x8500` |
| `glBegin` | `0xF3BB7` | `E8 94 6A FA FF`，`call glBegin@plt`；前有 `GL_TRIANGLE_FAN = 6` |
| `glEnd` | `0xF3E67` | `E8 84 64 FA FF`，`call glEnd@plt`；其后测试粒子标志 `0x100` |
| `glColor4f_DrawParticle` | `0xF3C13` | `E8 68 6C FA FF`，`call glColor4f@plt`；位于上述粒子绘制代码 |
| `glColor4f_DrawPortal` | `0xFAF57` | `E8 24 F9 F9 FF`，`call glColor4f@plt`；位于门户绘制代码 |
| `glEnable_GenerateInvisibleTexture` | `0xF718F` | `E8 3C 2A FA FF`，`call glEnable@plt`；`ClientPortalManager::CreateInvisiblePortalTextures`，实参 `0xDE1` |
| `glEnable_GeneratePortalTexture` ① | `0xFD193` | `E8 38 CA F9 FF`，`call glEnable@plt`；`RenderPortals` 的纹理分支，实参 `0xDE1` |
| `glEnable_GeneratePortalTexture` ② | `0xF43A1` | `E8 2A 58 FA FF`，`call glEnable@plt`；`ClientPortal::CreateTexture`，实参 `0xDE1` |
| `glDisable_FOG` | `0x10715B` | `E8 F0 32 F9 FF`，`call glDisable@plt`，实参 `0xB60` |
| `glDisable_ClipPlane` | `0xF785C`, `0xF7868`, `0xF7874`, `0xF7880`, `0xF788C`, `0xF7898` | `ClientPortalManager::DisableClipPlanes` 中六个 `call glDisable@plt`，实参依次 `0x3000` 至 `0x3005`；没有 DLL 的单个指针加载补丁点 |
| `glCopyTexSubImage2D_RenderPortals` | `0xFD213` | `E8 88 D2 F9 FF`，`call glCopyTexSubImage2D@plt`，实参包含 `0xDE1` |
| `glClear_ClipPlane` | `0xFCC26` | `E8 B5 CF F9 FF`，`call glClear@plt`，实参 `0x4000` |

## 8948 `client.dll`

SHA-256：`5e3bd90c24e829c43344f0fe18368a71cad3c9b3405695e2489b469cf694624c`

| 源码后缀 | VA | RVA | FO | 原始指令字节与含义 |
|---|---:|---:|---:|---|
| `glTexEnvf` | `0x1008DC9E` | `0x8DC9E` | `0x8D09E` | `FF 15 E8 51 0E 10`，`call [glTexEnvf]` |
| `glBegin` | `0x100920A8` | `0x920A8` | `0x914A8` | `FF 15 10 52 0E 10`，`call [glBegin]` |
| `glEnd` | `0x10092482` | `0x92482` | `0x91882` | `FF 15 00 52 0E 10`，`call [glEnd]` |
| `glColor4f_DrawParticle` | `0x1009220A` | `0x9220A` | `0x9160A` | `FF 15 0C 52 0E 10`，`call [glColor4f]` |
| `glColor4f_DrawPortal` | `0x10097724` | `0x97724` | `0x96B24` | `FF 15 0C 52 0E 10`，`call [glColor4f]` |
| `glEnable_GenerateInvisibleTexture` | `0x10094B96` | `0x94B96` | `0x93F96` | `FF 15 04 52 0E 10`，`call [glEnable]` |
| `glEnable_GeneratePortalTexture` ① | `0x10096FA8` | `0x96FA8` | `0x963A8` | `FF 15 04 52 0E 10`，`call [glEnable]`；`RenderPortals` |
| `glEnable_GeneratePortalTexture` ② | `0x100BCBA7` | `0xBCBA7` | `0xBBFA7` | `FF 15 04 52 0E 10`，`call [glEnable]`；门户纹理创建路径 |
| `glDisable_FOG` | `0x100A3AA5` | `0xA3AA5` | `0xA2EA5` | `FF 15 08 52 0E 10`，`call [glDisable]` |
| `glDisable_ClipPlane` | `0x10097131` | `0x97131` | `0x96531` | `8B 35 08 52 0E 10`，`mov esi, [glDisable]`；**当前源码模式零命中，因此此版不会被该函数修改**。若处理相同语义，操作数在 `VA 0x10097133` / `FO 0x96533` |
| `glCopyTexSubImage2D_RenderPortals` | `0x10097506` | `0x97506` | `0x96906` | `FF 15 E4 51 0E 10`，`call [glCopyTexSubImage2D]` |
| `glClear_ClipPlane` | `0x1009725A` | `0x9725A` | `0x9665A` | `FF 15 F4 51 0E 10`，`call [glClear]` |

8948 `glDisable_ClipPlane` 失配的直接原因：源码模式在 `mov esi,[glDisable]` 后要求 `33 D2 C6 05`，实际后续是 `C1 F8 02 89 55 D4 ...`。这条 `mov` 后面的 `esi` 仍用于 `0x100971DF` 至 `0x10097202` 的六次 `call esi`。

## 8948 `client.so`

SHA-256：`8b5fbb8f3533b38ab3fd53dfc6078012bc2f9259ba4e347b5bf301f3d0ebacc4`

| 源码后缀 | ELF VA = FO | 原始指令与对应依据 |
|---|---|---|
| `glTexEnvf` | `0x14FAA0` | `E8 9B 39 F5 FF`，`call glTexEnvf@plt`；前有 `0x8501, 0x8500` |
| `glBegin` | `0x155EFE` | `E8 DD 99 F4 FF`，`call glBegin@plt`；`CParticleSystem::ParticleDraw` |
| `glEnd` | `0x156177` | `E8 64 CF F4 FF`，`call glEnd@plt`；同一函数 |
| `glColor4f_DrawParticle` | `0x155F5D` | `E8 3E B9 F4 FF`，`call glColor4f@plt`；同一函数 |
| `glColor4f_DrawPortal` | `0x15CA21` | `E8 7A 4E F4 FF`，`call glColor4f@plt`；`ClientPortalManager::DrawPortals` |
| `glEnable_GenerateInvisibleTexture` | `0x1587EB` | `E8 60 96 F4 FF`，`call glEnable@plt`；`ClientPortalManager::GenerateInvisibleTexture`，实参 `0xDE1` |
| `glEnable_GeneratePortalTexture` ① | `0x15E64A` | `E8 01 38 F4 FF`，`call glEnable@plt`；`ClientPortalManager::PortalRender`，实参 `0xDE1` |
| `glEnable_GeneratePortalTexture` ② | `0x157670` | `E8 DB A7 F4 FF`，`call glEnable@plt`；`PortalSource::CreateTexture`，实参 `0xDE1` |
| `glDisable_FOG` | `0x167613` | `E8 A8 83 F3 FF`，`call glDisable@plt`，实参 `0xB60` |
| `glDisable_ClipPlane` | `0x158E28`, `0x158E34`, `0x158E40`, `0x158E4C`, `0x158E58`, `0x158E64` | `ClientPortalManager::DisableClipPlanes` 中六个 `call glDisable@plt`，实参依次 `0x3000` 至 `0x3005` |
| `glCopyTexSubImage2D_RenderPortals` | `0x15E6B7` | `E8 54 56 F4 FF`，`call glCopyTexSubImage2D@plt`，实参包含 `0xDE1` |
| `glClear_ClipPlane` | `0x15E1C1` | `E8 CA 17 F4 FF`，`call glClear@plt`，实参 `0x4000` |

## 核验记录

1. 从源码提取 11 个字节模式并仅扫描各 DLL 的 `.text`：10257 共 11 个调用点和 1 个指针加载点；8948 共 11 个调用点，`glDisable_ClipPlane` 模式无命中。
2. 使用 `objdump -d -M intel` 核对四份二进制的每条上述指令、指令长度、实参或后续上下文。8948 SO 的 `.symtab` 明确给出粒子、门户与裁剪平面相关函数名；10257 SO 以仓库的函数地址工件及指令上下文交叉核对。
3. 将 11 个 Windows 模式对两个完整 SO 文件再次扫描，全部零命中。SO 表因此只用于移植或分析时定位等价调用，不能直接用作原补丁模式。

## 函数归属与调用附近反汇编

下面的函数起止地址来自对应原始二进制的现有 IDB，终止地址为开区间。标注“仓库函数工件”或“ELF/IDB 符号”的名称有直接来源；“跨平台对应推定”的 Windows/10257 Linux 名称由 8948 ELF 符号、指令序列及调用上下文对应而得，IDB 自身仍为 `sub_*`。普通代码块保留目标前最多 6 条、后最多 3 条指令；`=>` 标示上述补丁点或 SO 对应点。`glDisable_ClipPlane` 额外列出相关的六条调用。

| 源码后缀 | 10257 DLL 函数 | 10257 SO 函数 | 8948 DLL 函数 | 8948 SO 函数 |
|---|---|---|---|---|
| `glTexEnvf` | `CParticleEngine::EngineThink` @ `0x10045C50` | `CParticleEngine::EngineThink` @ `0xECEFC` | `CParticleEngine::EngineThink` @ `0x1008DC80` | `CParticleEngine::EngineThink` @ `0x14FA78` |
| `glBegin` | `CParticleSystem::ParticleDraw` @ `0x10049AC0` | `CParticleSystem::ParticleDraw` @ `0xF39C2` | `CParticleSystem::ParticleDraw` @ `0x10091DF0` | `CParticleSystem::ParticleDraw` @ `0x155D24` |
| `glEnd` | `CParticleSystem::ParticleDraw` @ `0x10049AC0` | `CParticleSystem::ParticleDraw` @ `0xF39C2` | `CParticleSystem::ParticleDraw` @ `0x10091DF0` | `CParticleSystem::ParticleDraw` @ `0x155D24` |
| `glColor4f_DrawParticle` | `CParticleSystem::ParticleDraw` @ `0x10049AC0` | `CParticleSystem::ParticleDraw` @ `0xF39C2` | `CParticleSystem::ParticleDraw` @ `0x10091DF0` | `CParticleSystem::ParticleDraw` @ `0x155D24` |
| `glColor4f_DrawPortal` | `ClientPortalManager::DrawPortals` @ `0x1004F140` | `ClientPortalManager::DrawPortals` @ `0xFAE44` | `ClientPortalManager::DrawPortals` @ `0x10097670` | `ClientPortalManager::DrawPortals` @ `0x15C95E` |
| `glEnable_GenerateInvisibleTexture` | `ClientPortalManager::CreateInvisiblePortalTextures` @ `0x1004C900` | `ClientPortalManager::CreateInvisiblePortalTextures` @ `0xF70CE` | `ClientPortalManager::CreateInvisiblePortalTextures` @ `0x10094B10` | `ClientPortalManager::GenerateInvisibleTexture` @ `0x15877A` |
| `glEnable_GeneratePortalTexture ①` | `ClientPortalManager::RenderPortals` @ `0x1004E4F0` | `ClientPortalManager::RenderPortals` @ `0xFC2B4` | `ClientPortalManager::RenderPortals` @ `0x100969F0` | `ClientPortalManager::PortalRender` @ `0x15D88C` |
| `glEnable_GeneratePortalTexture ②` | `VRManager::GenerateTexture` @ `0x10075540` | `ClientPortal::CreateTexture` @ `0xF42F8` | `VRManager::GenerateTexture` @ `0x100BCB80` | `PortalSource::CreateTexture` @ `0x1575CE` |
| `glDisable_FOG` | `HUD_DrawTransparentTriangles` @ `0x1005BB10` | `HUD_DrawTransparentTriangles` @ `0x107140` | `HUD_DrawTransparentTriangles` @ `0x100A3AA0` | `HUD_DrawTransparentTriangles` @ `0x1675F8` |
| `glDisable_ClipPlane` | `ClientPortalManager::RenderPortals` @ `0x1004E4F0` | `ClientPortalManager::DisableClipPlanes` @ `0xF7846` | `ClientPortalManager::RenderPortals` @ `0x100969F0` | `ClientPortalManager::DisableClipPlanes` @ `0x158E14` |
| `glCopyTexSubImage2D_RenderPortals` | `ClientPortalManager::RenderPortals` @ `0x1004E4F0` | `ClientPortalManager::RenderPortals` @ `0xFC2B4` | `ClientPortalManager::RenderPortals` @ `0x100969F0` | `ClientPortalManager::PortalRender` @ `0x15D88C` |
| `glClear_ClipPlane` | `ClientPortalManager::RenderPortals` @ `0x1004E4F0` | `ClientPortalManager::RenderPortals` @ `0xFC2B4` | `ClientPortalManager::RenderPortals` @ `0x100969F0` | `ClientPortalManager::PortalRender` @ `0x15D88C` |

### 10257 `client.dll`

#### `glTexEnvf` — `CParticleEngine::EngineThink`

函数范围 `0x10045C50–0x10045D07`（跨平台对应推定；IDB: `sub_10045C50`）。

```asm
   10045C57: 51                                              push   ecx
   10045C58: 8B D9                                           mov    ebx,ecx
   10045C5A: F3 0F 10 40 0C                                  movss  xmm0,DWORD PTR [eax+0xc]
   10045C5F: F3 0F 11 04 24                                  movss  DWORD PTR [esp],xmm0
   10045C64: 68 01 85 00 00                                  push   0x8501
   10045C69: 68 00 85 00 00                                  push   0x8500
=> 10045C6E: FF 15 9C A1 11 10                               call   DWORD PTR ds:0x1011a19c
   10045C74: 80 7B 0C 00                                     cmp    BYTE PTR [ebx+0xc],0x0
   10045C78: 74 7F                                           je     0x10045cf9
   10045C7A: 56                                              push   esi
```

#### `glBegin` — `CParticleSystem::ParticleDraw`

函数范围 `0x10049AC0–0x1004A17F`（跨平台对应推定；IDB: `sub_10049AC0`）。

```asm
   10049D65: FF 70 04                                        push   DWORD PTR [eax+0x4]
   10049D68: E8 E4 14 0B 00                                  call   0x100fb251
   10049D6D: 50                                              push   eax
   10049D6E: FF D6                                           call   esi
   10049D70: 83 C4 08                                        add    esp,0x8
   10049D73: 6A 06                                           push   0x6
=> 10049D75: FF 15 94 A1 11 10                               call   DWORD PTR ds:0x1011a194
   10049D7B: F6 87 88 00 00 00 80                            test   BYTE PTR [edi+0x88],0x80
   10049D82: F3 0F 10 25 F8 10 12 10                         movss  xmm4,DWORD PTR ds:0x101210f8
   10049D8A: 0F 84 02 01 00 00                               je     0x10049e92
```

#### `glEnd` — `CParticleSystem::ParticleDraw`

函数范围 `0x10049AC0–0x1004A17F`（跨平台对应推定；IDB: `sub_10049AC0`）。

```asm
   1004A13E: FF D0                                           call   eax
   1004A140: A1 E0 8A 1F 10                                  mov    eax,ds:0x101f8ae0
   1004A145: 6A 00                                           push   0x0
   1004A147: 8B 40 04                                        mov    eax,DWORD PTR [eax+0x4]
   1004A14A: FF D0                                           call   eax
   1004A14C: 83 C4 10                                        add    esp,0x10
=> 1004A14F: FF 15 2C A2 11 10                               call   DWORD PTR ds:0x1011a22c
   1004A155: F7 87 88 00 00 00 00 01 00 00                   test   DWORD PTR [edi+0x88],0x100
   1004A15F: 74 0B                                           je     0x1004a16c
   1004A161: 68 71 0B 00 00                                  push   0xb71
```

#### `glColor4f_DrawParticle` — `CParticleSystem::ParticleDraw`

函数范围 `0x10049AC0–0x1004A17F`（跨平台对应推定；IDB: `sub_10049AC0`）。

```asm
   10049EB8: F3 0F 5E D4                                     divss  xmm2,xmm4
   10049EBC: F3 0F 5E CC                                     divss  xmm1,xmm4
   10049EC0: F3 0F 11 44 24 0C                               movss  DWORD PTR [esp+0xc],xmm0
   10049EC6: F3 0F 11 5C 24 08                               movss  DWORD PTR [esp+0x8],xmm3
   10049ECC: F3 0F 11 54 24 04                               movss  DWORD PTR [esp+0x4],xmm2
   10049ED2: F3 0F 11 0C 24                                  movss  DWORD PTR [esp],xmm1
=> 10049ED7: FF 15 98 A1 11 10                               call   DWORD PTR ds:0x1011a198
   10049EDD: 8D 45 98                                        lea    eax,[ebp-0x68]
   10049EE0: 50                                              push   eax
   10049EE1: 8D 4F 30                                        lea    ecx,[edi+0x30]
```

#### `glColor4f_DrawPortal` — `ClientPortalManager::DrawPortals`

函数范围 `0x1004F140–0x1004F360`（跨平台对应推定；IDB: `sub_1004F140`）。

```asm
   1004F1D1: FF D0                                           call   eax
   1004F1D3: C7 04 24 00 00 80 3F                            mov    DWORD PTR [esp],0x3f800000
   1004F1DA: 83 EC 0C                                        sub    esp,0xc
   1004F1DD: C7 44 24 08 00 00 80 3F                         mov    DWORD PTR [esp+0x8],0x3f800000
   1004F1E5: C7 44 24 04 00 00 80 3F                         mov    DWORD PTR [esp+0x4],0x3f800000
   1004F1ED: C7 04 24 00 00 80 3F                            mov    DWORD PTR [esp],0x3f800000
=> 1004F1F4: FF 15 98 A1 11 10                               call   DWORD PTR ds:0x1011a198
   1004F1FA: 68 E2 0B 00 00                                  push   0xbe2
   1004F1FF: FF 15 A4 A1 11 10                               call   DWORD PTR ds:0x1011a1a4
   1004F205: 68 03 02 00 00                                  push   0x203
```

#### `glEnable_GenerateInvisibleTexture` — `ClientPortalManager::CreateInvisiblePortalTextures`

函数范围 `0x1004C900–0x1004CB73`（仓库函数工件；IDB: `sub_1004C900`）。

```asm
   1004C970: 83 C4 08                                        add    esp,0x8
   1004C973: E9 D6 01 00 00                                  jmp    0x1004cb4e
   1004C978: 55                                              push   ebp
   1004C979: 6A 01                                           push   0x1
   1004C97B: FF 15 00 A2 11 10                               call   DWORD PTR ds:0x1011a200
   1004C981: 68 E1 0D 00 00                                  push   0xde1
=> 1004C986: FF 15 08 A2 11 10                               call   DWORD PTR ds:0x1011a208
   1004C98C: FF 75 00                                        push   DWORD PTR [ebp+0x0]
   1004C98F: 68 E1 0D 00 00                                  push   0xde1
   1004C994: FF 15 24 A2 11 10                               call   DWORD PTR ds:0x1011a224
```

#### `glEnable_GeneratePortalTexture ①` — `ClientPortalManager::RenderPortals`

函数范围 `0x1004E4F0–0x1004F12D`（仓库函数工件；IDB: `sub_1004E4F0`）。

```asm
   1004EA3C: 83 C4 08                                        add    esp,0x8
   1004EA3F: E9 9C 00 00 00                                  jmp    0x1004eae0
   1004EA44: 56                                              push   esi
   1004EA45: 6A 01                                           push   0x1
   1004EA47: FF 15 00 A2 11 10                               call   DWORD PTR ds:0x1011a200
   1004EA4D: 68 E1 0D 00 00                                  push   0xde1
=> 1004EA52: FF 15 08 A2 11 10                               call   DWORD PTR ds:0x1011a208
   1004EA58: FF 36                                           push   DWORD PTR [esi]
   1004EA5A: 68 E1 0D 00 00                                  push   0xde1
   1004EA5F: FF 15 24 A2 11 10                               call   DWORD PTR ds:0x1011a224
```

#### `glEnable_GeneratePortalTexture ②` — `VRManager::GenerateTexture`

函数范围 `0x10075540–0x100755DB`（跨平台对应推定；IDB: `sub_10075540`）。

```asm
   1007554D: FF 15 0C A2 11 10                               call   DWORD PTR ds:0x1011a20c
   10075553: C7 06 00 00 00 00                               mov    DWORD PTR [esi],0x0
   10075559: 56                                              push   esi
   1007555A: 6A 01                                           push   0x1
   1007555C: FF 15 00 A2 11 10                               call   DWORD PTR ds:0x1011a200
   10075562: 68 E1 0D 00 00                                  push   0xde1
=> 10075567: FF 15 08 A2 11 10                               call   DWORD PTR ds:0x1011a208
   1007556D: FF 36                                           push   DWORD PTR [esi]
   1007556F: 68 E1 0D 00 00                                  push   0xde1
   10075574: FF 15 24 A2 11 10                               call   DWORD PTR ds:0x1011a224
```

#### `glDisable_FOG` — `HUD_DrawTransparentTriangles`

函数范围 `0x1005BB10–0x1005BB90`（IDB 命名）。

```asm
   1005BB10: 68 60 0B 00 00                                  push   0xb60
=> 1005BB15: FF 15 A4 A1 11 10                               call   DWORD PTR ds:0x1011a1a4
   1005BB1B: A1 D0 C7 63 10                                  mov    eax,ds:0x1063c7d0
   1005BB20: 85 C0                                           test   eax,eax
   1005BB22: 75 1E                                           jne    0x1005bb42
```

#### `glDisable_ClipPlane` — `ClientPortalManager::RenderPortals`

函数范围 `0x1004E4F0–0x1004F12D`（仓库函数工件；IDB: `sub_1004E4F0`）。

```asm
   1004EBD1: 6A 00                                           push   0x0
   1004EBD3: 6A 00                                           push   0x0
   1004EBD5: 8B 01                                           mov    eax,DWORD PTR [ecx]
   1004EBD7: FF 50 2C                                        call   DWORD PTR [eax+0x2c]
=> 1004EBDA: 8B 35 A4 A1 11 10                               mov    esi,DWORD PTR ds:0x1011a1a4
   1004EBE0: 33 D2                                           xor    edx,edx
   1004EBE2: C6 05 05 C8 63 10 01                            mov    BYTE PTR ds:0x1063c805,0x1
   1004EBE9: 8B 47 04                                        mov    eax,DWORD PTR [edi+0x4]
   1004EBEC: 8B 0F                                           mov    ecx,DWORD PTR [edi]
```

源码 `WriteDWORD(pRealCall + 2, ...)` 写入 `0x1004EBDC`，随后 `esi` 被用于六次 `glDisable(GL_CLIP_PLANE0..5)` 间接调用。

被加载函数指针服务的六次调用：

```asm
   1004EC94: 68 00 30 00 00                                  push   0x3000
   1004EC99: 89 81 DC 00 00 00                               mov    DWORD PTR [ecx+0xdc],eax
   1004EC9F: FF D6                                           call   esi
   1004ECA1: 68 01 30 00 00                                  push   0x3001
   1004ECA6: FF D6                                           call   esi
   1004ECA8: 68 02 30 00 00                                  push   0x3002
   1004ECAD: FF D6                                           call   esi
   1004ECAF: 68 03 30 00 00                                  push   0x3003
   1004ECB4: FF D6                                           call   esi
   1004ECB6: 68 04 30 00 00                                  push   0x3004
   1004ECBB: FF D6                                           call   esi
   1004ECBD: 68 05 30 00 00                                  push   0x3005
   1004ECC2: FF D6                                           call   esi
```

#### `glCopyTexSubImage2D_RenderPortals` — `ClientPortalManager::RenderPortals`

函数范围 `0x1004E4F0–0x1004F12D`（仓库函数工件；IDB: `sub_1004E4F0`）。

```asm
   1004EFC5: 50                                              push   eax
   1004EFC6: 6A 00                                           push   0x0
   1004EFC8: 6A 00                                           push   0x0
   1004EFCA: 6A 00                                           push   0x0
   1004EFCC: 6A 00                                           push   0x0
   1004EFCE: 68 E1 0D 00 00                                  push   0xde1
=> 1004EFD3: FF 15 10 A2 11 10                               call   DWORD PTR ds:0x1011a210
   1004EFD9: 6A 00                                           push   0x0
   1004EFDB: 68 E1 0D 00 00                                  push   0xde1
   1004EFE0: FF D7                                           call   edi
```

#### `glClear_ClipPlane` — `ClientPortalManager::RenderPortals`

函数范围 `0x1004E4F0–0x1004F12D`（仓库函数工件；IDB: `sub_1004E4F0`）。

```asm
   1004ECF1: C7 44 24 0C 00 00 00 00                         mov    DWORD PTR [esp+0xc],0x0
   1004ECF9: C7 44 24 08 00 00 80 3F                         mov    DWORD PTR [esp+0x8],0x3f800000
   1004ED01: C7 44 24 04 00 00 00 00                         mov    DWORD PTR [esp+0x4],0x0
   1004ED09: C7 04 24 00 00 00 00                            mov    DWORD PTR [esp],0x0
   1004ED10: FF 15 1C A2 11 10                               call   DWORD PTR ds:0x1011a21c
   1004ED16: 68 00 40 00 00                                  push   0x4000
=> 1004ED1B: FF 15 20 A2 11 10                               call   DWORD PTR ds:0x1011a220
   1004ED21: FF 15 64 8A 1F 10                               call   DWORD PTR ds:0x101f8a64
   1004ED27: 8B F8                                           mov    edi,eax
   1004ED29: 89 7D C8                                        mov    DWORD PTR [ebp-0x38],edi
```


### 10257 `client.so`

#### `glTexEnvf` — `CParticleEngine::EngineThink`

函数范围 `0xECEFC–0xECFDC`（8948 ELF 符号及代码对应推定；IDB: `sub_ECEFC`）。

```asm
   000ECF12: 8D 83 5C AA 47 00                               lea    eax,[ebx+0x47aa5c]
   000ECF18: 8B 10                                           mov    edx,DWORD PTR [eax]
   000ECF1A: F3 0F 10 42 0C                                  movss  xmm0,DWORD PTR [edx+0xc]
   000ECF1F: F3 0F 11 44 24 08                               movss  DWORD PTR [esp+0x8],xmm0
   000ECF25: C7 44 24 04 01 85 00 00                         mov    DWORD PTR [esp+0x4],0x8501
   000ECF2D: C7 04 24 00 85 00 00                            mov    DWORD PTR [esp],0x8500
=> 000ECF34: E8 A7 D2 FA FF                                  call   9a1e0 <glTexEnvf@plt>
   000ECF39: 80 7D 0C 00                                     cmp    BYTE PTR [ebp+0xc],0x0
   000ECF3D: 0F 84 85 00 00 00                               je     ecfc8 <IN_ClearStates+0xba38>
   000ECF43: 8D B3 A0 9F 43 00                               lea    esi,[ebx+0x439fa0]
```

#### `glBegin` — `CParticleSystem::ParticleDraw`

函数范围 `0xF39C2–0xF4056`（8948 ELF 符号及代码对应推定；IDB: `sub_F39C2`）。

```asm
   000F3BA0: E8 6B 64 FA FF                                  call   9a010 <strtol@plt>
   000F3BA5: 89 04 24                                        mov    DWORD PTR [esp],eax
   000F3BA8: 8B 4C 24 1C                                     mov    ecx,DWORD PTR [esp+0x1c]
   000F3BAC: FF D1                                           call   ecx
   000F3BAE: C7 04 24 06 00 00 00                            mov    DWORD PTR [esp],0x6
   000F3BB5: 89 FB                                           mov    ebx,edi
=> 000F3BB7: E8 94 6A FA FF                                  call   9a650 <glBegin@plt>
   000F3BBC: F6 86 88 00 00 00 80                            test   BYTE PTR [esi+0x88],0x80
   000F3BC3: 0F 85 C1 03 00 00                               jne    f3f8a <IN_ClearStates+0x129fa>
   000F3BC9: D9 46 74                                        fld    DWORD PTR [esi+0x74]
```

#### `glEnd` — `CParticleSystem::ParticleDraw`

函数范围 `0xF39C2–0xF4056`（8948 ELF 符号及代码对应推定；IDB: `sub_F39C2`）。

```asm
   000F3E4F: 89 1C 24                                        mov    DWORD PTR [esp],ebx
   000F3E52: FF 50 1C                                        call   DWORD PTR [eax+0x1c]
   000F3E55: 8B AD 48 01 00 00                               mov    ebp,DWORD PTR [ebp+0x148]
   000F3E5B: C7 04 24 00 00 00 00                            mov    DWORD PTR [esp],0x0
   000F3E62: FF 55 04                                        call   DWORD PTR [ebp+0x4]
   000F3E65: 89 FB                                           mov    ebx,edi
=> 000F3E67: E8 84 64 FA FF                                  call   9a2f0 <glEnd@plt>
   000F3E6C: F6 86 89 00 00 00 01                            test   BYTE PTR [esi+0x89],0x1
   000F3E73: 0F 84 F4 FB FF FF                               je     f3a6d <IN_ClearStates+0x124dd>
   000F3E79: C7 04 24 71 0B 00 00                            mov    DWORD PTR [esp],0xb71
```

#### `glColor4f_DrawParticle` — `CParticleSystem::ParticleDraw`

函数范围 `0xF39C2–0xF4056`（8948 ELF 符号及代码对应推定；IDB: `sub_F39C2`）。

```asm
   000F3C04: DC F9                                           fdiv   st(1),st
   000F3C06: D9 C9                                           fxch   st(1)
   000F3C08: D9 5C 24 04                                     fstp   DWORD PTR [esp+0x4]
   000F3C0C: DE F9                                           fdivp  st(1),st
   000F3C0E: D9 1C 24                                        fstp   DWORD PTR [esp]
   000F3C11: 89 FB                                           mov    ebx,edi
=> 000F3C13: E8 68 6C FA FF                                  call   9a880 <glColor4f@plt>
   000F3C18: D9 46 30                                        fld    DWORD PTR [esi+0x30]
   000F3C1B: D9 46 34                                        fld    DWORD PTR [esi+0x34]
   000F3C1E: D9 44 24 38                                     fld    DWORD PTR [esp+0x38]
```

#### `glColor4f_DrawPortal` — `ClientPortalManager::DrawPortals`

函数范围 `0xFAE44–0xFB0F6`（8948 ELF 符号及代码对应推定；IDB: `sub_FAE44`）。

```asm
   000FAF43: FF 55 04                                        call   DWORD PTR [ebp+0x4]
   000FAF46: D9 E8                                           fld1
   000FAF48: D9 54 24 0C                                     fst    DWORD PTR [esp+0xc]
   000FAF4C: D9 54 24 08                                     fst    DWORD PTR [esp+0x8]
   000FAF50: D9 54 24 04                                     fst    DWORD PTR [esp+0x4]
   000FAF54: D9 1C 24                                        fstp   DWORD PTR [esp]
=> 000FAF57: E8 24 F9 F9 FF                                  call   9a880 <glColor4f@plt>
   000FAF5C: C7 04 24 E2 0B 00 00                            mov    DWORD PTR [esp],0xbe2
   000FAF63: E8 E8 F4 F9 FF                                  call   9a450 <glDisable@plt>
   000FAF68: C7 04 24 03 02 00 00                            mov    DWORD PTR [esp],0x203
```

#### `glEnable_GenerateInvisibleTexture` — `ClientPortalManager::CreateInvisiblePortalTextures`

函数范围 `0xF70CE–0xF7387`（仓库函数工件；IDB: `sub_F70CE`）。

```asm
   000F7171: 90                                              nop
   000F7172: 8D 86 A4 01 00 00                               lea    eax,[esi+0x1a4]
   000F7178: 89 44 24 04                                     mov    DWORD PTR [esp+0x4],eax
   000F717C: C7 04 24 01 00 00 00                            mov    DWORD PTR [esp],0x1
   000F7183: E8 88 26 FA FF                                  call   99810 <glGenTextures@plt>
   000F7188: C7 04 24 E1 0D 00 00                            mov    DWORD PTR [esp],0xde1
=> 000F718F: E8 3C 2A FA FF                                  call   99bd0 <glEnable@plt>
   000F7194: 8B 96 A4 01 00 00                               mov    edx,DWORD PTR [esi+0x1a4]
   000F719A: 89 54 24 04                                     mov    DWORD PTR [esp+0x4],edx
   000F719E: C7 04 24 E1 0D 00 00                            mov    DWORD PTR [esp],0xde1
```

#### `glEnable_GeneratePortalTexture ①` — `ClientPortalManager::RenderPortals`

函数范围 `0xFC2B4–0xFD27F`（仓库函数工件；IDB: `sub_FC2B4`）。

```asm
   000FD184: 5E                                              pop    esi
   000FD185: 5F                                              pop    edi
   000FD186: 5D                                              pop    ebp
   000FD187: C3                                              ret
   000FD188: C7 04 24 E1 0D 00 00                            mov    DWORD PTR [esp],0xde1
   000FD18F: 8B 5C 24 30                                     mov    ebx,DWORD PTR [esp+0x30]
=> 000FD193: E8 38 CA F9 FF                                  call   99bd0 <glEnable@plt>
   000FD198: 8B 9E C4 00 00 00                               mov    ebx,DWORD PTR [esi+0xc4]
   000FD19E: 89 5C 24 04                                     mov    DWORD PTR [esp+0x4],ebx
   000FD1A2: C7 04 24 E1 0D 00 00                            mov    DWORD PTR [esp],0xde1
```

#### `glEnable_GeneratePortalTexture ②` — `ClientPortal::CreateTexture`

函数范围 `0xF42F8–0xF4469`（仓库函数工件；IDB: `sub_F42F8`）。

```asm
   000F4383: C3                                              ret
   000F4384: 8D 86 C4 00 00 00                               lea    eax,[esi+0xc4]
   000F438A: 89 44 24 04                                     mov    DWORD PTR [esp+0x4],eax
   000F438E: C7 04 24 01 00 00 00                            mov    DWORD PTR [esp],0x1
   000F4395: E8 76 54 FA FF                                  call   99810 <glGenTextures@plt>
   000F439A: C7 04 24 E1 0D 00 00                            mov    DWORD PTR [esp],0xde1
=> 000F43A1: E8 2A 58 FA FF                                  call   99bd0 <glEnable@plt>
   000F43A6: 8B 96 C4 00 00 00                               mov    edx,DWORD PTR [esi+0xc4]
   000F43AC: 89 54 24 04                                     mov    DWORD PTR [esp+0x4],edx
   000F43B0: C7 04 24 E1 0D 00 00                            mov    DWORD PTR [esp],0xde1
```

#### `glDisable_FOG` — `HUD_DrawTransparentTriangles`

函数范围 `0x107140–0x107344`（ELF/IDB 符号）。

```asm
   00107143: 53                                              push   ebx
   00107144: 83 EC 2C                                        sub    esp,0x2c
   00107147: E8 F3 C2 F9 FF                                  call   a343f <strncmp@plt+0x89d7>
   0010714C: 81 C6 B4 6E 51 00                               add    esi,0x516eb4
   00107152: C7 04 24 60 0B 00 00                            mov    DWORD PTR [esp],0xb60
   00107159: 89 F3                                           mov    ebx,esi
=> 0010715B: E8 F0 32 F9 FF                                  call   9a450 <glDisable@plt>
   00107160: 8D AE B0 CA 47 00                               lea    ebp,[esi+0x47cab0]
   00107166: 8B 7D 00                                        mov    edi,DWORD PTR [ebp+0x0]
   00107169: 85 FF                                           test   edi,edi
```

#### `glDisable_ClipPlane` — `ClientPortalManager::DisableClipPlanes`

函数范围 `0xF7846–0xF78A2`（8948 ELF 符号及代码对应推定；IDB: `sub_F7846`）。

```asm
   000F7847: 83 EC 18                                        sub    esp,0x18
   000F784A: E8 41 6D FA FF                                  call   9e590 <strncmp@plt+0x3b28>
   000F784F: 81 C3 B1 67 52 00                               add    ebx,0x5267b1
   000F7855: C7 04 24 00 30 00 00                            mov    DWORD PTR [esp],0x3000
=> 000F785C: E8 EF 2B FA FF                                  call   9a450 <glDisable@plt>
   000F7861: C7 04 24 01 30 00 00                            mov    DWORD PTR [esp],0x3001
=> 000F7868: E8 E3 2B FA FF                                  call   9a450 <glDisable@plt>
   000F786D: C7 04 24 02 30 00 00                            mov    DWORD PTR [esp],0x3002
=> 000F7874: E8 D7 2B FA FF                                  call   9a450 <glDisable@plt>
   000F7879: C7 04 24 03 30 00 00                            mov    DWORD PTR [esp],0x3003
=> 000F7880: E8 CB 2B FA FF                                  call   9a450 <glDisable@plt>
   000F7885: C7 04 24 04 30 00 00                            mov    DWORD PTR [esp],0x3004
=> 000F788C: E8 BF 2B FA FF                                  call   9a450 <glDisable@plt>
   000F7891: C7 04 24 05 30 00 00                            mov    DWORD PTR [esp],0x3005
=> 000F7898: E8 B3 2B FA FF                                  call   9a450 <glDisable@plt>
   000F789D: 83 C4 18                                        add    esp,0x18
   000F78A0: 5B                                              pop    ebx
   000F78A1: C3                                              ret
```

#### `glCopyTexSubImage2D_RenderPortals` — `ClientPortalManager::RenderPortals`

函数范围 `0xFC2B4–0xFD27F`（仓库函数工件；IDB: `sub_FC2B4`）。

```asm
   000FD1E8: C7 44 24 10 00 00 00 00                         mov    DWORD PTR [esp+0x10],0x0
   000FD1F0: C7 44 24 0C 00 00 00 00                         mov    DWORD PTR [esp+0xc],0x0
   000FD1F8: C7 44 24 08 00 00 00 00                         mov    DWORD PTR [esp+0x8],0x0
   000FD200: C7 44 24 04 00 00 00 00                         mov    DWORD PTR [esp+0x4],0x0
   000FD208: C7 04 24 E1 0D 00 00                            mov    DWORD PTR [esp],0xde1
   000FD20F: 8B 5C 24 30                                     mov    ebx,DWORD PTR [esp+0x30]
=> 000FD213: E8 88 D2 F9 FF                                  call   9a4a0 <glCopyTexSubImage2D@plt>
   000FD218: C7 44 24 04 00 00 00 00                         mov    DWORD PTR [esp+0x4],0x0
   000FD220: C7 04 24 E1 0D 00 00                            mov    DWORD PTR [esp],0xde1
   000FD227: E8 24 D7 F9 FF                                  call   9a950 <glBindTexture@plt>
```

#### `glClear_ClipPlane` — `ClientPortalManager::RenderPortals`

函数范围 `0xFC2B4–0xFD27F`（仓库函数工件；IDB: `sub_FC2B4`）。

```asm
   000FCC07: C7 44 24 08 00 00 80 3F                         mov    DWORD PTR [esp+0x8],0x3f800000
   000FCC0F: D9 54 24 04                                     fst    DWORD PTR [esp+0x4]
   000FCC13: D9 1C 24                                        fstp   DWORD PTR [esp]
   000FCC16: E8 35 C7 F9 FF                                  call   99350 <glClearColor@plt>
   000FCC1B: C7 04 24 00 40 00 00                            mov    DWORD PTR [esp],0x4000
   000FCC22: 8B 5C 24 30                                     mov    ebx,DWORD PTR [esp+0x30]
=> 000FCC26: E8 B5 CF F9 FF                                  call   99be0 <glClear@plt>
   000FCC2B: 8B 5C 24 60                                     mov    ebx,DWORD PTR [esp+0x60]
   000FCC2F: FF 93 CC 00 00 00                               call   DWORD PTR [ebx+0xcc]
   000FCC35: 89 44 24 3C                                     mov    DWORD PTR [esp+0x3c],eax
```


### 8948 `client.dll`

#### `glTexEnvf` — `CParticleEngine::EngineThink`

函数范围 `0x1008DC80–0x1008DD37`（跨平台对应推定；IDB: `sub_1008DC80`）。

```asm
   1008DC87: 51                                              push   ecx
   1008DC88: 8B D9                                           mov    ebx,ecx
   1008DC8A: F3 0F 10 40 0C                                  movss  xmm0,DWORD PTR [eax+0xc]
   1008DC8F: F3 0F 11 04 24                                  movss  DWORD PTR [esp],xmm0
   1008DC94: 68 01 85 00 00                                  push   0x8501
   1008DC99: 68 00 85 00 00                                  push   0x8500
=> 1008DC9E: FF 15 E8 51 0E 10                               call   DWORD PTR ds:0x100e51e8
   1008DCA4: 80 7B 0C 00                                     cmp    BYTE PTR [ebx+0xc],0x0
   1008DCA8: 74 7F                                           je     0x1008dd29
   1008DCAA: 56                                              push   esi
```

#### `glBegin` — `CParticleSystem::ParticleDraw`

函数范围 `0x10091DF0–0x100924B2`（跨平台对应推定；IDB: `sub_10091DF0`）。

```asm
   10092098: E8 FD 9C 03 00                                  call   0x100cbd9a
   1009209D: 50                                              push   eax
   1009209E: 8B 46 04                                        mov    eax,DWORD PTR [esi+0x4]
   100920A1: FF D0                                           call   eax
   100920A3: 83 C4 08                                        add    esp,0x8
   100920A6: 6A 06                                           push   0x6
=> 100920A8: FF 15 10 52 0E 10                               call   DWORD PTR ds:0x100e5210
   100920AE: F6 87 88 00 00 00 80                            test   BYTE PTR [edi+0x88],0x80
   100920B5: F3 0F 10 25 30 AC 10 10                         movss  xmm4,DWORD PTR ds:0x1010ac30
   100920BD: 0F 84 02 01 00 00                               je     0x100921c5
```

#### `glEnd` — `CParticleSystem::ParticleDraw`

函数范围 `0x10091DF0–0x100924B2`（跨平台对应推定；IDB: `sub_10091DF0`）。

```asm
   10092471: FF D0                                           call   eax
   10092473: A1 D0 A9 1B 10                                  mov    eax,ds:0x101ba9d0
   10092478: 6A 00                                           push   0x0
   1009247A: 8B 40 04                                        mov    eax,DWORD PTR [eax+0x4]
   1009247D: FF D0                                           call   eax
   1009247F: 83 C4 10                                        add    esp,0x10
=> 10092482: FF 15 00 52 0E 10                               call   DWORD PTR ds:0x100e5200
   10092488: F7 87 88 00 00 00 00 01 00 00                   test   DWORD PTR [edi+0x88],0x100
   10092492: 74 0B                                           je     0x1009249f
   10092494: 68 71 0B 00 00                                  push   0xb71
```

#### `glColor4f_DrawParticle` — `CParticleSystem::ParticleDraw`

函数范围 `0x10091DF0–0x100924B2`（跨平台对应推定；IDB: `sub_10091DF0`）。

```asm
   100921EB: F3 0F 5E D4                                     divss  xmm2,xmm4
   100921EF: F3 0F 5E CC                                     divss  xmm1,xmm4
   100921F3: F3 0F 11 44 24 0C                               movss  DWORD PTR [esp+0xc],xmm0
   100921F9: F3 0F 11 5C 24 08                               movss  DWORD PTR [esp+0x8],xmm3
   100921FF: F3 0F 11 54 24 04                               movss  DWORD PTR [esp+0x4],xmm2
   10092205: F3 0F 11 0C 24                                  movss  DWORD PTR [esp],xmm1
=> 1009220A: FF 15 0C 52 0E 10                               call   DWORD PTR ds:0x100e520c
   10092210: 8D 45 98                                        lea    eax,[ebp-0x68]
   10092213: 50                                              push   eax
   10092214: 8D 4F 30                                        lea    ecx,[edi+0x30]
```

#### `glColor4f_DrawPortal` — `ClientPortalManager::DrawPortals`

函数范围 `0x10097670–0x10097890`（跨平台对应推定；IDB: `sub_10097670`）。

```asm
   10097701: FF D0                                           call   eax
   10097703: C7 04 24 00 00 80 3F                            mov    DWORD PTR [esp],0x3f800000
   1009770A: 83 EC 0C                                        sub    esp,0xc
   1009770D: C7 44 24 08 00 00 80 3F                         mov    DWORD PTR [esp+0x8],0x3f800000
   10097715: C7 44 24 04 00 00 80 3F                         mov    DWORD PTR [esp+0x4],0x3f800000
   1009771D: C7 04 24 00 00 80 3F                            mov    DWORD PTR [esp],0x3f800000
=> 10097724: FF 15 0C 52 0E 10                               call   DWORD PTR ds:0x100e520c
   1009772A: 68 E2 0B 00 00                                  push   0xbe2
   1009772F: FF 15 08 52 0E 10                               call   DWORD PTR ds:0x100e5208
   10097735: 68 03 02 00 00                                  push   0x203
```

#### `glEnable_GenerateInvisibleTexture` — `ClientPortalManager::CreateInvisiblePortalTextures`

函数范围 `0x10094B10–0x10094D83`（仓库函数工件；IDB: `sub_10094B10`）。

```asm
   10094B80: 83 C4 08                                        add    esp,0x8
   10094B83: E9 D6 01 00 00                                  jmp    0x10094d5e
   10094B88: 55                                              push   ebp
   10094B89: 6A 01                                           push   0x1
   10094B8B: FF 15 D4 51 0E 10                               call   DWORD PTR ds:0x100e51d4
   10094B91: 68 E1 0D 00 00                                  push   0xde1
=> 10094B96: FF 15 04 52 0E 10                               call   DWORD PTR ds:0x100e5204
   10094B9C: FF 75 00                                        push   DWORD PTR [ebp+0x0]
   10094B9F: 68 E1 0D 00 00                                  push   0xde1
   10094BA4: FF 15 F8 51 0E 10                               call   DWORD PTR ds:0x100e51f8
```

#### `glEnable_GeneratePortalTexture ①` — `ClientPortalManager::RenderPortals`

函数范围 `0x100969F0–0x10097661`（仓库函数工件；IDB: `sub_100969F0`）。

```asm
   10096F92: 83 C4 08                                        add    esp,0x8
   10096F95: E9 9C 00 00 00                                  jmp    0x10097036
   10096F9A: 56                                              push   esi
   10096F9B: 6A 01                                           push   0x1
   10096F9D: FF 15 D4 51 0E 10                               call   DWORD PTR ds:0x100e51d4
   10096FA3: 68 E1 0D 00 00                                  push   0xde1
=> 10096FA8: FF 15 04 52 0E 10                               call   DWORD PTR ds:0x100e5204
   10096FAE: FF 36                                           push   DWORD PTR [esi]
   10096FB0: 68 E1 0D 00 00                                  push   0xde1
   10096FB5: FF 15 F8 51 0E 10                               call   DWORD PTR ds:0x100e51f8
```

#### `glEnable_GeneratePortalTexture ②` — `VRManager::GenerateTexture`

函数范围 `0x100BCB80–0x100BCC1B`（跨平台对应推定；IDB: `sub_100BCB80`）。

```asm
   100BCB8D: FF 15 E0 51 0E 10                               call   DWORD PTR ds:0x100e51e0
   100BCB93: C7 06 00 00 00 00                               mov    DWORD PTR [esi],0x0
   100BCB99: 56                                              push   esi
   100BCB9A: 6A 01                                           push   0x1
   100BCB9C: FF 15 D4 51 0E 10                               call   DWORD PTR ds:0x100e51d4
   100BCBA2: 68 E1 0D 00 00                                  push   0xde1
=> 100BCBA7: FF 15 04 52 0E 10                               call   DWORD PTR ds:0x100e5204
   100BCBAD: FF 36                                           push   DWORD PTR [esi]
   100BCBAF: 68 E1 0D 00 00                                  push   0xde1
   100BCBB4: FF 15 F8 51 0E 10                               call   DWORD PTR ds:0x100e51f8
```

#### `glDisable_FOG` — `HUD_DrawTransparentTriangles`

函数范围 `0x100A3AA0–0x100A3B20`（IDB 命名）。

```asm
   100A3AA0: 68 60 0B 00 00                                  push   0xb60
=> 100A3AA5: FF 15 08 52 0E 10                               call   DWORD PTR ds:0x100e5208
   100A3AAB: A1 B8 E1 5F 10                                  mov    eax,ds:0x105fe1b8
   100A3AB0: 85 C0                                           test   eax,eax
   100A3AB2: 75 1E                                           jne    0x100a3ad2
```

#### `glDisable_ClipPlane` — `ClientPortalManager::RenderPortals`

函数范围 `0x100969F0–0x10097661`（仓库函数工件；模式失配；IDB: `sub_100969F0`）。

```asm
   10097128: 33 D2                                           xor    edx,edx
   1009712A: 8B 46 04                                        mov    eax,DWORD PTR [esi+0x4]
   1009712D: 8B 0E                                           mov    ecx,DWORD PTR [esi]
   1009712F: 2B C1                                           sub    eax,ecx
=> 10097131: 8B 35 08 52 0E 10                               mov    esi,DWORD PTR ds:0x100e5208
   10097137: C1 F8 02                                        sar    eax,0x2
   1009713A: 89 55 D4                                        mov    DWORD PTR [ebp-0x2c],edx
   1009713D: 85 C0                                           test   eax,eax
   1009713F: 0F 84 A4 04 00 00                               je     0x100975e9
```

此处是 8948 的语义对应指令，源码模式在本版零命中；若改写操作数，其位置是 `0x10097133`。随后 `esi` 被用于六次 `glDisable(GL_CLIP_PLANE0..5)` 间接调用。

被加载函数指针服务的六次调用：

```asm
   100971D4: 68 00 30 00 00                                  push   0x3000
   100971D9: 89 81 DC 00 00 00                               mov    DWORD PTR [ecx+0xdc],eax
   100971DF: FF D6                                           call   esi
   100971E1: 68 01 30 00 00                                  push   0x3001
   100971E6: FF D6                                           call   esi
   100971E8: 68 02 30 00 00                                  push   0x3002
   100971ED: FF D6                                           call   esi
   100971EF: 68 03 30 00 00                                  push   0x3003
   100971F4: FF D6                                           call   esi
   100971F6: 68 04 30 00 00                                  push   0x3004
   100971FB: FF D6                                           call   esi
   100971FD: 68 05 30 00 00                                  push   0x3005
   10097202: FF D6                                           call   esi
```

#### `glCopyTexSubImage2D_RenderPortals` — `ClientPortalManager::RenderPortals`

函数范围 `0x100969F0–0x10097661`（仓库函数工件；IDB: `sub_100969F0`）。

```asm
   100974F8: 50                                              push   eax
   100974F9: 6A 00                                           push   0x0
   100974FB: 6A 00                                           push   0x0
   100974FD: 6A 00                                           push   0x0
   100974FF: 6A 00                                           push   0x0
   10097501: 68 E1 0D 00 00                                  push   0xde1
=> 10097506: FF 15 E4 51 0E 10                               call   DWORD PTR ds:0x100e51e4
   1009750C: 6A 00                                           push   0x0
   1009750E: 68 E1 0D 00 00                                  push   0xde1
   10097513: FF 15 F8 51 0E 10                               call   DWORD PTR ds:0x100e51f8
```

#### `glClear_ClipPlane` — `ClientPortalManager::RenderPortals`

函数范围 `0x100969F0–0x10097661`（仓库函数工件；IDB: `sub_100969F0`）。

```asm
   10097230: C7 44 24 0C 00 00 00 00                         mov    DWORD PTR [esp+0xc],0x0
   10097238: C7 44 24 08 00 00 80 3F                         mov    DWORD PTR [esp+0x8],0x3f800000
   10097240: C7 44 24 04 00 00 00 00                         mov    DWORD PTR [esp+0x4],0x0
   10097248: C7 04 24 00 00 00 00                            mov    DWORD PTR [esp],0x0
   1009724F: FF 15 F0 51 0E 10                               call   DWORD PTR ds:0x100e51f0
   10097255: 68 00 40 00 00                                  push   0x4000
=> 1009725A: FF 15 F4 51 0E 10                               call   DWORD PTR ds:0x100e51f4
   10097260: FF 15 54 A9 1B 10                               call   DWORD PTR ds:0x101ba954
   10097266: 89 45 E8                                        mov    DWORD PTR [ebp-0x18],eax
   10097269: FF 15 60 A9 1B 10                               call   DWORD PTR ds:0x101ba960
```


### 8948 `client.so`

#### `glTexEnvf` — `CParticleEngine::EngineThink`

函数范围 `0x14FA78–0x14FB5C`（ELF 符号）。

```asm
   0014FA8A: 8B 83 98 CB FF FF                               mov    eax,DWORD PTR [ebx-0x3468]
   0014FA90: 8B 10                                           mov    edx,DWORD PTR [eax]
   0014FA92: 8B 4A 0C                                        mov    ecx,DWORD PTR [edx+0xc]
   0014FA95: 51                                              push   ecx
   0014FA96: 68 01 85 00 00                                  push   0x8501
   0014FA9B: 68 00 85 00 00                                  push   0x8500
=> 0014FAA0: E8 9B 39 F5 FF                                  call   a3440 <glTexEnvf@plt>
   0014FAA5: 83 C4 10                                        add    esp,0x10
   0014FAA8: 8B 74 24 20                                     mov    esi,DWORD PTR [esp+0x20]
   0014FAAC: 80 7E 0C 00                                     cmp    BYTE PTR [esi+0xc],0x0
```

#### `glBegin` — `CParticleSystem::ParticleDraw`

函数范围 `0x155D24–0x1563B2`（ELF 符号）。

```asm
   00155EEC: 8B 85 7C FF FF FF                               mov    eax,DWORD PTR [ebp-0x84]
   00155EF2: FF D0                                           call   eax
   00155EF4: 83 C4 10                                        add    esp,0x10
   00155EF7: 83 EC 0C                                        sub    esp,0xc
   00155EFA: 6A 06                                           push   0x6
   00155EFC: 89 FB                                           mov    ebx,edi
=> 00155EFE: E8 DD 99 F4 FF                                  call   9f8e0 <glBegin@plt>
   00155F03: 83 C4 10                                        add    esp,0x10
   00155F06: F6 86 88 00 00 00 80                            test   BYTE PTR [esi+0x88],0x80
   00155F0D: 0F 85 C5 03 00 00                               jne    1562d8 <_ZN15CParticleSystem12ParticleDrawEP13CParticleUnit+0x5b4>
```

#### `glEnd` — `CParticleSystem::ParticleDraw`

函数范围 `0x155D24–0x1563B2`（ELF 符号）。

```asm
   0015615F: 8B 5D 8C                                        mov    ebx,DWORD PTR [ebp-0x74]
   00156162: 8B 8B 48 01 00 00                               mov    ecx,DWORD PTR [ebx+0x148]
   00156168: C7 04 24 00 00 00 00                            mov    DWORD PTR [esp],0x0
   0015616F: FF 51 04                                        call   DWORD PTR [ecx+0x4]
   00156172: 83 C4 10                                        add    esp,0x10
   00156175: 89 FB                                           mov    ebx,edi
=> 00156177: E8 64 CF F4 FF                                  call   a30e0 <glEnd@plt>
   0015617C: F6 86 89 00 00 00 01                            test   BYTE PTR [esi+0x89],0x1
   00156183: 0F 84 54 FC FF FF                               je     155ddd <_ZN15CParticleSystem12ParticleDrawEP13CParticleUnit+0xb9>
   00156189: 83 EC 0C                                        sub    esp,0xc
```

#### `glColor4f_DrawParticle` — `CParticleSystem::ParticleDraw`

函数范围 `0x155D24–0x1563B2`（ELF 符号）。

```asm
   00155F4E: DC F9                                           fdiv   st(1),st
   00155F50: D9 C9                                           fxch   st(1)
   00155F52: D9 5C 24 04                                     fstp   DWORD PTR [esp+0x4]
   00155F56: DE F9                                           fdivp  st(1),st
   00155F58: D9 1C 24                                        fstp   DWORD PTR [esp]
   00155F5B: 89 FB                                           mov    ebx,edi
=> 00155F5D: E8 3E B9 F4 FF                                  call   a18a0 <glColor4f@plt>
   00155F62: D9 46 30                                        fld    DWORD PTR [esi+0x30]
   00155F65: D9 45 B0                                        fld    DWORD PTR [ebp-0x50]
   00155F68: D9 46 34                                        fld    DWORD PTR [esi+0x34]
```

#### `glColor4f_DrawPortal` — `ClientPortalManager::DrawPortals`

函数范围 `0x15C95E–0x15CB75`（ELF 符号）。

```asm
   0015CA0D: FF 50 04                                        call   DWORD PTR [eax+0x4]
   0015CA10: D9 E8                                           fld1
   0015CA12: D9 54 24 0C                                     fst    DWORD PTR [esp+0xc]
   0015CA16: D9 54 24 08                                     fst    DWORD PTR [esp+0x8]
   0015CA1A: D9 54 24 04                                     fst    DWORD PTR [esp+0x4]
   0015CA1E: D9 1C 24                                        fstp   DWORD PTR [esp]
=> 0015CA21: E8 7A 4E F4 FF                                  call   a18a0 <glColor4f@plt>
   0015CA26: C7 04 24 E2 0B 00 00                            mov    DWORD PTR [esp],0xbe2
   0015CA2D: E8 8E 2F F4 FF                                  call   9f9c0 <glDisable@plt>
   0015CA32: C7 04 24 03 02 00 00                            mov    DWORD PTR [esp],0x203
```

#### `glEnable_GenerateInvisibleTexture` — `ClientPortalManager::GenerateInvisibleTexture`

函数范围 `0x15877A–0x1589AB`（ELF 符号）。

```asm
   001587D3: 83 EC 08                                        sub    esp,0x8
   001587D6: 8D 86 A4 01 00 00                               lea    eax,[esi+0x1a4]
   001587DC: 50                                              push   eax
   001587DD: 6A 01                                           push   0x1
   001587DF: E8 1C AD F4 FF                                  call   a3500 <glGenTextures@plt>
   001587E4: C7 04 24 E1 0D 00 00                            mov    DWORD PTR [esp],0xde1
=> 001587EB: E8 60 96 F4 FF                                  call   a1e50 <glEnable@plt>
   001587F0: 58                                              pop    eax
   001587F1: 5A                                              pop    edx
   001587F2: 8B 96 A4 01 00 00                               mov    edx,DWORD PTR [esi+0x1a4]
```

#### `glEnable_GeneratePortalTexture ①` — `ClientPortalManager::PortalRender`

函数范围 `0x15D88C–0x15E71F`（ELF 符号）。

```asm
   0015E63E: 5E                                              pop    esi
   0015E63F: 5F                                              pop    edi
   0015E640: 5D                                              pop    ebp
   0015E641: C3                                              ret
   0015E642: 83 EC 0C                                        sub    esp,0xc
   0015E645: 68 E1 0D 00 00                                  push   0xde1
=> 0015E64A: E8 01 38 F4 FF                                  call   a1e50 <glEnable@plt>
   0015E64F: 5A                                              pop    edx
   0015E650: 59                                              pop    ecx
   0015E651: 8B 87 C4 00 00 00                               mov    eax,DWORD PTR [edi+0xc4]
```

#### `glEnable_GeneratePortalTexture ②` — `PortalSource::CreateTexture`

函数范围 `0x1575CE–0x157719`（ELF 符号）。

```asm
   00157658: 83 EC 08                                        sub    esp,0x8
   0015765B: 8D 86 C4 00 00 00                               lea    eax,[esi+0xc4]
   00157661: 50                                              push   eax
   00157662: 6A 01                                           push   0x1
   00157664: E8 97 BE F4 FF                                  call   a3500 <glGenTextures@plt>
   00157669: C7 04 24 E1 0D 00 00                            mov    DWORD PTR [esp],0xde1
=> 00157670: E8 DB A7 F4 FF                                  call   a1e50 <glEnable@plt>
   00157675: 58                                              pop    eax
   00157676: 5A                                              pop    edx
   00157677: 8B 96 C4 00 00 00                               mov    edx,DWORD PTR [esi+0xc4]
```

#### `glDisable_FOG` — `HUD_DrawTransparentTriangles`

函数范围 `0x1675F8–0x1677F1`（ELF/IDB 符号）。

```asm
   001675FD: 53                                              push   ebx
   001675FE: 83 EC 28                                        sub    esp,0x28
   00167601: E8 52 57 F4 FF                                  call   acd58 <__x86.get_pc_thunk.si>
   00167606: 81 C6 FA 09 1A 00                               add    esi,0x1a09fa
   0016760C: 68 60 0B 00 00                                  push   0xb60
   00167611: 89 F3                                           mov    ebx,esi
=> 00167613: E8 A8 83 F3 FF                                  call   9f9c0 <glDisable@plt>
   00167618: 8B BE 90 BF FF FF                               mov    edi,DWORD PTR [esi-0x4070]
   0016761E: 8B 07                                           mov    eax,DWORD PTR [edi]
   00167620: 83 C4 10                                        add    esp,0x10
```

#### `glDisable_ClipPlane` — `ClientPortalManager::DisableClipPlanes`

函数范围 `0x158E14–0x158E6E`（ELF 符号）。

```asm
   00158E15: 83 EC 14                                        sub    esp,0x14
   00158E18: E8 93 F1 F4 FF                                  call   a7fb0 <__x86.get_pc_thunk.bx>
   00158E1D: 81 C3 E3 F1 1A 00                               add    ebx,0x1af1e3
   00158E23: 68 00 30 00 00                                  push   0x3000
=> 00158E28: E8 93 6B F4 FF                                  call   9f9c0 <glDisable@plt>
   00158E2D: C7 04 24 01 30 00 00                            mov    DWORD PTR [esp],0x3001
=> 00158E34: E8 87 6B F4 FF                                  call   9f9c0 <glDisable@plt>
   00158E39: C7 04 24 02 30 00 00                            mov    DWORD PTR [esp],0x3002
=> 00158E40: E8 7B 6B F4 FF                                  call   9f9c0 <glDisable@plt>
   00158E45: C7 04 24 03 30 00 00                            mov    DWORD PTR [esp],0x3003
=> 00158E4C: E8 6F 6B F4 FF                                  call   9f9c0 <glDisable@plt>
   00158E51: C7 04 24 04 30 00 00                            mov    DWORD PTR [esp],0x3004
=> 00158E58: E8 63 6B F4 FF                                  call   9f9c0 <glDisable@plt>
   00158E5D: C7 04 24 05 30 00 00                            mov    DWORD PTR [esp],0x3005
=> 00158E64: E8 57 6B F4 FF                                  call   9f9c0 <glDisable@plt>
   00158E69: 83 C4 18                                        add    esp,0x18
   00158E6C: 5B                                              pop    ebx
   00158E6D: C3                                              ret
```

#### `glCopyTexSubImage2D_RenderPortals` — `ClientPortalManager::PortalRender`

函数范围 `0x15D88C–0x15E71F`（ELF 符号）。

```asm
   0015E6A9: 57                                              push   edi
   0015E6AA: 6A 00                                           push   0x0
   0015E6AC: 6A 00                                           push   0x0
   0015E6AE: 6A 00                                           push   0x0
   0015E6B0: 6A 00                                           push   0x0
   0015E6B2: 68 E1 0D 00 00                                  push   0xde1
=> 0015E6B7: E8 54 56 F4 FF                                  call   a3d10 <glCopyTexSubImage2D@plt>
   0015E6BC: 83 C4 18                                        add    esp,0x18
   0015E6BF: 6A 00                                           push   0x0
   0015E6C1: 68 E1 0D 00 00                                  push   0xde1
```

#### `glClear_ClipPlane` — `ClientPortalManager::PortalRender`

函数范围 `0x15D88C–0x15E71F`（ELF 符号）。

```asm
   0015E1A6: 68 00 00 80 3F                                  push   0x3f800000
   0015E1AB: 83 EC 08                                        sub    esp,0x8
   0015E1AE: D9 54 24 04                                     fst    DWORD PTR [esp+0x4]
   0015E1B2: D9 1C 24                                        fstp   DWORD PTR [esp]
   0015E1B5: E8 F6 59 F4 FF                                  call   a3bb0 <glClearColor@plt>
   0015E1BA: C7 04 24 00 40 00 00                            mov    DWORD PTR [esp],0x4000
=> 0015E1C1: E8 CA 17 F4 FF                                  call   9f990 <glClear@plt>
   0015E1C6: 83 C4 10                                        add    esp,0x10
   0015E1C9: 8B 44 24 38                                     mov    eax,DWORD PTR [esp+0x38]
   0015E1CD: FF 90 CC 00 00 00                               call   DWORD PTR [eax+0xcc]
```

## OpenGL 4.4 Core Profile 完整兼容性静态审计（2026-09-25）

### 范围、方法与结论边界

本轮覆盖上述 10257 / 8948 的 DLL、SO 四个原始二进制，并对照当前 `MetaHookSv/Plugins/Renderer` 源码。通过 PE 导入/IAT 与 IDB 引用（包括已识别的寄存器间接调用）、ELF PLT 调用、ELF 原始符号、函数反编译、调用者及 Renderer hook 安装表交叉核对。共核验 **1,022 条常规 GL 调用指令**的地址与原始字节：DLL 各 270，10257 SO 244，8948 SO 238。这个数字包括 Core 合法 API；不是需要修补的数量。GLEW/GLX 扩展解析器不计入这个数字。

IDB 只读打开、关闭时不保存；本轮没有修改二进制或 Renderer。没有启动游戏和真实 Core 上下文，因此没有运行时命中率、GL debug 日志、shader 编译日志或画面对照；不能据此宣称“完美支持”。动态函数指针及引擎回调仍需运行时追踪。这份清单是静态证据支持的修补范围，而非完整动态可达性证明。

DLL 地址继续采用首选 VA，SO 地址采用 ELF VA。以下非原始 ELF 符号的语义名称来自跨平台函数行为对应；保留起始地址作为最终定位依据。

### 对前文的更正

1. Windows `glEnable_GeneratePortalTexture` 的第二次模式命中，10257 `0x10075567` / 8948 `0x100BCBA7`，实际属于 **VRManager::GenerateTexture**（函数入口 `0x10075540` / `0x100BCB80`，语义推定）。其调用者 VRRefdef 为两眼纹理传入纹理 id 地址及宽高。前文把它命名为 ClientPortal/PortalSource::CreateTexture 不准确。
   - DLL 真正独立的门户 CreateTexture 副本在 `0x10050A90` / `0x100990F0`；其中 enable 点为 `0x10050B0A` / `0x1009916A`，未被该模式覆盖，独立副本的运行可达性未证实。
   - SO 前文 `0xF43A1` / `0x157670` 确为门户 CreateTexture；对应 VR GenerateTexture enable 为 `0x12E257` / `0x18C28A`。之前的 ② 行只是纹理创建语义相似，不能作为跨平台同一函数映射。
2. `glDisable(GL_CLIP_PLANE0..5)` 的实参数值 `0x3000..0x3005` 同时是 Core 的 `GL_CLIP_DISTANCE0..5`。它们在 Core 中**不是必然非法枚举**。真正被删除的是 `glClipPlane` 方程设置 API；遗留 enable/disable 会改动现代 clip-distance 状态，需要按 Renderer 的裁剪实现接管。参见 [Khronos Core 头文件](https://raw.githubusercontent.com/KhronosGroup/OpenGL-Registry/main/api/GL/glcorearb.h) 与 [4.4 Core 规范 §13.5](https://registry.khronos.org/OpenGL/specs/gl/glspec44.core.pdf)。
3. 发现 `glBegin`、矩阵操作或 `glNormal3f` 存在，不等于当前正常游戏路径会执行。下文把已整体替换的门户函数、没有找到调用者的副本和条件性 VR 路径分别注明。

### A. 优先修补：客户端状态入口与门户 shader 管理

**A1. client 模块级 glEnable / glDisable 拦截，补齐现有站点遗漏。**

- DLL `RenderPortals` 的 `glEnable(GL_TEXTURE_2D)`：10257 `0x1004EF74`，8948 `0x100974AC`。Renderer 的 `ClientPortalManager_RenderPortals` 在 `gl_portal.cpp:457` 继续调用原函数，此处尚未 patch。
- DLL VRRefdef 另有同样调用：10257 `0x1007577B`, `0x10075871`；8948 `0x100BCDB9`, `0x100BCEB0`。是否触发取决于立体视图配置及 FBO 条件。
- 原 clip-plane 补丁还漏掉循环尾的第二次指针加载：10257 `0x1004F099: mov esi,[0x1011A1A4]`，8948 `0x100975D3: mov esi,[0x100E5208]`。随后会执行另一组六次 `call esi`；循环进入下一次迭代还会沿用重新加载的原指针。10257 的前一次加载即使 patch 成功，也不等于整个函数覆盖成功。8948 的前一次加载本身还存在前文所述模式失配。
- 推荐 DLL hook **client 自己**的 IAT：10257 enable/disable `0x1011A208` / `0x1011A1A4`；8948 `0x100E5204` / `0x100E5208`。覆盖随后读取 IAT 的寄存器调用；在首个相关调用前安装，并核实旧指针缓存。
- SO 需要本模块 GOT/PLT 或符号绑定层的等价处理；Windows 模式不能直接使用。需处理重定位时机与动态解析出来的入口。
- 对 GL_TEXTURE_2D / GL_ALPHA_TEST / GL_FOG 等不能只靠静默吞调用就声称语义完整：纹理采样、alpha discard、fog 必须由对应 shader 路径实现。合法 depth/blend/stencil 状态继续转发。裁剪枚举应按客户端遗留路径过滤，不能把整个进程的现代 GL_CLIP_DISTANCE 调用全部吞掉。

**A2. 接管门户 InitShader / EnableShader / DisableShader。这里 GL API 名称合法，shader 内容及 program 管理却仍依赖旧管线。**

| 位置 | 10257 DLL | 10257 SO | 8948 DLL | 8948 SO |
|---|---|---|---|---|
| InitShader 函数入口 | `0x1004D640` | `0xF5B8C` | `0x10095A00` | `0x157A52` |
| AreShadersAvailable | 内联于 InitShader | `0xF5ACE` | 内联于 InitShader | `0x157996` |
| DrawPortals 函数入口 | `0x1004F140` | `0xFAE44` | `0x10097670` | `0x15C95E` |
| DrawPortals 中 use-program / reset 调用点 | `0x1004F22F` / `0x1004F326` | 需沿 helper 处理 | `0x1009775F` / `0x10097856` | EnableShader `0x157B88` / DisableShader `0x157BCE` |

四个二进制均包含门户旧 shader 字符串：vertex shader 使用 `gl_MultiTexCoord0`、`gl_ModelViewProjectionMatrix`、`gl_Vertex`；fragment shader 使用 `varying`、`texture2D`、`gl_FragColor`，均无显式现代 Core version。字符串起始文件偏移分别为 DLL 10257 `0x1276F0` / `0x127778`，DLL 8948 `0x10FFD8` / `0x110060`；SO 10257 `0x4AC5F8` / `0x4AC5E4`，SO 8948 `0x273014` / `0x273000`。

已反编译确认 Windows DrawPortals 在调用被替换的 DrawPortalSurface 前后仍执行 InitShader，并可能 `glUseProgram(clientProgram)` / `glUseProgram(0)`。InitShader 检查 shader compiler 和函数指针、创建/编译/链接旧程序，但观察到的函数体未检查 compile/link status。Core 下不能依赖旧固定管线内建输入；shader 失败及 program 切换还可能干扰 Renderer 的状态缓存。

建议在 Renderer 接管门户绘制时，同步接管客户端自己的 shader 初始化/启停及可用状态；正确清理旧资源并维护标志，不能仅把 InitShader 改成空 return 留下旧状态。若保留客户端绘制，则应替换 shader 源、顶点输入、矩阵 uniform 和 program 状态恢复，作为一套迁移。不要全局禁用 glUseProgram / glCompileShader，它们本身是 Core 合法 API。

### B. 条件性路径：保留这些功能时需要迁移

**B1. CSurfaceHandler 的 glNormal3f（四个二进制均有，两处/文件）。**

| 函数 | 10257 DLL call | 10257 SO call | 8948 DLL call | 8948 SO call |
|---|---|---|---|---|
| FMOD_InitializeScene | `0x10044995` | `0xEB97B` | `0x1008C9F5` | `0x14E614` |
| DrawKnownSurfaces | `0x10044AE9` | `0xEB5B0` | `0x1008CB49` | `0x14E328` |

这些函数没有现有 Renderer hook，glNormal3f 也没有对应 wrapper。DrawKnownSurfaces 用 engine TriangleAPI 绘制已知表面，glNormal3f 则直接调用 GL。静态引用中未找到普通代码调用者，Linux 有保留符号；不能据此断言正常游戏必经，也不能证明绝对不可达。

若渲染路径确定是无光照绘制，法线可以由专用 wrapper 忽略；若法线参与效果，应写入 Renderer 顶点属性并在 shader 消费。不要未经验证就把“清除 API 错误”当成功能等价。

**B2. Linux VRManager::DrawVR 的完整 fixed-function 绘制。**

- 函数入口：10257 SO `0x12E35E`；8948 SO `0x18C732`。
- glBegin(GL_POLYGON)：10257 `0x12E4B4`, `0x12E5D6`；8948 `0x18C876`, `0x18C93A`。
- 同函数还含 `glMatrixMode`, `glPushMatrix`, `glLoadIdentity`, `glOrtho`, `glPopMatrix`, `glColor4f`, `glTexCoord2f`, `glVertex3f`, `glEnd`，以及 GL_ALPHA_TEST 的 enable/disable 语义。
- 8948 `P_DrawVR` @ `0x18CA86` 的 `0x18CA9C` 调用 DrawVR；DrawVR 自身检查待绘制标志和 `CancelVRDueToEngineFBOBeingSet`。尚未证明 P_DrawVR 在当前引擎运行中被调用；如果非零 FBO 使 VR 被取消，也不能因此声称 VR 已兼容。
- 建议整体 hook DrawVR，使用 Renderer 2D shader、显式正交矩阵和 VAO/VBO/EBO 绘制两眼四边形（三角形化），恢复 FBO/program/viewport/depth/blend/texture 等状态。Core 不提供旧矩阵栈，不能把 MatrixMode/Ortho 简单 NOP，也不能将 GL_POLYGON 原样交给 Core draw API。
- Windows 有 VRRefdef 及纹理创建/拷贝路径；本次常规导入调用扫描没有发现独立于门户 DrawTest 的同款双眼 glBegin 函数，不能直接套用 SO 的函数映射。若要完整 Windows VR 支持，还需从输出入口追踪其绘制实现。
- VRRefdef 的 glCopyTexSubImage2D 本身合法，但在 Renderer FBO 管线下需确定正确 read framebuffer、尺寸与 MSAA resolve；不能套用“清空当前 portal 指针”的 portal 专用替换函数。

**B3. DrawTest 及门户独立 helper。**

DrawTest：10257 DLL `0x10052BC0`、SO `0xF6E8A`；8948 DLL `0x1009B240`、SO `0x158576`。含完整矩阵栈/立即模式，未找到普通代码调用者，列为潜在诊断功能覆盖项。

DrawMonitor / DrawStencil / DrawPortalOrMirrorImageWhereStencilIsOne / DrawDepth / DrawOverlay 的调用点详见下方完整清单。DLL 主要绘制代码已内联在被整体替换的 DrawPortalSurface；DLL 的独立 `DrawPortalOrMirrorImageWhereStencilIsOne` 仅发现该原函数调用。8948 SO 这些 helper 则由 DrawPortalSurface @ `0x15ACEA` 调用。移植到 SO 时如保留同样的整体替换策略，通常无需逐条模拟这一批旧 API；若其他路径调用这些 helper，则需一并处理。

### C. 已有覆盖与不应误报的项目

- **ParticleDraw**：已有 DLL glBegin/glEnd/glColor4f 站点补丁；顶点/纹理坐标通过共享 engine TriangleAPI 表进入 Renderer，表在 `gl_hooks.cpp:1136` 起替换。SO 需要等价移植，不能假定已有 Windows patch 生效。粒子 begin/end 必须成对，颜色与顶点状态须同步；`CoreProfile_glBegin` 是空函数，不能拿它替代有实际绘制需求的 begin，应使用正确的 triapi/绘制桥接。
- **glClipPlane + glLoadIdentity**：落在 EnableClipPlane，当前 DLL 函数由 `gl_portal.cpp:463` 整体替换为记录门户裁剪平面；旧函数不被转发。SO 需相同功能 hook。
- **glFogf/glFogi/glFogfv/glHint(GL_FOG_HINT)**：位于 V_CalcNormalRefdef；`exportfuncs.cpp:97` 起暂时清零客户端雾距离，调用原 V_CalcRefdef 后恢复，另由 Renderer shader 实现雾。这个机制成功时旧分支不执行。验证水下/非水下及各雾距离边界；如果无法保证压制，则需迁移 fog 状态而非只吞 glEnable(GL_FOG)。
- **glGetIntegerv / glGetBooleanv**：观察到的是 GL_ACTIVE_TEXTURE、GL_MAX_TEXTURE_SIZE、GL_DRAW/READ_FRAMEBUFFER_BINDING、GL_NUM_EXTENSIONS、GL_SHADER_COMPILER 等有效查询。当前常规调用清单未发现 legacy matrix 查询；不能在没有二进制证据时要求 blanket hook glGetFloatv/GetIntegerv。
- **glTexParameteri / glTexImage2D**：已收集点使用 MIN/MAG_FILTER + NEAREST/LINEAR，RGBA 格式与零 border。未发现这些点传 GL_CLAMP、LUMINANCE、ALPHA 或数字 3/4 internalformat。它们目前不是已证实的 legacy 参数遗漏。
- **GLEW 的 glGetString(GL_EXTENSIONS)**：DLL 中确有旧分支，但 10257 已反编译证明 GL>=3.0 时走 NUM_EXTENSIONS + 动态 glGetStringi；不能仅因为存在旧分支就判定 4.4 会执行它，更不能盲目返回空串破坏扩展探测。8948 同类路径和 SO 自带 loader 仍应在首次初始化、视频重初始化时运行跟踪。
- **glClear / glCopyTexSubImage2D**：Core 合法。原有 portal 专用 patch 是为了 FBO 渲染流程和状态，不是因为 API 被废弃。
- 未在本次已识别调用清单中发现 glNewList/glCallList、glVertexPointer/glEnableClientState、glTexGen 等实际常规调用。GLEW 中大量这些名字只表示解析能力；字符串/指针赋值不等于业务执行。未完全解析的动态调用不在此排除结论内。

### D. API 之外影响“完整支持”的现有问题

- `gl_portal.cpp:178` 起的 ClientPortal_GetTextureId/Width/Height 只处理 build>=10000，8948 返回 -1；portal FBO 管线因此还需适配旧布局。
- `gl_portal.cpp:124` 的 ClientPortal_GetIndex 把 vector begin/end 都读自 +140，循环不会遍历；需按版本/平台正确取两个字段。这是源码直接可见的问题，不属于 legacy GL API。
- `R_RedirectSCClientLegacyOpenGLCall_*` 对模式零命中通常静默结束，没有预期数量校验。需要按版本校验数量、记录实际函数/地址，并在不完整覆盖时明确报错；否则客户端更新后易出现部分 hook 成功的状态。

### E. 实施顺序与验收

1. DLL 建立 client 自己的 enable/disable IAT 拦截，SO 建立对应入口拦截；检查 hook 时机、缓存指针及 GLEW 重初始化。保留现有粒子、portal/FBO 等专用补丁。
2. 接管客户端门户 shader 初始化和 program 启停，修正 8948 字段布局、函数定位和模式命中校验。
3. SO 移植 DrawPortalSurface/EnableClipPlane、粒子、fog 与 portal FBO 的整个流程；需要保留 VR/DrawTest 时迁移其矩阵和绘制，不依靠禁用功能通过验收。
4. 按动态命中结果处理 glNormal3f 及其他残余入口。对未识别函数指针记录来源、目标、调用方模块偏移和参数。
5. 在真正的 4.4 Core debug context 中验证 profile mask/version；记录调试回调、shader compile/link status、FBO 完整性及关键 program/VAO 状态。仅 glGetError 为零不足以证明画面正确，未进入的分支也不算通过。
6. 覆盖首次进入地图/切图/重启视频、门户/镜子/监视器、粒子透明模式、雾和水下、分辨率切换、启用立体视图、可触发的诊断绘制；与 Compatibility 原版场景截图及状态轨迹对照。需在两版 DLL/SO 各自的运行环境验证。

Core API 移除范围依据 [OpenGL 4.4 Core 规范附录 D.2](https://registry.khronos.org/OpenGL/specs/gl/glspec44.core.pdf)。下面清单列出所有已识别的被移除 API 调用，以及 enable/disable；地址存在本身不代表必须单独 patch，结合上文函数覆盖解释使用。

### 10257-dll：legacy API 与状态调用完整定位表

| 所属函数（入口） | API | call VA |
|---|---|---|
| `CSurfaceHandler::FMOD_InitializeScene` @ `0x100448C0` | `glNormal3f` | `0x10044995` |
| `CSurfaceHandler::DrawKnownSurfaces` @ `0x10044A00` | `glNormal3f` | `0x10044AE9` |
| `CParticleEngine::EngineThink` @ `0x10045C50` | `glTexEnvf` | `0x10045C6E` |
| `CParticleSystem::ParticleDraw` @ `0x10049AC0` | `glBegin` | `0x10049D75` |
| `CParticleSystem::ParticleDraw` @ `0x10049AC0` | `glColor4f` | `0x10049ED7` |
| `CParticleSystem::ParticleDraw` @ `0x10049AC0` | `glDisable` | `0x10049D2E` |
| `CParticleSystem::ParticleDraw` @ `0x10049AC0` | `glEnable` | `0x1004A166` |
| `CParticleSystem::ParticleDraw` @ `0x10049AC0` | `glEnd` | `0x1004A14F` |
| `ClientPortalManager::CreateInvisiblePortalTextures / GenerateInvisibleTexture` @ `0x1004C900` | `glEnable` | `0x1004C986` |
| `ClientPortalManager::RenderPortals / PortalRender` @ `0x1004E4F0` | `glDisable` | `0x1004EC9F`, `0x1004ECA6`, `0x1004ECAD`, `0x1004ECB4`, `0x1004ECBB`, `0x1004ECC2`, `0x1004F0BA`, `0x1004F0C1`, `0x1004F0C8`, `0x1004F0CF`, `0x1004F0D6`, `0x1004F0DD` |
| `ClientPortalManager::RenderPortals / PortalRender` @ `0x1004E4F0` | `glEnable` | `0x1004EA52`, `0x1004EF74` |
| `ClientPortalManager::DrawPortals` @ `0x1004F140` | `glColor4f` | `0x1004F1F4` |
| `ClientPortalManager::DrawPortals` @ `0x1004F140` | `glDisable` | `0x1004F1FF` |
| `ClientPortalManager::DrawPortalSurface` @ `0x1004F360` | `glAlphaFunc` | `0x1004F81E` |
| `ClientPortalManager::DrawPortalSurface` @ `0x1004F360` | `glBegin` | `0x1004F39E`, `0x1004F557`, `0x1004F6D5`, `0x1004F832` |
| `ClientPortalManager::DrawPortalSurface` @ `0x1004F360` | `glColor4f` | `0x1004F539` |
| `ClientPortalManager::DrawPortalSurface` @ `0x1004F360` | `glDisable` | `0x1004F387`, `0x1004F4DA`, `0x1004F658`, `0x1004F6A2`, `0x1004F7BB`, `0x1004F946` |
| `ClientPortalManager::DrawPortalSurface` @ `0x1004F360` | `glEnable` | `0x1004F4E5`, `0x1004F663`, `0x1004F6AD`, `0x1004F7D4`, `0x1004F80B` |
| `ClientPortalManager::DrawPortalSurface` @ `0x1004F360` | `glEnd` | `0x1004F4B0`, `0x1004F64D`, `0x1004F7B0`, `0x1004F92E` |
| `ClientPortalManager::DrawPortalSurface` @ `0x1004F360` | `glTexCoord2f` | `0x1004F401`, `0x1004F88A` |
| `ClientPortalManager::DrawPortalSurface` @ `0x1004F360` | `glVertex3fv` | `0x1004F480`, `0x1004F610`, `0x1004F784`, `0x1004F909` |
| `ClientPortalManager::EnableClipPlane` @ `0x1004F960` | `glClipPlane` | `0x1004FC47` |
| `ClientPortalManager::EnableClipPlane` @ `0x1004F960` | `glEnable` | `0x1004FC4E` |
| `ClientPortalManager::EnableClipPlane` @ `0x1004F960` | `glLoadIdentity` | `0x1004FC31` |
| `ClientPortal / PortalSource::CreateTexture（DLL 独立副本）` @ `0x10050A90` | `glEnable` | `0x10050B0A` |
| `ClientPortalManager::DisableClipPlanes` @ `0x10050BC0` | `glDisable` | `0x10050C5D`, `0x10050C64`, `0x10050C6B`, `0x10050C72`, `0x10050C79`, `0x10050C80` |
| `DrawMonitor` @ `0x100523E0` | `glBegin` | `0x100523FF` |
| `DrawMonitor` @ `0x100523E0` | `glDisable` | `0x100523E8` |
| `DrawMonitor` @ `0x100523E0` | `glEnd` | `0x10052505` |
| `DrawMonitor` @ `0x100523E0` | `glTexCoord2f` | `0x10052461` |
| `DrawMonitor` @ `0x100523E0` | `glVertex3fv` | `0x100524E1` |
| `DrawStencil` @ `0x10052520` | `glBegin` | `0x100525B4` |
| `DrawStencil` @ `0x10052520` | `glColor4f` | `0x10052596` |
| `DrawStencil` @ `0x10052520` | `glDisable` | `0x10052537`, `0x10052679` |
| `DrawStencil` @ `0x10052520` | `glEnable` | `0x10052542`, `0x10052684` |
| `DrawStencil` @ `0x10052520` | `glEnd` | `0x1005266E` |
| `DrawStencil` @ `0x10052520` | `glVertex3fv` | `0x10052653` |
| `DrawPortalOrMirrorImageWhereStencilIsOne` @ `0x100526B0` | `glAlphaFunc` | `0x1005272C` |
| `DrawPortalOrMirrorImageWhereStencilIsOne` @ `0x100526B0` | `glBegin` | `0x10052767` |
| `DrawPortalOrMirrorImageWhereStencilIsOne` @ `0x100526B0` | `glDisable` | `0x10052737`, `0x10052907`, `0x1005290E` |
| `DrawPortalOrMirrorImageWhereStencilIsOne` @ `0x100526B0` | `glEnable` | `0x1005271D`, `0x10052742`, `0x10052915` |
| `DrawPortalOrMirrorImageWhereStencilIsOne` @ `0x100526B0` | `glEnd` | `0x100528E9` |
| `DrawPortalOrMirrorImageWhereStencilIsOne` @ `0x100526B0` | `glLoadIdentity` | `0x100526CE`, `0x100526D9` |
| `DrawPortalOrMirrorImageWhereStencilIsOne` @ `0x100526B0` | `glMatrixMode` | `0x100526BE`, `0x100526D5`, `0x10052928`, `0x10052937` |
| `DrawPortalOrMirrorImageWhereStencilIsOne` @ `0x100526B0` | `glOrtho` | `0x10052704` |
| `DrawPortalOrMirrorImageWhereStencilIsOne` @ `0x100526B0` | `glPopMatrix` | `0x10052930`, `0x10052939` |
| `DrawPortalOrMirrorImageWhereStencilIsOne` @ `0x100526B0` | `glPushMatrix` | `0x100526C6`, `0x100526D7` |
| `DrawPortalOrMirrorImageWhereStencilIsOne` @ `0x100526B0` | `glTexCoord2f` | `0x10052793`, `0x100527C9`, `0x100527F9`, `0x10052835`, `0x1005286B`, `0x1005289B`, `0x100528CB` |
| `DrawPortalOrMirrorImageWhereStencilIsOne` @ `0x100526B0` | `glVertex3f` | `0x100527B5`, `0x100527E5`, `0x10052815`, `0x10052857`, `0x10052887`, `0x100528B7`, `0x100528E7` |
| `DrawDepth` @ `0x10052940` | `glBegin` | `0x1005298A` |
| `DrawDepth` @ `0x10052940` | `glDisable` | `0x10052957`, `0x10052A56` |
| `DrawDepth` @ `0x10052940` | `glEnable` | `0x10052962`, `0x10052A6F` |
| `DrawDepth` @ `0x10052940` | `glEnd` | `0x10052A4B` |
| `DrawDepth` @ `0x10052940` | `glVertex3fv` | `0x10052A30` |
| `DrawOverlay` @ `0x10052A80` | `glAlphaFunc` | `0x10052A9D` |
| `DrawOverlay` @ `0x10052A80` | `glBegin` | `0x10052AB4` |
| `DrawOverlay` @ `0x10052A80` | `glDisable` | `0x10052BA6` |
| `DrawOverlay` @ `0x10052A80` | `glEnable` | `0x10052A8A` |
| `DrawOverlay` @ `0x10052A80` | `glEnd` | `0x10052B8E` |
| `DrawOverlay` @ `0x10052A80` | `glTexCoord2f` | `0x10052AFA` |
| `DrawOverlay` @ `0x10052A80` | `glVertex3fv` | `0x10052B76` |
| `DrawTest` @ `0x10052BC0` | `glBegin` | `0x10052C76` |
| `DrawTest` @ `0x10052BC0` | `glColor4f` | `0x10052C6E` |
| `DrawTest` @ `0x10052BC0` | `glDisable` | `0x10052C2D`, `0x10052C34`, `0x10052C3B`, `0x10052D53`, `0x10052D5A` |
| `DrawTest` @ `0x10052BC0` | `glEnable` | `0x10052D61` |
| `DrawTest` @ `0x10052BC0` | `glEnd` | `0x10052D48` |
| `DrawTest` @ `0x10052BC0` | `glLoadIdentity` | `0x10052BDE`, `0x10052BE9` |
| `DrawTest` @ `0x10052BC0` | `glMatrixMode` | `0x10052BCE`, `0x10052BE5`, `0x10052D7A`, `0x10052D89` |
| `DrawTest` @ `0x10052BC0` | `glOrtho` | `0x10052C14` |
| `DrawTest` @ `0x10052BC0` | `glPopMatrix` | `0x10052D82`, `0x10052D8B` |
| `DrawTest` @ `0x10052BC0` | `glPushMatrix` | `0x10052BD6`, `0x10052BE7` |
| `DrawTest` @ `0x10052BC0` | `glTexCoord2f` | `0x10052C94`, `0x10052CCA`, `0x10052CFA`, `0x10052D2A` |
| `DrawTest` @ `0x10052BC0` | `glVertex3f` | `0x10052CB6`, `0x10052CE6`, `0x10052D16`, `0x10052D46` |
| `HUD_DrawTransparentTriangles` @ `0x1005BB10` | `glDisable` | `0x1005BB15` |
| `V_CalcNormalRefdef` @ `0x100735E0` | `glEnable` | `0x1007531D` |
| `V_CalcNormalRefdef` @ `0x100735E0` | `glFogf` | `0x10075301`, `0x10075316` |
| `V_CalcNormalRefdef` @ `0x100735E0` | `glFogfv` | `0x100752D2` |
| `V_CalcNormalRefdef` @ `0x100735E0` | `glFogi` | `0x1007527C` |
| `V_CalcNormalRefdef` @ `0x100735E0` | `glHint` | `0x100752E2` |
| `VRManager::GenerateTexture` @ `0x10075540` | `glEnable` | `0x10075567` |
| `VRManager::VRRefdef` @ `0x100755E0` | `glEnable` | `0x1007577B`, `0x10075871` |

### 10257-so：legacy API 与状态调用完整定位表

| 所属函数（入口） | API | call VA |
|---|---|---|
| `CSurfaceHandler::DrawKnownSurfaces` @ `0xEB474` | `glNormal3f` | `0xEB5B0` |
| `CSurfaceHandler::FMOD_InitializeScene` @ `0xEB870` | `glNormal3f` | `0xEB97B` |
| `CParticleEngine::EngineThink` @ `0xECEFC` | `glTexEnvf` | `0xECF34` |
| `CParticleSystem::ParticleDraw` @ `0xF39C2` | `glBegin` | `0xF3BB7` |
| `CParticleSystem::ParticleDraw` @ `0xF39C2` | `glColor4f` | `0xF3C13` |
| `CParticleSystem::ParticleDraw` @ `0xF39C2` | `glDisable` | `0xF3F4B` |
| `CParticleSystem::ParticleDraw` @ `0xF39C2` | `glEnable` | `0xF3E80` |
| `CParticleSystem::ParticleDraw` @ `0xF39C2` | `glEnd` | `0xF3E67` |
| `ClientPortal / PortalSource::CreateTexture（DLL 独立副本）` @ `0xF42F8` | `glEnable` | `0xF43A1` |
| `DrawMonitor` @ `0xF64C2` | `glBegin` | `0xF64FF` |
| `DrawMonitor` @ `0xF64C2` | `glDisable` | `0xF64DF` |
| `DrawMonitor` @ `0xF64C2` | `glEnd` | `0xF6610` |
| `DrawMonitor` @ `0xF64C2` | `glTexCoord2f` | `0xF6568` |
| `DrawMonitor` @ `0xF64C2` | `glVertex3fv` | `0xF65F4` |
| `DrawStencil` @ `0xF6632` | `glBegin` | `0xF6705` |
| `DrawStencil` @ `0xF6632` | `glColor4f` | `0xF66C9` |
| `DrawStencil` @ `0xF6632` | `glDisable` | `0xF6663`, `0xF67E6` |
| `DrawStencil` @ `0xF6632` | `glEnable` | `0xF666F`, `0xF67F2` |
| `DrawStencil` @ `0xF6632` | `glEnd` | `0xF67DA` |
| `DrawStencil` @ `0xF6632` | `glVertex3fv` | `0xF67BD` |
| `DrawPortalOrMirrorImageWhereStencilIsOne` @ `0xF6830` | `glAlphaFunc` | `0xF68CA` |
| `DrawPortalOrMirrorImageWhereStencilIsOne` @ `0xF6830` | `glBegin` | `0xF691E` |
| `DrawPortalOrMirrorImageWhereStencilIsOne` @ `0xF6830` | `glDisable` | `0xF68D6`, `0xF6A2A`, `0xF6A36` |
| `DrawPortalOrMirrorImageWhereStencilIsOne` @ `0xF6830` | `glEnable` | `0xF68B6`, `0xF68E2`, `0xF6A42` |
| `DrawPortalOrMirrorImageWhereStencilIsOne` @ `0xF6830` | `glEnd` | `0xF6A0A` |
| `DrawPortalOrMirrorImageWhereStencilIsOne` @ `0xF6830` | `glLoadIdentity` | `0xF6850`, `0xF6866` |
| `DrawPortalOrMirrorImageWhereStencilIsOne` @ `0xF6830` | `glMatrixMode` | `0xF6846`, `0xF685C`, `0xF6A5A`, `0xF6A6B` |
| `DrawPortalOrMirrorImageWhereStencilIsOne` @ `0xF6830` | `glOrtho` | `0xF689E` |
| `DrawPortalOrMirrorImageWhereStencilIsOne` @ `0xF6830` | `glPopMatrix` | `0xF6A5F`, `0xF6A70` |
| `DrawPortalOrMirrorImageWhereStencilIsOne` @ `0xF6830` | `glPushMatrix` | `0xF684B`, `0xF6861` |
| `DrawPortalOrMirrorImageWhereStencilIsOne` @ `0xF6830` | `glTexCoord2f` | `0xF6941`, `0xF697D`, `0xF69B1`, `0xF69E5`, `0xF6A81`, `0xF6ABD`, `0xF6AF1`, `0xF6B25` |
| `DrawPortalOrMirrorImageWhereStencilIsOne` @ `0xF6830` | `glVertex3f` | `0xF6969`, `0xF699D`, `0xF69D1`, `0xF6A05`, `0xF6AA9`, `0xF6ADD`, `0xF6B11`, `0xF6B45` |
| `DrawDepth` @ `0xF6B50` | `glBegin` | `0xF6BD9` |
| `DrawDepth` @ `0xF6B50` | `glDisable` | `0xF6B81`, `0xF6CBA` |
| `DrawDepth` @ `0xF6B50` | `glEnable` | `0xF6B8D`, `0xF6CEA` |
| `DrawDepth` @ `0xF6B50` | `glEnd` | `0xF6CAE` |
| `DrawDepth` @ `0xF6B50` | `glVertex3fv` | `0xF6C91` |
| `DrawOverlay` @ `0xF6CF8` | `glAlphaFunc` | `0xF6D29` |
| `DrawOverlay` @ `0xF6CF8` | `glBegin` | `0xF6D49` |
| `DrawOverlay` @ `0xF6CF8` | `glDisable` | `0xF6E7C` |
| `DrawOverlay` @ `0xF6CF8` | `glEnable` | `0xF6D15` |
| `DrawOverlay` @ `0xF6CF8` | `glEnd` | `0xF6E5C` |
| `DrawOverlay` @ `0xF6CF8` | `glTexCoord2f` | `0xF6DB4` |
| `DrawOverlay` @ `0xF6CF8` | `glVertex3fv` | `0xF6E40` |
| `DrawTest` @ `0xF6E8A` | `glBegin` | `0xF6F6C` |
| `DrawTest` @ `0xF6E8A` | `glColor4f` | `0xF6F60` |
| `DrawTest` @ `0xF6E8A` | `glDisable` | `0xF6F10`, `0xF6F1C`, `0xF6F28`, `0xF707D`, `0xF7089` |
| `DrawTest` @ `0xF6E8A` | `glEnable` | `0xF7095` |
| `DrawTest` @ `0xF6E8A` | `glEnd` | `0xF7071` |
| `DrawTest` @ `0xF6E8A` | `glLoadIdentity` | `0xF6EAA`, `0xF6EC0` |
| `DrawTest` @ `0xF6E8A` | `glMatrixMode` | `0xF6EA0`, `0xF6EB6`, `0xF70AD`, `0xF70BE` |
| `DrawTest` @ `0xF6E8A` | `glOrtho` | `0xF6EF8` |
| `DrawTest` @ `0xF6E8A` | `glPopMatrix` | `0xF70B2`, `0xF70C3` |
| `DrawTest` @ `0xF6E8A` | `glPushMatrix` | `0xF6EA5`, `0xF6EBB` |
| `DrawTest` @ `0xF6E8A` | `glTexCoord2f` | `0xF6F80`, `0xF6FD8`, `0xF700E`, `0xF704A` |
| `DrawTest` @ `0xF6E8A` | `glVertex3f` | `0xF6FC4`, `0xF6FFA`, `0xF7036`, `0xF706C` |
| `ClientPortalManager::CreateInvisiblePortalTextures / GenerateInvisibleTexture` @ `0xF70CE` | `glEnable` | `0xF718F` |
| `ClientPortalManager::EnableClipPlane` @ `0xF7684` | `glClipPlane` | `0xF7832` |
| `ClientPortalManager::EnableClipPlane` @ `0xF7684` | `glEnable` | `0xF783A` |
| `ClientPortalManager::EnableClipPlane` @ `0xF7684` | `glLoadIdentity` | `0xF7815` |
| `ClientPortalManager::DisableClipPlanes` @ `0xF7846` | `glDisable` | `0xF785C`, `0xF7868`, `0xF7874`, `0xF7880`, `0xF788C`, `0xF7898` |
| `ClientPortalManager::DrawPortals` @ `0xFAE44` | `glColor4f` | `0xFAF57` |
| `ClientPortalManager::DrawPortals` @ `0xFAE44` | `glDisable` | `0xFAF63` |
| `ClientPortalManager::RenderPortals / PortalRender` @ `0xFC2B4` | `glEnable` | `0xFD193` |
| `HUD_DrawTransparentTriangles` @ `0x107140` | `glDisable` | `0x10715B` |
| `V_CalcNormalRefdef` @ `0x12C2AE` | `glEnable` | `0x12CE46` |
| `V_CalcNormalRefdef` @ `0x12C2AE` | `glFogf` | `0x12CE24`, `0x12CE3A` |
| `V_CalcNormalRefdef` @ `0x12C2AE` | `glFogfv` | `0x12CDF9` |
| `V_CalcNormalRefdef` @ `0x12C2AE` | `glFogi` | `0x12CDB4` |
| `V_CalcNormalRefdef` @ `0x12C2AE` | `glHint` | `0x12CE0D` |
| `VRManager::GenerateTexture` @ `0x12E210` | `glEnable` | `0x12E257` |
| `VRManager::DrawVR` @ `0x12E35E` | `glBegin` | `0x12E4B4`, `0x12E5D6` |
| `VRManager::DrawVR` @ `0x12E35E` | `glColor4f` | `0x12E3F5` |
| `VRManager::DrawVR` @ `0x12E35E` | `glDisable` | `0x12E401`, `0x12E47D`, `0x12E489`, `0x12E495`, `0x12E6D3`, `0x12E6DF` |
| `VRManager::DrawVR` @ `0x12E35E` | `glEnable` | `0x12E6EB` |
| `VRManager::DrawVR` @ `0x12E35E` | `glEnd` | `0x12E5A3`, `0x12E6B3` |
| `VRManager::DrawVR` @ `0x12E35E` | `glLoadIdentity` | `0x12E417`, `0x12E42D` |
| `VRManager::DrawVR` @ `0x12E35E` | `glMatrixMode` | `0x12E40D`, `0x12E423`, `0x12E703`, `0x12E714` |
| `VRManager::DrawVR` @ `0x12E35E` | `glOrtho` | `0x12E465` |
| `VRManager::DrawVR` @ `0x12E35E` | `glPopMatrix` | `0x12E708`, `0x12E719` |
| `VRManager::DrawVR` @ `0x12E35E` | `glPushMatrix` | `0x12E412`, `0x12E428` |
| `VRManager::DrawVR` @ `0x12E35E` | `glTexCoord2f` | `0x12E4C8`, `0x12E504`, `0x12E538`, `0x12E57A`, `0x12E5EA`, `0x12E622`, `0x12E65A`, `0x12E68E` |
| `VRManager::DrawVR` @ `0x12E35E` | `glVertex3f` | `0x12E4F0`, `0x12E524`, `0x12E566`, `0x12E59E`, `0x12E60E`, `0x12E646`, `0x12E67A`, `0x12E6AE` |
| `sub_12E764` @ `0x12E764` | `glEnable` | `0x12E9BD`, `0x12EA74` |

### 8948-dll：legacy API 与状态调用完整定位表

| 所属函数（入口） | API | call VA |
|---|---|---|
| `CSurfaceHandler::FMOD_InitializeScene` @ `0x1008C920` | `glNormal3f` | `0x1008C9F5` |
| `CSurfaceHandler::DrawKnownSurfaces` @ `0x1008CA60` | `glNormal3f` | `0x1008CB49` |
| `CParticleEngine::EngineThink` @ `0x1008DC80` | `glTexEnvf` | `0x1008DC9E` |
| `CParticleSystem::ParticleDraw` @ `0x10091DF0` | `glBegin` | `0x100920A8` |
| `CParticleSystem::ParticleDraw` @ `0x10091DF0` | `glColor4f` | `0x1009220A` |
| `CParticleSystem::ParticleDraw` @ `0x10091DF0` | `glDisable` | `0x1009205B` |
| `CParticleSystem::ParticleDraw` @ `0x10091DF0` | `glEnable` | `0x10092499` |
| `CParticleSystem::ParticleDraw` @ `0x10091DF0` | `glEnd` | `0x10092482` |
| `ClientPortalManager::CreateInvisiblePortalTextures / GenerateInvisibleTexture` @ `0x10094B10` | `glEnable` | `0x10094B96` |
| `ClientPortalManager::RenderPortals / PortalRender` @ `0x100969F0` | `glDisable` | `0x100971DF`, `0x100971E6`, `0x100971ED`, `0x100971F4`, `0x100971FB`, `0x10097202`, `0x100975EE`, `0x100975F5`, `0x100975FC`, `0x10097603`, `0x1009760A`, `0x10097611` |
| `ClientPortalManager::RenderPortals / PortalRender` @ `0x100969F0` | `glEnable` | `0x10096FA8`, `0x100974AC` |
| `ClientPortalManager::DrawPortals` @ `0x10097670` | `glColor4f` | `0x10097724` |
| `ClientPortalManager::DrawPortals` @ `0x10097670` | `glDisable` | `0x1009772F` |
| `ClientPortalManager::DrawPortalSurface` @ `0x10097890` | `glAlphaFunc` | `0x10097D48` |
| `ClientPortalManager::DrawPortalSurface` @ `0x10097890` | `glBegin` | `0x100978C7`, `0x10097A85`, `0x10097BF2`, `0x10097D5C` |
| `ClientPortalManager::DrawPortalSurface` @ `0x10097890` | `glColor4f` | `0x10097A67` |
| `ClientPortalManager::DrawPortalSurface` @ `0x10097890` | `glDisable` | `0x100978B0`, `0x10097A08`, `0x10097B78`, `0x10097BBF`, `0x10097CE8`, `0x10097E8B` |
| `ClientPortalManager::DrawPortalSurface` @ `0x10097890` | `glEnable` | `0x10097A13`, `0x10097B83`, `0x10097BCA`, `0x10097D01`, `0x10097D35` |
| `ClientPortalManager::DrawPortalSurface` @ `0x10097890` | `glEnd` | `0x100979DE`, `0x10097B6D`, `0x10097CDD`, `0x10097E73` |
| `ClientPortalManager::DrawPortalSurface` @ `0x10097890` | `glTexCoord2f` | `0x10097924`, `0x10097DBD` |
| `ClientPortalManager::DrawPortalSurface` @ `0x10097890` | `glVertex3fv` | `0x100979B4`, `0x10097B43`, `0x10097CB3`, `0x10097E4D` |
| `ClientPortalManager::EnableClipPlane` @ `0x10097EA0` | `glClipPlane` | `0x10098187` |
| `ClientPortalManager::EnableClipPlane` @ `0x10097EA0` | `glEnable` | `0x1009818E` |
| `ClientPortalManager::EnableClipPlane` @ `0x10097EA0` | `glLoadIdentity` | `0x10098171` |
| `ClientPortal / PortalSource::CreateTexture（DLL 独立副本）` @ `0x100990F0` | `glEnable` | `0x1009916A` |
| `ClientPortalManager::DisableClipPlanes` @ `0x10099220` | `glDisable` | `0x100992BD`, `0x100992C4`, `0x100992CB`, `0x100992D2`, `0x100992D9`, `0x100992E0` |
| `DrawMonitor` @ `0x1009AA10` | `glBegin` | `0x1009AA30` |
| `DrawMonitor` @ `0x1009AA10` | `glDisable` | `0x1009AA19` |
| `DrawMonitor` @ `0x1009AA10` | `glEnd` | `0x1009AB47` |
| `DrawMonitor` @ `0x1009AA10` | `glTexCoord2f` | `0x1009AA94` |
| `DrawMonitor` @ `0x1009AA10` | `glVertex3fv` | `0x1009AB24` |
| `DrawStencil` @ `0x1009AB60` | `glBegin` | `0x1009ABF4` |
| `DrawStencil` @ `0x1009AB60` | `glColor4f` | `0x1009ABD6` |
| `DrawStencil` @ `0x1009AB60` | `glDisable` | `0x1009AB77`, `0x1009ACCA` |
| `DrawStencil` @ `0x1009AB60` | `glEnable` | `0x1009AB82`, `0x1009ACD5` |
| `DrawStencil` @ `0x1009AB60` | `glEnd` | `0x1009ACBF` |
| `DrawStencil` @ `0x1009AB60` | `glVertex3fv` | `0x1009ACA7` |
| `DrawPortalOrMirrorImageWhereStencilIsOne` @ `0x1009AD00` | `glAlphaFunc` | `0x1009AD7C` |
| `DrawPortalOrMirrorImageWhereStencilIsOne` @ `0x1009AD00` | `glBegin` | `0x1009ADB7` |
| `DrawPortalOrMirrorImageWhereStencilIsOne` @ `0x1009AD00` | `glDisable` | `0x1009AD87`, `0x1009AF57`, `0x1009AF5E` |
| `DrawPortalOrMirrorImageWhereStencilIsOne` @ `0x1009AD00` | `glEnable` | `0x1009AD6D`, `0x1009AD92`, `0x1009AF65` |
| `DrawPortalOrMirrorImageWhereStencilIsOne` @ `0x1009AD00` | `glEnd` | `0x1009AF39` |
| `DrawPortalOrMirrorImageWhereStencilIsOne` @ `0x1009AD00` | `glLoadIdentity` | `0x1009AD1E`, `0x1009AD29` |
| `DrawPortalOrMirrorImageWhereStencilIsOne` @ `0x1009AD00` | `glMatrixMode` | `0x1009AD0E`, `0x1009AD25`, `0x1009AF78`, `0x1009AF87` |
| `DrawPortalOrMirrorImageWhereStencilIsOne` @ `0x1009AD00` | `glOrtho` | `0x1009AD54` |
| `DrawPortalOrMirrorImageWhereStencilIsOne` @ `0x1009AD00` | `glPopMatrix` | `0x1009AF80`, `0x1009AF89` |
| `DrawPortalOrMirrorImageWhereStencilIsOne` @ `0x1009AD00` | `glPushMatrix` | `0x1009AD16`, `0x1009AD27` |
| `DrawPortalOrMirrorImageWhereStencilIsOne` @ `0x1009AD00` | `glTexCoord2f` | `0x1009ADE3`, `0x1009AE19`, `0x1009AE49`, `0x1009AE85`, `0x1009AEBB`, `0x1009AEEB`, `0x1009AF1B` |
| `DrawPortalOrMirrorImageWhereStencilIsOne` @ `0x1009AD00` | `glVertex3f` | `0x1009AE05`, `0x1009AE35`, `0x1009AE65`, `0x1009AEA7`, `0x1009AED7`, `0x1009AF07`, `0x1009AF37` |
| `DrawDepth` @ `0x1009AF90` | `glBegin` | `0x1009AFDA` |
| `DrawDepth` @ `0x1009AF90` | `glDisable` | `0x1009AFA7`, `0x1009B0AC` |
| `DrawDepth` @ `0x1009AF90` | `glEnable` | `0x1009AFB2`, `0x1009B0C5` |
| `DrawDepth` @ `0x1009AF90` | `glEnd` | `0x1009B0A1` |
| `DrawDepth` @ `0x1009AF90` | `glVertex3fv` | `0x1009B089` |
| `DrawOverlay` @ `0x1009B0E0` | `glAlphaFunc` | `0x1009B0FD` |
| `DrawOverlay` @ `0x1009B0E0` | `glBegin` | `0x1009B116` |
| `DrawOverlay` @ `0x1009B0E0` | `glDisable` | `0x1009B22F` |
| `DrawOverlay` @ `0x1009B0E0` | `glEnable` | `0x1009B0EA` |
| `DrawOverlay` @ `0x1009B0E0` | `glEnd` | `0x1009B21B` |
| `DrawOverlay` @ `0x1009B0E0` | `glTexCoord2f` | `0x1009B16D` |
| `DrawOverlay` @ `0x1009B0E0` | `glVertex3fv` | `0x1009B1FD` |
| `DrawTest` @ `0x1009B240` | `glBegin` | `0x1009B2F6` |
| `DrawTest` @ `0x1009B240` | `glColor4f` | `0x1009B2EE` |
| `DrawTest` @ `0x1009B240` | `glDisable` | `0x1009B2AD`, `0x1009B2B4`, `0x1009B2BB`, `0x1009B3D3`, `0x1009B3DA` |
| `DrawTest` @ `0x1009B240` | `glEnable` | `0x1009B3E1` |
| `DrawTest` @ `0x1009B240` | `glEnd` | `0x1009B3C8` |
| `DrawTest` @ `0x1009B240` | `glLoadIdentity` | `0x1009B25E`, `0x1009B269` |
| `DrawTest` @ `0x1009B240` | `glMatrixMode` | `0x1009B24E`, `0x1009B265`, `0x1009B3FA`, `0x1009B409` |
| `DrawTest` @ `0x1009B240` | `glOrtho` | `0x1009B294` |
| `DrawTest` @ `0x1009B240` | `glPopMatrix` | `0x1009B402`, `0x1009B40B` |
| `DrawTest` @ `0x1009B240` | `glPushMatrix` | `0x1009B256`, `0x1009B267` |
| `DrawTest` @ `0x1009B240` | `glTexCoord2f` | `0x1009B314`, `0x1009B34A`, `0x1009B37A`, `0x1009B3AA` |
| `DrawTest` @ `0x1009B240` | `glVertex3f` | `0x1009B336`, `0x1009B366`, `0x1009B396`, `0x1009B3C6` |
| `HUD_DrawTransparentTriangles` @ `0x100A3AA0` | `glDisable` | `0x100A3AA5` |
| `V_CalcNormalRefdef` @ `0x100BABD0` | `glEnable` | `0x100BC975` |
| `V_CalcNormalRefdef` @ `0x100BABD0` | `glFogf` | `0x100BC959`, `0x100BC96E` |
| `V_CalcNormalRefdef` @ `0x100BABD0` | `glFogfv` | `0x100BC92A` |
| `V_CalcNormalRefdef` @ `0x100BABD0` | `glFogi` | `0x100BC8DC` |
| `V_CalcNormalRefdef` @ `0x100BABD0` | `glHint` | `0x100BC93A` |
| `VRManager::GenerateTexture` @ `0x100BCB80` | `glEnable` | `0x100BCBA7` |
| `VRManager::VRRefdef` @ `0x100BCC20` | `glEnable` | `0x100BCDB9`, `0x100BCEB0` |

### 8948-so：legacy API 与状态调用完整定位表

| 所属函数（入口） | API | call VA |
|---|---|---|
| `CSurfaceHandler::DrawKnownSurfaces` @ `0x14E208` | `glNormal3f` | `0x14E328` |
| `CSurfaceHandler::FMOD_InitializeScene` @ `0x14E546` | `glNormal3f` | `0x14E614` |
| `CParticleEngine::EngineThink` @ `0x14FA78` | `glTexEnvf` | `0x14FAA0` |
| `CParticleSystem::ParticleDraw` @ `0x155D24` | `glBegin` | `0x155EFE` |
| `CParticleSystem::ParticleDraw` @ `0x155D24` | `glColor4f` | `0x155F5D` |
| `CParticleSystem::ParticleDraw` @ `0x155D24` | `glDisable` | `0x15628E` |
| `CParticleSystem::ParticleDraw` @ `0x155D24` | `glEnable` | `0x156191` |
| `CParticleSystem::ParticleDraw` @ `0x155D24` | `glEnd` | `0x156177` |
| `ClientPortal / PortalSource::CreateTexture（DLL 独立副本）` @ `0x1575CE` | `glEnable` | `0x157670` |
| `DrawMonitor` @ `0x157D5E` | `glBegin` | `0x157D96` |
| `DrawMonitor` @ `0x157D5E` | `glDisable` | `0x157D79` |
| `DrawMonitor` @ `0x157D5E` | `glEnd` | `0x157E87` |
| `DrawMonitor` @ `0x157D5E` | `glTexCoord2f` | `0x157DEC` |
| `DrawMonitor` @ `0x157D5E` | `glVertex3fv` | `0x157E70` |
| `DrawStencil` @ `0x157EA6` | `glBegin` | `0x157F46` |
| `DrawStencil` @ `0x157EA6` | `glColor4f` | `0x157F1E` |
| `DrawStencil` @ `0x157EA6` | `glDisable` | `0x157ECB`, `0x158019` |
| `DrawStencil` @ `0x157EA6` | `glEnable` | `0x157ED7`, `0x158025` |
| `DrawStencil` @ `0x157EA6` | `glEnd` | `0x15800C` |
| `DrawStencil` @ `0x157EA6` | `glVertex3fv` | `0x157FF0` |
| `DrawPortalOrMirrorImageWhereStencilIsOne` @ `0x158052` | `glAlphaFunc` | `0x1580E0` |
| `DrawPortalOrMirrorImageWhereStencilIsOne` @ `0x158052` | `glBegin` | `0x158129` |
| `DrawPortalOrMirrorImageWhereStencilIsOne` @ `0x158052` | `glDisable` | `0x1580EC`, `0x1581EB`, `0x1581F7` |
| `DrawPortalOrMirrorImageWhereStencilIsOne` @ `0x158052` | `glEnable` | `0x1580CF`, `0x1580F8`, `0x158203` |
| `DrawPortalOrMirrorImageWhereStencilIsOne` @ `0x158052` | `glEnd` | `0x1581D0` |
| `DrawPortalOrMirrorImageWhereStencilIsOne` @ `0x158052` | `glLoadIdentity` | `0x158073`, `0x15808D` |
| `DrawPortalOrMirrorImageWhereStencilIsOne` @ `0x158052` | `glMatrixMode` | `0x158066`, `0x158080`, `0x15821B`, `0x158230` |
| `DrawPortalOrMirrorImageWhereStencilIsOne` @ `0x158052` | `glOrtho` | `0x1580B9` |
| `DrawPortalOrMirrorImageWhereStencilIsOne` @ `0x158052` | `glPopMatrix` | `0x158223`, `0x158238` |
| `DrawPortalOrMirrorImageWhereStencilIsOne` @ `0x158052` | `glPushMatrix` | `0x15806E`, `0x158088` |
| `DrawPortalOrMirrorImageWhereStencilIsOne` @ `0x158052` | `glTexCoord2f` | `0x15814B`, `0x15816D`, `0x15818F`, `0x1581B1`, `0x15824C`, `0x158271`, `0x158290` |
| `DrawPortalOrMirrorImageWhereStencilIsOne` @ `0x158052` | `glVertex3f` | `0x15815F`, `0x15817E`, `0x1581A3`, `0x1581C8`, `0x158260`, `0x158282`, `0x1582A4` |
| `DrawDepth` @ `0x1582B4` | `glBegin` | `0x158315` |
| `DrawDepth` @ `0x1582B4` | `glDisable` | `0x1582D9`, `0x1583E8` |
| `DrawDepth` @ `0x1582B4` | `glEnable` | `0x1582E5`, `0x158404` |
| `DrawDepth` @ `0x1582B4` | `glEnd` | `0x1583DB` |
| `DrawDepth` @ `0x1582B4` | `glVertex3fv` | `0x1583BF` |
| `DrawOverlay` @ `0x158414` | `glAlphaFunc` | `0x158440` |
| `DrawOverlay` @ `0x158414` | `glBegin` | `0x15845D` |
| `DrawOverlay` @ `0x158414` | `glDisable` | `0x158565` |
| `DrawOverlay` @ `0x158414` | `glEnable` | `0x15842F` |
| `DrawOverlay` @ `0x158414` | `glEnd` | `0x15854A` |
| `DrawOverlay` @ `0x158414` | `glTexCoord2f` | `0x1584AF` |
| `DrawOverlay` @ `0x158414` | `glVertex3fv` | `0x158533` |
| `DrawTest` @ `0x158576` | `glBegin` | `0x15864A` |
| `DrawTest` @ `0x158576` | `glColor4f` | `0x15863E` |
| `DrawTest` @ `0x158576` | `glDisable` | `0x1585F9`, `0x158605`, `0x158611`, `0x158723`, `0x15872F` |
| `DrawTest` @ `0x158576` | `glEnable` | `0x15873B` |
| `DrawTest` @ `0x158576` | `glEnd` | `0x158716` |
| `DrawTest` @ `0x158576` | `glLoadIdentity` | `0x158597`, `0x1585B1` |
| `DrawTest` @ `0x158576` | `glMatrixMode` | `0x15858A`, `0x1585A4`, `0x158753`, `0x158768` |
| `DrawTest` @ `0x158576` | `glOrtho` | `0x1585E3` |
| `DrawTest` @ `0x158576` | `glPopMatrix` | `0x15875B`, `0x158770` |
| `DrawTest` @ `0x158576` | `glPushMatrix` | `0x158592`, `0x1585AC` |
| `DrawTest` @ `0x158576` | `glTexCoord2f` | `0x15865F`, `0x15869E`, `0x1586D1`, `0x1586F3` |
| `DrawTest` @ `0x158576` | `glVertex3f` | `0x15868A`, `0x1586BD`, `0x1586E8`, `0x15870E` |
| `ClientPortalManager::CreateInvisiblePortalTextures / GenerateInvisibleTexture` @ `0x15877A` | `glEnable` | `0x1587EB` |
| `ClientPortalManager::EnableClipPlane` @ `0x158C7E` | `glClipPlane` | `0x158E00` |
| `ClientPortalManager::EnableClipPlane` @ `0x158C7E` | `glEnable` | `0x158E08` |
| `ClientPortalManager::EnableClipPlane` @ `0x158C7E` | `glLoadIdentity` | `0x158DE8` |
| `ClientPortalManager::DisableClipPlanes` @ `0x158E14` | `glDisable` | `0x158E28`, `0x158E34`, `0x158E40`, `0x158E4C`, `0x158E58`, `0x158E64` |
| `ClientPortalManager::DrawPortals` @ `0x15C95E` | `glColor4f` | `0x15CA21` |
| `ClientPortalManager::DrawPortals` @ `0x15C95E` | `glDisable` | `0x15CA2D` |
| `ClientPortalManager::RenderPortals / PortalRender` @ `0x15D88C` | `glEnable` | `0x15E64A` |
| `HUD_DrawTransparentTriangles` @ `0x1675F8` | `glDisable` | `0x167613` |
| `V_CalcNormalRefdef` @ `0x18A3EA` | `glEnable` | `0x18B12B` |
| `V_CalcNormalRefdef` @ `0x18A3EA` | `glFogf` | `0x18B110`, `0x18B11F` |
| `V_CalcNormalRefdef` @ `0x18A3EA` | `glFogfv` | `0x18B0F0` |
| `V_CalcNormalRefdef` @ `0x18A3EA` | `glFogi` | `0x18B0AE` |
| `V_CalcNormalRefdef` @ `0x18A3EA` | `glHint` | `0x18B101` |
| `VRManager::GenerateTexture` @ `0x18C24C` | `glEnable` | `0x18C28A` |
| `VRManager::VRRefdef` @ `0x18C35E` | `glEnable` | `0x18C5B8`, `0x18C646` |
| `VRManager::DrawVR` @ `0x18C732` | `glBegin` | `0x18C876`, `0x18C93A` |
| `VRManager::DrawVR` @ `0x18C732` | `glColor4f` | `0x18C7C1` |
| `VRManager::DrawVR` @ `0x18C732` | `glDisable` | `0x18C7CD`, `0x18C842`, `0x18C84E`, `0x18C85A`, `0x18C9EB`, `0x18C9F7` |
| `VRManager::DrawVR` @ `0x18C732` | `glEnable` | `0x18CA03` |
| `VRManager::DrawVR` @ `0x18C732` | `glEnd` | `0x18C90F`, `0x18C9D0` |
| `VRManager::DrawVR` @ `0x18C732` | `glLoadIdentity` | `0x18C7E6`, `0x18C800` |
| `VRManager::DrawVR` @ `0x18C732` | `glMatrixMode` | `0x18C7D9`, `0x18C7F3`, `0x18CA1B`, `0x18CA30` |
| `VRManager::DrawVR` @ `0x18C732` | `glOrtho` | `0x18C82C` |
| `VRManager::DrawVR` @ `0x18C732` | `glPopMatrix` | `0x18CA23`, `0x18CA38` |
| `VRManager::DrawVR` @ `0x18C732` | `glPushMatrix` | `0x18C7E1`, `0x18C7FB` |
| `VRManager::DrawVR` @ `0x18C732` | `glTexCoord2f` | `0x18C881`, `0x18C8A3`, `0x18C8C5`, `0x18C8F0`, `0x18C945`, `0x18C96A`, `0x18C98F`, `0x18C9B1` |
| `VRManager::DrawVR` @ `0x18C732` | `glVertex3f` | `0x18C895`, `0x18C8B4`, `0x18C8E2`, `0x18C907`, `0x18C95C`, `0x18C97E`, `0x18C9A3`, `0x18C9C8` |

### 新发现重点位置的原始指令上下文

以下 `=>` 指向目标指令；用于复查调用约定、实参及指针重载。

#### 10257-dll `0x1004EF74`

```asm
   0x1004EF60: 6a 01                          push   0x1
   0x1004EF62: e8 49 bd fd ff                 call   0x1002acb0
   0x1004EF67: 83 c4 08                       add    esp,0x8
   0x1004EF6A: e9 7c 00 00 00                 jmp    0x1004efeb
   0x1004EF6F: 68 e1 0d 00 00                 push   0xde1
=> 0x1004EF74: ff 15 08 a2 11 10              call   DWORD PTR ds:0x1011a208
   0x1004EF7A: 8b 75 dc                       mov    esi,DWORD PTR [ebp-0x24]
   0x1004EF7D: 8b 3d 24 a2 11 10              mov    edi,DWORD PTR ds:0x1011a224
```

#### 10257-dll `0x1004F099`

```asm
   0x1004F08B: 89 41 fc                       mov    DWORD PTR [ecx-0x4],eax
   0x1004F08E: 83 ee 01                       sub    esi,0x1
   0x1004F091: 75 ed                          jne    0x1004f080
   0x1004F093: 8b 45 e8                       mov    eax,DWORD PTR [ebp-0x18]
   0x1004F096: 8b 55 cc                       mov    edx,DWORD PTR [ebp-0x34]
=> 0x1004F099: 8b 35 a4 a1 11 10              mov    esi,DWORD PTR ds:0x1011a1a4
   0x1004F09F: 42                             inc    edx
   0x1004F0A0: 89 55 cc                       mov    DWORD PTR [ebp-0x34],edx
```

#### 10257-dll `0x1004F0BA`

```asm
   0x1004F0A8: 2b c1                          sub    eax,ecx
   0x1004F0AA: c1 f8 02                       sar    eax,0x2
   0x1004F0AD: 3b d0                          cmp    edx,eax
   0x1004F0AF: 0f 82 4b fb ff ff              jb     0x1004ec00
   0x1004F0B5: 68 00 30 00 00                 push   0x3000
=> 0x1004F0BA: ff d6                          call   esi
   0x1004F0BC: 68 01 30 00 00                 push   0x3001
   0x1004F0C1: ff d6                          call   esi
```

#### 10257-dll `0x1004D711`

```asm
   0x1004D705: 6a 00                          push   0x0
   0x1004D707: 68 28 2a 1a 10                 push   0x101a2a28
   0x1004D70C: 8b f8                          mov    edi,eax
   0x1004D70E: 6a 01                          push   0x1
   0x1004D710: 57                             push   edi
=> 0x1004D711: ff 15 f8 96 64 10              call   DWORD PTR ds:0x106496f8
   0x1004D717: 57                             push   edi
   0x1004D718: ff 15 88 96 64 10              call   DWORD PTR ds:0x10649688
```

#### 10257-dll `0x1004D718`

```asm
   0x1004D70C: 8b f8                          mov    edi,eax
   0x1004D70E: 6a 01                          push   0x1
   0x1004D710: 57                             push   edi
   0x1004D711: ff 15 f8 96 64 10              call   DWORD PTR ds:0x106496f8
   0x1004D717: 57                             push   edi
=> 0x1004D718: ff 15 88 96 64 10              call   DWORD PTR ds:0x10649688
   0x1004D71E: 8b 0d 90 96 64 10              mov    ecx,DWORD PTR ds:0x10649690
   0x1004D724: 68 30 8b 00 00                 push   0x8b30
```

#### 10257-dll `0x1004F22F`

```asm
   0x1004F21E: 74 11                          je     0x1004f231
   0x1004F220: a1 54 97 64 10                 mov    eax,ds:0x10649754
   0x1004F225: 85 c0                          test   eax,eax
   0x1004F227: 74 08                          je     0x1004f231
   0x1004F229: ff b3 e4 01 00 00              push   DWORD PTR [ebx+0x1e4]
=> 0x1004F22F: ff d0                          call   eax
   0x1004F231: 57                             push   edi
   0x1004F232: ff 15 64 8a 1f 10              call   DWORD PTR ds:0x101f8a64
```

#### 10257-dll `0x1004F326`

```asm
   0x1004F319: 74 0d                          je     0x1004f328
   0x1004F31B: a1 54 97 64 10                 mov    eax,ds:0x10649754
   0x1004F320: 85 c0                          test   eax,eax
   0x1004F322: 74 04                          je     0x1004f328
   0x1004F324: 6a 00                          push   0x0
=> 0x1004F326: ff d0                          call   eax
   0x1004F328: 8b 44 24 10                    mov    eax,DWORD PTR [esp+0x10]
   0x1004F32C: 3d c0 84 00 00                 cmp    eax,0x84c0
```

#### 10257-dll `0x10044995`

```asm
   0x1004497B: f3 0f 11 44 24 08              movss  DWORD PTR [esp+0x8],xmm0
   0x10044981: f3 0f 10 40 04                 movss  xmm0,DWORD PTR [eax+0x4]
   0x10044986: f3 0f 11 44 24 04              movss  DWORD PTR [esp+0x4],xmm0
   0x1004498C: f3 0f 10 00                    movss  xmm0,DWORD PTR [eax]
   0x10044990: f3 0f 11 04 24                 movss  DWORD PTR [esp],xmm0
=> 0x10044995: ff 15 30 a2 11 10              call   DWORD PTR ds:0x1011a230
   0x1004499B: f3 0f 10 46 04                 movss  xmm0,DWORD PTR [esi+0x4]
   0x100449A0: 83 ec 0c                       sub    esp,0xc
```

#### 10257-dll `0x10044AE9`

```asm
   0x10044ACF: f3 0f 11 44 24 08              movss  DWORD PTR [esp+0x8],xmm0
   0x10044AD5: f3 0f 10 40 04                 movss  xmm0,DWORD PTR [eax+0x4]
   0x10044ADA: f3 0f 11 44 24 04              movss  DWORD PTR [esp+0x4],xmm0
   0x10044AE0: f3 0f 10 00                    movss  xmm0,DWORD PTR [eax]
   0x10044AE4: f3 0f 11 04 24                 movss  DWORD PTR [esp],xmm0
=> 0x10044AE9: ff 15 30 a2 11 10              call   DWORD PTR ds:0x1011a230
   0x10044AEF: f3 0f 10 46 04                 movss  xmm0,DWORD PTR [esi+0x4]
   0x10044AF4: 83 ec 08                       sub    esp,0x8
```

#### 10257-dll `0x1007577B`

```asm
   0x1007575E: c7 81 e0 00 00 00 01 00 00 00  mov    DWORD PTR [ecx+0xe0],0x1
   0x10075768: e9 5a 01 00 00                 jmp    0x100758c7
   0x1007576D: 83 f8 01                       cmp    eax,0x1
   0x10075770: 0f 85 f1 00 00 00              jne    0x10075867
   0x10075776: 68 e1 0d 00 00                 push   0xde1
=> 0x1007577B: ff 15 08 a2 11 10              call   DWORD PTR ds:0x1011a208
   0x10075781: ff 36                          push   DWORD PTR [esi]
   0x10075783: 8b 35 24 a2 11 10              mov    esi,DWORD PTR ds:0x1011a224
```

#### 8948-dll `0x100974AC`

```asm
   0x1009749B: 6a 01                          push   0x1
   0x1009749D: e8 ce e0 fd ff                 call   0x10075570
   0x100974A2: 83 c4 08                       add    esp,0x8
   0x100974A5: eb 72                          jmp    0x10097519
   0x100974A7: 68 e1 0d 00 00                 push   0xde1
=> 0x100974AC: ff 15 04 52 0e 10              call   DWORD PTR ds:0x100e5204
   0x100974B2: ff b7 cc 00 00 00              push   DWORD PTR [edi+0xcc]
   0x100974B8: 68 e1 0d 00 00                 push   0xde1
```

#### 8948-dll `0x100975D3`

```asm
   0x100975C1: 75 ed                          jne    0x100975b0
   0x100975C3: 8b 83 90 00 00 00              mov    eax,DWORD PTR [ebx+0x90]
   0x100975C9: 8b 55 d4                       mov    edx,DWORD PTR [ebp-0x2c]
   0x100975CC: 8b 8b 8c 00 00 00              mov    ecx,DWORD PTR [ebx+0x8c]
   0x100975D2: 42                             inc    edx
=> 0x100975D3: 8b 35 08 52 0e 10              mov    esi,DWORD PTR ds:0x100e5208
   0x100975D9: 2b c1                          sub    eax,ecx
   0x100975DB: c1 f8 02                       sar    eax,0x2
```

#### 8948-dll `0x1008C9F5`

```asm
   0x1008C9DB: f3 0f 11 44 24 08              movss  DWORD PTR [esp+0x8],xmm0
   0x1008C9E1: f3 0f 10 40 04                 movss  xmm0,DWORD PTR [eax+0x4]
   0x1008C9E6: f3 0f 11 44 24 04              movss  DWORD PTR [esp+0x4],xmm0
   0x1008C9EC: f3 0f 10 00                    movss  xmm0,DWORD PTR [eax]
   0x1008C9F0: f3 0f 11 04 24                 movss  DWORD PTR [esp],xmm0
=> 0x1008C9F5: ff 15 88 51 0e 10              call   DWORD PTR ds:0x100e5188
   0x1008C9FB: f3 0f 10 46 04                 movss  xmm0,DWORD PTR [esi+0x4]
   0x1008CA00: 83 ec 0c                       sub    esp,0xc
```

#### 8948-dll `0x1008CB49`

```asm
   0x1008CB2F: f3 0f 11 44 24 08              movss  DWORD PTR [esp+0x8],xmm0
   0x1008CB35: f3 0f 10 40 04                 movss  xmm0,DWORD PTR [eax+0x4]
   0x1008CB3A: f3 0f 11 44 24 04              movss  DWORD PTR [esp+0x4],xmm0
   0x1008CB40: f3 0f 10 00                    movss  xmm0,DWORD PTR [eax]
   0x1008CB44: f3 0f 11 04 24                 movss  DWORD PTR [esp],xmm0
=> 0x1008CB49: ff 15 88 51 0e 10              call   DWORD PTR ds:0x100e5188
   0x1008CB4F: f3 0f 10 46 04                 movss  xmm0,DWORD PTR [esi+0x4]
   0x1008CB54: 83 ec 08                       sub    esp,0x8
```

#### 8948-dll `0x1009775F`

```asm
   0x1009774E: 74 11                          je     0x10097761
   0x10097750: a1 a4 19 18 10                 mov    eax,ds:0x101819a4
   0x10097755: 85 c0                          test   eax,eax
   0x10097757: 74 08                          je     0x10097761
   0x10097759: ff b3 e4 01 00 00              push   DWORD PTR [ebx+0x1e4]
=> 0x1009775F: ff d0                          call   eax
   0x10097761: 57                             push   edi
   0x10097762: ff 15 54 a9 1b 10              call   DWORD PTR ds:0x101ba954
```

#### 10257-so `0xEB5B0`

```asm
   0xEB596: f3 0f 11 44 24 08              movss  DWORD PTR [esp+0x8],xmm0
   0xEB59C: f3 0f 10 4a 04                 movss  xmm1,DWORD PTR [edx+0x4]
   0xEB5A1: f3 0f 11 4c 24 04              movss  DWORD PTR [esp+0x4],xmm1
   0xEB5A7: f3 0f 10 12                    movss  xmm2,DWORD PTR [edx]
   0xEB5AB: f3 0f 11 14 24                 movss  DWORD PTR [esp],xmm2
=> 0xEB5B0: e8 9b f1 fa ff                 call   9a750 <glNormal3f@plt>
   0xEB5B5: 8b 86 48 01 00 00              mov    eax,DWORD PTR [esi+0x148]
   0xEB5BB: d9 45 10                       fld    DWORD PTR [ebp+0x10]
```

#### 10257-so `0xEB97B`

```asm
   0xEB963: f3 0f 10 49 04                 movss  xmm1,DWORD PTR [ecx+0x4]
   0xEB968: f3 0f 11 4c 24 04              movss  DWORD PTR [esp+0x4],xmm1
   0xEB96E: f3 0f 10 11                    movss  xmm2,DWORD PTR [ecx]
   0xEB972: f3 0f 11 14 24                 movss  DWORD PTR [esp],xmm2
   0xEB977: 8b 5c 24 18                    mov    ebx,DWORD PTR [esp+0x18]
=> 0xEB97B: e8 d0 ed fa ff                 call   9a750 <glNormal3f@plt>
   0xEB980: f3 0f 10 5f 08                 movss  xmm3,DWORD PTR [edi+0x8]
   0xEB985: f3 0f 11 5c 24 08              movss  DWORD PTR [esp+0x8],xmm3
```

#### 10257-so `0x12E40D`

```asm
   0x12E3EE: c7 04 24 00 00 80 3f           mov    DWORD PTR [esp],0x3f800000
   0x12E3F5: e8 86 c4 f6 ff                 call   9a880 <glColor4f@plt>
   0x12E3FA: c7 04 24 e2 0b 00 00           mov    DWORD PTR [esp],0xbe2
   0x12E401: e8 4a c0 f6 ff                 call   9a450 <glDisable@plt>
   0x12E406: c7 04 24 00 17 00 00           mov    DWORD PTR [esp],0x1700
=> 0x12E40D: e8 4e ae f6 ff                 call   99260 <glMatrixMode@plt>
   0x12E412: e8 e9 ba f6 ff                 call   99f00 <glPushMatrix@plt>
   0x12E417: e8 74 b1 f6 ff                 call   99590 <glLoadIdentity@plt>
```

#### 10257-so `0x12E4B4`

```asm
   0x12E49A: 8b 4e 10                       mov    ecx,DWORD PTR [esi+0x10]
   0x12E49D: 89 4c 24 04                    mov    DWORD PTR [esp+0x4],ecx
   0x12E4A1: c7 04 24 e1 0d 00 00           mov    DWORD PTR [esp],0xde1
   0x12E4A8: e8 a3 c4 f6 ff                 call   9a950 <glBindTexture@plt>
   0x12E4AD: c7 04 24 09 00 00 00           mov    DWORD PTR [esp],0x9
=> 0x12E4B4: e8 97 c1 f6 ff                 call   9a650 <glBegin@plt>
   0x12E4B9: c7 44 24 04 00 00 00 00        mov    DWORD PTR [esp+0x4],0x0
   0x12E4C1: c7 04 24 00 00 00 00           mov    DWORD PTR [esp],0x0
```

#### 10257-so `0x12E5D6`

```asm
   0x12E5BC: 8b 46 14                       mov    eax,DWORD PTR [esi+0x14]
   0x12E5BF: 89 44 24 04                    mov    DWORD PTR [esp+0x4],eax
   0x12E5C3: c7 04 24 e1 0d 00 00           mov    DWORD PTR [esp],0xde1
   0x12E5CA: e8 81 c3 f6 ff                 call   9a950 <glBindTexture@plt>
   0x12E5CF: c7 04 24 09 00 00 00           mov    DWORD PTR [esp],0x9
=> 0x12E5D6: e8 75 c0 f6 ff                 call   9a650 <glBegin@plt>
   0x12E5DB: c7 44 24 04 00 00 00 00        mov    DWORD PTR [esp+0x4],0x0
   0x12E5E3: c7 04 24 00 00 00 00           mov    DWORD PTR [esp],0x0
```

#### 10257-so `0x12E257`

```asm
   0x12E23A: c7 06 00 00 00 00              mov    DWORD PTR [esi],0x0
   0x12E240: 89 74 24 04                    mov    DWORD PTR [esp+0x4],esi
   0x12E244: c7 04 24 01 00 00 00           mov    DWORD PTR [esp],0x1
   0x12E24B: e8 c0 b5 f6 ff                 call   99810 <glGenTextures@plt>
   0x12E250: c7 04 24 e1 0d 00 00           mov    DWORD PTR [esp],0xde1
=> 0x12E257: e8 74 b9 f6 ff                 call   99bd0 <glEnable@plt>
   0x12E25C: 8b 16                          mov    edx,DWORD PTR [esi]
   0x12E25E: 89 54 24 04                    mov    DWORD PTR [esp+0x4],edx
```

#### 8948-so `0x14E328`

```asm
   0x14E320: 51                             push   ecx
   0x14E321: 8b 42 04                       mov    eax,DWORD PTR [edx+0x4]
   0x14E324: 50                             push   eax
   0x14E325: 8b 12                          mov    edx,DWORD PTR [edx]
   0x14E327: 52                             push   edx
=> 0x14E328: e8 83 34 f5 ff                 call   a17b0 <glNormal3f@plt>
   0x14E32D: 58                             pop    eax
   0x14E32E: 8b 8e 48 01 00 00              mov    ecx,DWORD PTR [esi+0x148]
```

#### 8948-so `0x14E614`

```asm
   0x14E60C: 50                             push   eax
   0x14E60D: 8b 4a 04                       mov    ecx,DWORD PTR [edx+0x4]
   0x14E610: 51                             push   ecx
   0x14E611: 8b 12                          mov    edx,DWORD PTR [edx]
   0x14E613: 52                             push   edx
=> 0x14E614: e8 97 31 f5 ff                 call   a17b0 <glNormal3f@plt>
   0x14E619: 83 c4 0c                       add    esp,0xc
   0x14E61C: 8b 47 08                       mov    eax,DWORD PTR [edi+0x8]
```

#### 8948-so `0x18C7D9`

```asm
   0x18C7BC: 68 00 00 80 3f                 push   0x3f800000
   0x18C7C1: e8 da 50 f1 ff                 call   a18a0 <glColor4f@plt>
   0x18C7C6: c7 04 24 e2 0b 00 00           mov    DWORD PTR [esp],0xbe2
   0x18C7CD: e8 ee 31 f1 ff                 call   9f9c0 <glDisable@plt>
   0x18C7D2: c7 04 24 00 17 00 00           mov    DWORD PTR [esp],0x1700
=> 0x18C7D9: e8 72 6c f1 ff                 call   a3450 <glMatrixMode@plt>
   0x18C7DE: 83 c4 10                       add    esp,0x10
   0x18C7E1: e8 9a 78 f1 ff                 call   a4080 <glPushMatrix@plt>
```

#### 8948-so `0x18C876`

```asm
   0x18C861: 8b 46 10                       mov    eax,DWORD PTR [esi+0x10]
   0x18C864: 50                             push   eax
   0x18C865: 68 e1 0d 00 00                 push   0xde1
   0x18C86A: e8 41 65 f1 ff                 call   a2db0 <glBindTexture@plt>
   0x18C86F: c7 04 24 09 00 00 00           mov    DWORD PTR [esp],0x9
=> 0x18C876: e8 65 30 f1 ff                 call   9f8e0 <glBegin@plt>
   0x18C87B: 58                             pop    eax
   0x18C87C: 5a                             pop    edx
```

#### 8948-so `0x18C93A`

```asm
   0x18C925: 8b 4e 14                       mov    ecx,DWORD PTR [esi+0x14]
   0x18C928: 51                             push   ecx
   0x18C929: 68 e1 0d 00 00                 push   0xde1
   0x18C92E: e8 7d 64 f1 ff                 call   a2db0 <glBindTexture@plt>
   0x18C933: c7 04 24 09 00 00 00           mov    DWORD PTR [esp],0x9
=> 0x18C93A: e8 a1 2f f1 ff                 call   9f8e0 <glBegin@plt>
   0x18C93F: 58                             pop    eax
   0x18C940: 5a                             pop    edx
```

#### 8948-so `0x18C28A`

```asm
   0x18C278: 83 ec 08                       sub    esp,0x8
   0x18C27B: 56                             push   esi
   0x18C27C: 6a 01                          push   0x1
   0x18C27E: e8 7d 72 f1 ff                 call   a3500 <glGenTextures@plt>
   0x18C283: c7 04 24 e1 0d 00 00           mov    DWORD PTR [esp],0xde1
=> 0x18C28A: e8 c1 5b f1 ff                 call   a1e50 <glEnable@plt>
   0x18C28F: 58                             pop    eax
   0x18C290: 5a                             pop    edx
```
