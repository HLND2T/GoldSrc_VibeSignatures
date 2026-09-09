---
title: Old-tag blob binaries need hw.decrypt.dll for byte-level checks
type: note
permalink: goldsrc-vibesignatures/notes/old-tag-blob-binaries-need-hw.decrypt.dll-for-byte-level-checks
tags:
- blob
- decrypt
- gamebin
- binary-identity
- pitfall
- anchor
---

# Old-tag engine binaries are encrypted blobs — byte-level checks must target hw.decrypt.dll

## Trigger（触发信号）

- 任何直接对 `bin/hl-3248`、`bin/hl-3266`、`bin/hl-3329`、`bin/hl-3647` 下 `hw.dll`（或 `bin/` 里任何非 PE/ELF 文件）做的字节/字符串/模式扫描、PE 节表解析，或基于"字符串 X 在 Y 版本不存在"得出的结论（注册范围判定、机制存在性判定、anchor 可行性判定）。
- 2026-09-09 事故：一次对 `bin/*/engine/hw.dll` 的 anchor 可行性字符串普查报告四个老版本"缺少" studio-interface 字符串、`Sys_InitArgv( OrigCmd )`、`models/player/%s/%s.mdl`，据此得出"该引擎年代无此机制、不注册"的错误结论并险些提交。实际上四个字面量全部存在——普查读的是加密字节。用户质疑后才翻案。

## Root cause / constraint（根因与约束）

- WON 时代 hl tag 的 `hw.dll` 是加密 "blob" 镜像：不是 MZ/ELF（hl-3248/3266/3329 开头 `00 00 …`，hl-3647 开头 `LS`）。对它做原始字节搜索会**静默返回 0 命中**——没有任何错误把"字符串不存在"和"文件不可读"区分开。
- 分析管线（现有 artifact、IDB、finder）对这些 tag 全部运行在解密后的 PE32 上：`bin/<tag>/engine/hw.decrypt.dll`（+ `hw.decrypt.dll.i64`）。`configs/hl-32xx.yaml` 里 `module_windows` 仍写 `hw.dll`；解密是仓库维护的预处理步骤（`decrypt_blob.py`，仅通过用户 slash 命令 `/decrypt-blob-gamebin` 触发，skill 为 `disable-model-invocation`，模型不会自动撞见）。
- 旧知识只作为一句附带表述埋在 [[sys-init-memory-locator]]（"incl. blob gamevers via their decrypted `hw.decrypt.dll`"）里，按 blob/decrypt/encrypted 搜索不出来，因此坑重复踩了。

## Correct approach（正确做法）

1. 对 `bin/` 下任何二进制做字节级检查前，先验证它是否真实镜像：`MZ`（PE）或 `\x7fELF`。其它一律是 blob，**绝不能**对它做内容性结论。
2. 老 hl tag 的字节级检查一律指向 `hw.decrypt.dll`（命名规则 `<stem>.decrypt.<ext>`）。若解密文件缺失，正确动作是走仓库解密步骤，而不是得出"符号/机制不存在"。
3. "机制不存在"类结论先与现有证据交叉核对：config 注册项 + `bin/<tag>/engine/*.yaml` 覆盖面。老 tag 已有几十个 artifact，这本身就证明分析对象是解密镜像。
4. 在**合法** PE/ELF 上"anchor 字符串计数 == 0"仍是有效证据（如各 engine family 文案确实不同）；该证据只在 blob 上无效。

## Verification（验证方式）

- 2026-09-09 在 `hw.decrypt.dll` 上重跑（owned `IdaMcpLifecycle`，`restored_strict`）：四个老 tag 均有 studio-interface 字面量（1×）、`HUD_GetStudioModelInterface`（2×）、`models/player/%s/%s.mdl`（2×）、`Sys_InitArgv( OrigCmd )`（1× 且唯一 owner = RunListenServer）；studio 全链路（engine_studio_api 表 → slot 0x7C → studioapi_SetupPlayerModel → R_StudioChangePlayerModel 两处调用点 → DM_PlayerState 0x20C 步长）四版本全部验证通过。

## Scope（适用范围）

- 任何对 `bin/` 游戏二进制做字符串/模式/节表扫描、"可行性"检查或缺失性声明的任务：`find-anchor-to-goldsrc-symbol`、`create-preprocessor-scripts` 的注册决策、gamesymbol 清单规划。不涉及 IDB 分析本身（lifecycle 绑定的已是解密镜像）。
