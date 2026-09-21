---
title: Host_Init palette and fallback texture locators
type: note
permalink: goldsrc-vibesignatures/locators/host-init-palette-and-fallback-texture-locators
tags:
- locator
- engine
- gv
- func
---

# Host_Init palette and fallback textures

## Symbols

- `Host_Init` (`func`, engine `hw.dll`/`hw.so`)
- `Host_LoadBasePalette` (`func`, SvEngine only)
- `host_basepal` (`gv`, `word*`)
- `R_InitTextures` (`func`)
- `r_notexture_mip` (`gv`, GoldSrc/HL25/CoF)
- `R_UploadEmptyTex` (`func`; HL25 Windows inlined into `R_Init`)
- `r_emptytexture` (`gv`, SvEngine ELF name)
- `R_UploadMissingTex` (`func`, SvEngine)
- `r_missingtexture` (`gv`, SvEngine)

Producer: `ida_preprocessor_scripts/find-Host_Init.py` and siblings; shared walks in `_host_palette_common.py`.

## Anchors

- GoldSrc/HL25/CoF `Host_Init`: `FULLMATCH:Host_Init: Couldn't load gfx/palette.lmp`
- SvEngine `Host_Init`: `FULLMATCH:Heap size: %4.1f MB\n` (`Host_Init()` is owned by `Sys_InitGame`)
- SvEngine `Host_LoadBasePalette`: `Could not load base palette from "%s".\n` excluding the heap banner (Windows Host_Init inlines the same body)
- `host_basepal`: revalidated `Hunk_AllocName` callee, C arguments `0x800` and a `palette.lmp` pointer (including the Linux `gfx/palette.lmp` suffix), and EAX/return-register dataflow into the unique writable-global store. Linux GoldSrc merges `"palette.lmp"` into `"gfx/palette.lmp"+4`. SvEngine Linux 8948 reaches the allocator through a PIC PLT `jmp [ebx+GOTOFF]` whose lazy `.got.plt` dword is still `stub+6`; the walk proves the slot with the owner's GOT base.
- `R_InitTextures`: previous direct call of the unique `custom` HPAK xref inside `Host_Init`
- `r_notexture_mip`: unique writable store in GoldSrc `R_InitTextures` (`Hunk_AllocName(..., "notexture")`)
- `R_UploadEmptyTex`: `**empty**` excluding `**missing**` and `gl_dump`
- `r_emptytexture` / `r_missingtexture`: unique post-prologue writable global in the corresponding upload function

## Availability

- `Host_Init` / `host_basepal` / `R_InitTextures`: all 11 engine configs (15 Win/Linux pairs)
- `R_UploadEmptyTex`: 14 pairs; missing on hl-10210 Windows (inlined)
- `r_notexture_mip`: hl-* / cof-5936 only
- `Host_LoadBasePalette`, `r_emptytexture`, `R_UploadMissingTex`, `r_missingtexture`: svencoop-8948 / 10257 only

## Pitfalls

- SvEngine empty-texture ELF name is `r_emptytexture`, not `r_notexture_mip`.
- `-allgamever -skill` errors on gamevers that do not register the skill; filter `-modules engine` and run SvEngine-only skills with `-gamever svencoop-*`.
- Walk helpers must parse hex owner EAs with `int(value, 0)`.
- A nearby `0x800` immediate plus the next global write is not `host_basepal`; the store must write the `Hunk_AllocName` return register.
- `local_call_target` / `resolve_elf_plt` reject a PIC PLT stub when `.got.plt` still holds the lazy resolver; `host_basepal` must resolve that stub from the caller's GOT register before comparing with the `Hunk_AllocName` artifact.
- SvEngine `Host_LoadBasePalette` loads `palette.lmp` into a callee-saved register, then `test`/`jz` on `COM_LoadHunkFile` before `mov [esp+4], ebp`. The `jz` taken target is the error path after the call, so the name assignment dominates the call. A `jcc` that can skip the assignment while still reaching the call leaves the name argument unknown.
- After `Hunk_AllocName`, only proven keep-alive instructions may preserve the return register: `mov` copies, `cmp`/`test`/`push`, and `add`/`sub esp, imm`. Implicit EAX writes such as `mul` kill the live set.
