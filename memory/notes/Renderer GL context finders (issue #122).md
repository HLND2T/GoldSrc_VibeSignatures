---
title: 'Renderer GL context finders (issue #122)'
type: note
permalink: goldsrc-vibesignatures/notes/renderer-gl-context-finders-issue-122
tags:
- '- renderer

  - gl

  - issue-122

  - py_eval

  - anchors'
---

# Renderer GL context finders (issue #122)

## Trigger
Adding `find-GL_Shutdown`, `find-GL_LoadFilterTexture`, `find-GL_SelectPixelFormat`, `find-GL_SetMode_call_qwglCreateContext` for the engine module (PR #123).

## Confirmed anchors
- `GL_SelectPixelFormat`: FULLMATCH `"ChoosePixelFormat failed"` literal, unique owner on every legacy Windows build. HL25 inlines the selection into GL_SetMode (the literal's owner *is* GL_SetMode); SvEngine uses wglChoosePixelFormatARB/EXT + glew.
- `GL_Shutdown`: `"Sys_Shutdown()"` TRACESHUTDOWN literal has ≤2 owners (Sys_InitGame TraceInit pair + the real shutdown path); discriminate by the call shape: ≥3 distinct absolute-global loads (`mov reg,[abs]`/`push [abs]`), ≥3 argument writes (push reg / push [reg] / push [abs] / `mov [esp+X],reg`), and the pmainwindow-style double dereference. CoF routes the call 2 levels deep (Sys_ShutdownGame→Sys_Shutdown→GL_Shutdown). Window must cut at the preceding call/jmp or a tail-chunk call reuses the earlier argument setup.
- `GL_LoadFilterTexture`: body contains 0xC0 (malloc 8*8*3) + 0x1907 (GL_RGB). A byte-level prefilter narrows the scan, then each candidate must expose both values as **o_imm instruction operands** (review P2: displacements or unrelated 32-bit words must not satisfy the pair — hl-8684/linux Draw_AlphaSubPic fails the 0xC0 immediate check while still matching the byte prefilter). Not unique on hl-8684/linux even then → waterfall discriminator: direct GL_Bind call (Windows hl/cof families, SvEngine and Linux inline GL_Bind out) → named allocator call (free/_ZdlPv/_ZdaPv/malloc; WON blobs call free through an unnamed thunk but `_malloc` is named) → bare constant pair (only when unique). The GL_Bind artifact is declared as `optional_input` in all ten engine configs so the scheduler owns that dependency edge.
- `GL_SetMode_call_qwglCreateContext` (patch): inside the GL_SetMode/GL_SetModeLegacy host artifact, the first non-IAT `FF 15` after the direct GL_SelectPixelFormat call (maindc = GetDC; SelectPixelFormat; CreateContext). PE builds cross-check the exported `qwglCreateContext` variable; WON blobs have no export directory and fall back to that post-SelectPF scan with `.idata` slots excluded.

## Non-applicability evidence
- hl-10210/linux GL_Shutdown is a 395-byte byte-identical clone of FreeFBOObjects (compiler cloning) — no unique func_sig can ever exist; excluded.
- svencoop/linux Sys_Shutdown has no GL_Shutdown call; SvEngine Windows GL_Shutdown is a 5-byte `jmp` thunk whose signature needs branch displacements pinned (per-version artifacts may pin rel32 because it is fixed at link time).
- E13: no binary/config in the repo (issue author confirmed skip this cycle).

## Pitfalls hit
- py_eval scoping: module-level constants and nested/peer `def`s are not visible inside functions unless `globals().update(locals())` runs **after all top-level defs** (see find-ClientDLL_Shutdown); defs inside the `try:` block cannot call each other — keep helpers top-level.
- IDA x86 operand encoding: register-indirect without displacement (`mov eax,[edx]`, `mov eax,[eax]`) is **o_phrase (type 3)**, not o_displ; `mov [esp+X],reg` may decode as o_phrase too. Register number 0 **is eax** — never use `base != 0` to mean "no base".
- Argument-shape discriminators must count `push [abs]` (FF 35) and `push [reg]` (FF 30) or the HL25/SvEngine call form fails.
- Patch signatures must wildcard the `FF 15` slot displacement (loader relocates absolute addresses); anchor uniqueness with the surrounding instruction stream instead.
- `-allgamever` stops at the first failing gamever; a failed run leaves `.id0/.id1` sidecars that make the next run report an IDB lock — delete the sidecars (the `.i64` stays intact).

## Verification
- 41/41 artifacts regenerated from final code: GL_Shutdown 11 (10 win + hl-8684 linux), GL_LoadFilterTexture 13, GL_SelectPixelFormat 8, callsite 9. Unit 812 OK, repository-contract 14 OK, format clean. PR #123.

## Scope
GoldSrc x86 engine finders; the argument-shape/constant-pair/thunk-pin techniques apply to any small helper function without own strings.