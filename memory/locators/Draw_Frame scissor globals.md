---
title: Draw_Frame scissor globals
type: note
permalink: goldsrc-vibesignatures/locators/draw-frame-scissor-globals
tags:
- locator
- engine
- gv
- scissor
- draw_frame
- svencoop
- pic
---

# Draw_Frame scissor globals (`giScissorTest`, `scissor_x/y/width/height`)

## Symbols

- **Names**: `giScissorTest` (`qboolean*`), `scissor_x`, `scissor_y`, `scissor_width`, `scissor_height` (`int*`)
- **Category**: `gv`
- **Module**: engine (`hw.dll` / `hw.so` / `hw.decrypt.dll` for the BLOB builds)
- **Owners**: `ida_preprocessor_scripts/find-Draw_Frame-scissor-globals.py` (globals),
  `ida_preprocessor_scripts/find-Draw_SpriteFrame-family-svencoop.py` (Linux `Draw_Frame`),
  shared shape in `ida_preprocessor_scripts/_draw_frame_scissor_common.py`

## Trigger

Adding engine scissor globals, or any need to identify `Draw_Frame` on a build where the
sprite-frame family walk cannot. Root constraint: `gl_draw.c` keeps these five as file-scope
statics with no exported name, and `Draw_Frame` is their only reader:

```c
static int scissor_x, scissor_y;
static int scissor_width, scissor_height;
static qboolean giScissorTest = false;

if ( giScissorTest )
{
    qglScissor( scissor_x, scissor_y, scissor_width, scissor_height );
    qglEnable( GL_SCISSOR_TEST );
}
```

## How it is located

`Draw_Frame` is located first, from that block alone; the globals are read out of it.

1. **Frame** — the only function in the image that (a) supplies four argument values each
   resolving to a *distinct* writable dword global to one `call`, (b) immediately stores
   `GL_SCISSOR_TEST` (0xC11) for the following enable, and (c) has that call guarded by a
   conditional branch. A `b'\x11\x0C\x00\x00'` scan is only a candidate prefilter; the
   instruction shapes decide.
2. **`giScissorTest`** — the writable global the guarding branch tests: `cmp gv, <imm 0>`,
   `cmp gv, <callee-saved register zeroed by xor/sub>`, or `mov reg, gv` + `test reg, reg`.
3. **Rect** — argument identity follows source order, which both ABIs lay out right-to-left,
   so the *reverse* instruction order is `qglScissor(x, y, width, height)`.

Four emitted forms must all be handled (all verified):

| form | example | builds |
| --- | --- | --- |
| MSVC direct push | `push ds:scissor_y` | hl-10210/8684 w |
| MSVC register push + load | `mov edx, ds:scissor_y` … `push edx` | hl-3248/3266/3329/3647/4554/6153 w, svencoop w |
| gcc outgoing-argument slot | `mov eax, ds:scissor_y` … `mov [esp+8], eax` | hl-10210/8684 `hw.so` |
| gcc PIC slot + `_glScissor` import | `mov eax, (scissor_y - 33A000h)[ebx]` … `mov [esp+4], eax` … `call _glScissor` | svencoop `hw.so` |

Each global's artifact must reference the instruction that carries a four-byte displacement —
the **load** (`mov reg, gv`), not a `push reg`, whose displacement is zero and which
`gv_resolution_fields_via_mcp` rejects. This was the only real trap: the walk resolved all
five globals long before the artifact writer accepted them.

Address order is deliberately **not** used. Layouts disagree and none matches declaration
order:

| build | ascending layout |
| --- | --- |
| all Windows | `x, y, width, height, giScissorTest` |
| hl-10210 `hw.so` | `giScissorTest, height, width, y, x` |
| hl-8684 `hw.so` | `x, width, y, height, giScissorTest`, 0x10 apart |
| svencoop `hw.so` | `giScissorTest, height, width, y, x` |

## SvEngine Linux: why the family walk needed the same invariant

`find-Draw_SpriteFrame-family-svencoop` previously derived `Draw_Frame` as the callee shared by
all three `SPR_Draw*` literal owners. Both Linux builds break that:

- **svencoop-8948/hw.so** — each literal owner calls a PIC trampoline (`jmp ds:off_33B7D4`), not
  the renderer, so no callee is shared by all three owners at all. The trampoline's GOT slot
  dword holds the renderer VA (`idc.get_wide_dword(slot)`), which `_resolve` now follows.
- **svencoop-10257/hw.so** — the three renderers share five callees, so the support set cannot
  be narrowed.

Both are fixed by locating `Draw_Frame` from the scissor block instead, then taking the unique
literal-reachable candidate that `call`s it. An orphan diagnostic that IDA attached to a
neighbouring function (8948: the `SPR_DrawHoles` literal sits inside `DrawCrosshair`'s chunk)
cannot pollute the result.

## Validation

- 15/15 engine binaries resolve exactly one `Draw_Frame` and all five globals: cof-5936,
  hl-3248/3266/3329/3647/4554/6153/8684/10210 (Windows), hl-8684/10210 (Linux),
  svencoop-8948/10257 (Windows + Linux).
- Independent ground truth: the Linux IDBs' own symbol tables
  (`_ZL13giScissorTest`=0x2a81540, `_ZL9scissor_x`=0x2a81550 …) and IDA's DWARF parameter
  annotations (`var_6C`=GLint/x, `var_60`=GLsizei/height) match the argument-order mapping;
  SvEngine Windows keeps the parameter names as operand comments (`push dword_30FC70C; x`).
- `gv_pic_addend: 0x33a000` is emitted for the PIC globals, matching IDA's
  `(giScissorTest - 33A000h)[ebx]` rendering.
- Sven Windows family artifacts regenerate **byte-identically** (deleted, re-run, `git diff`
  empty), so the family rewrite is not a Windows regression.
- `-allgamever -modules engine -skill find-Draw_Frame-scissor-globals`: 14 successful, 0 failed,
  1 skipped (outputs already present). Unit and repository-contract suites pass; format clean.

## Scope

- `cstrike-*` / `czero-*` / `czeror-*` configs declare no `engine` module, so the symbols are
  not registered there.
- hl-3248..3647 are BLOB builds: the analysis object is `hw.decrypt.dll` and the recorded VAs
  live in that IDB.
- `enable_scissor_test` / `disable_scissor_test` also write the four ints; they are not used as
  anchors because `Draw_Frame` is their only reader.
