---
title: EngineSurface drawFlushText private globals (#241)
type: note
permalink: goldsrc-vibesignatures/locators/enginesurface-drawflushtext-private-globals-241
tags:
- locator
- engine
- gv
- structmember
- enginesurface
- issue-241
---

# EngineSurface drawFlushText private globals (#241)

Producer: `find-EngineSurface_drawFlushText-private-globals`. Owner: the already shipped
`EngineSurface_drawFlushText` vfunc artifact, consumed through
`inspect_owner_artifact(..., func_name="EngineSurface::drawFlushText()")` — the artifact stores the
source-qualified name, so the filename stem and `func_name` differ. `inspect_owner_artifact` gained
that optional override for this case.

Source (`engine/VGUI_EngineSurface.cpp`): `VertexBuffer_t g_VertexBuffer[256]`,
`int g_iVertexBufferEntriesUsed = 0`, and the `EngineSurface` member `int _drawTextColor[4]`.

## `g_iVertexBufferEntriesUsed`

Rule: the only writable-data global in the owner body that the body both reads and writes. Every
other absolute reference is a read of a qgl* function-pointer slot (`call dword ptr [..]`), and
`g_VertexBuffer` is only materialised as an argument address here, never dereferenced. Reads/writes
are classified from each memory operand's `CF_CHGn` feature, so x87 stores count as writes.

## `g_VertexBuffer`

Rule: the earliest writable-data address materialised in the body that has a sibling materialised at
exactly +8. The two GL pointer calls pass `&g_VertexBuffer[0].texcoords[0]` and
`&g_VertexBuffer[0].vertex[0]`; the gap is `sizeof(VertexBuffer_t::texcoords)` (2 floats). The pair
also rejects the PIC prologue `add ebx, GOT`, which materialises the GOT base but has no sibling.
Target resolution uses IDA data refs, which already fold the PIC GOT base, so MSVC absolute
(`push offset`), GCC absolute (`mov reg, offset`) and GCC PIC (`lea eax, (gv - GOT)[ebx]`) share one
rule. `write_located_globals` then encodes the PIC form as `gv_pic_addend`.

## `EngineSurface::_drawTextColor`

Rule: in the owner body the only `this`-relative member reads with displacements
{K, K+4, K+8, K+12} are the four byte lanes passed to the colour call; base K is
`_drawTextColor[0]`. Layout differs per engine family, so every gamever records its own offset:
`0x18` on hl-*/cof-5936, `0x14` on SvEngine (svencoop-8948/10257). The artifact is a
`structmember` with `offset_sig_disp` = the offset of the lane-0 instruction in the owner body and
the default `displacement` ref kind.

## Coverage

15/15 binary/platform combinations, `-allgamever -modules engine -skill
find-EngineSurface_drawFlushText-private-globals -platform windows,linux`: 15 successful, 0 failed,
0 skipped. hl-3248/3266/3329/3647 are BLOB builds analysed through `hw.decrypt.dll`. The two
svencoop Linux builds are PIC and exercise the GOT-relative path; hl-10210/hl-8684 Linux are
GCC absolute.

Cross-check on the hl-10210 Windows IDB: `g_iVertexBufferEntriesUsed = 0x109a7a5c` and
`g_VertexBuffer = 0x109a6a58` with a sibling at `0x109a6a60` (= +8). An independent LLM-free
disassembly read of the same body produced the same three values.
