#!/usr/bin/env python3
"""Recover EngineSurface::drawFlushText's vertex-buffer state and text colour.

engine/VGUI_EngineSurface.cpp keeps the VGUI glyph batch in two file-private
globals that only this method consumes, plus the text colour in an
EngineSurface member array:

    VertexBuffer_t g_VertexBuffer[MAXVERTEXBUFFERS];
    int g_iVertexBufferEntriesUsed = 0;
    int EngineSurface::_drawTextColor[4];

    void EngineSurface::drawFlushText()
    {
        if ( g_iVertexBufferEntriesUsed > 0 )
        {
            ...
            qglColor4ub( _drawTextColor[0], _drawTextColor[1], _drawTextColor[2], 255 - _drawTextColor[3] );
            qglTexCoordPointer( 2, GL_FLOAT, sizeof( VertexBuffer_t ), &g_VertexBuffer[0].texcoords[0] );
            qglVertexPointer( 2, GL_FLOAT, sizeof( VertexBuffer_t ), &g_VertexBuffer[0].vertex[0] );
            qglDrawArrays( GL_QUADS, 0, g_iVertexBufferEntriesUsed );
            ...
            g_iVertexBufferEntriesUsed = 0;
        }
    }

The owner is the already-shipped EngineSurface_drawFlushText vfunc artifact, so
each rule below is a structural invariant of that same source method:

g_iVertexBufferEntriesUsed
    The only writable-data global the body both reads and writes.  Every other
    absolute reference in the body is a read of the qgl* function pointer slots
    (the dispatch is `call dword ptr [..]`), and g_VertexBuffer is never
    dereferenced here, only materialised as an argument address.

g_VertexBuffer
    The earliest writable-data address materialised by the body that has a
    sibling materialised at exactly +8.  The two GL pointer calls pass
    &g_VertexBuffer[0].texcoords[0] and &g_VertexBuffer[0].vertex[0]; the +8 gap
    is sizeof(VertexBuffer_t::texcoords), and the pair also rejects the
    `add ebx, GOT` PIC prologue that is merely a base register setup.

EngineSurface::_drawTextColor
    The byte lanes fed to the colour call form the only four `this`-relative
    member reads in the body with displacements {K, K+4, K+8, K+12}; the array
    base K is _drawTextColor[0].  Layout differs per engine family, so each
    gamever records its own current-binary offset.

All three candidates come from verified current-binary instruction operands; no
address, offset or signature is copied from another build.  Validated on all 15
engine binaries declared by the 11 engine game-version configs (hl-3248/3266/
3329/3647 via their decrypted hw.decrypt.dll), covering MSVC absolute, GCC
absolute and GCC PIC GOT-relative forms.
"""

from ida_analyze_util import (
    _load_yaml_mapping,
    _output_for_symbol,
    parse_mcp_result,
    write_struct_offset_yaml,
)
from ida_preprocessor_scripts._direct_gv_common import (
    inspect_owner_artifact,
    write_located_globals,
)

OWNER = "EngineSurface_drawFlushText"
# The shipped EngineSurface_drawFlushText artifact stores the source-qualified
# name, so its identity differs from the config symbol / filename stem.
OWNER_FUNC_NAME = "EngineSurface::drawFlushText()"
STRUCT = "EngineSurface"
ENTRIES_SYMBOL = "g_iVertexBufferEntriesUsed"
BUFFER_SYMBOL = "g_VertexBuffer"
COLOR_SYMBOL = "EngineSurface__drawTextColor"
COLOR_MEMBER = "_drawTextColor"
COLOR_SIZE = 16
BUFFER_FIELD_GAP = 8

GV_FIELDS = [
    "gv_name",
    "gv_va",
    "gv_rva",
    "gv_sig",
    "gv_sig_va",
    "gv_inst_offset",
    "gv_inst_length",
    "gv_inst_disp",
    "gv_pic_addend?",
    "gv_address_offset?",
]

LOCATE = r"""
import ida_bytes, ida_funcs, ida_segment, ida_ua, idaapi, idautils, idc, ida_idp, json


def _locate():
    owner_start = OWNER_START_PLACEHOLDER
    owner_end = OWNER_END_PLACEHOLDER

    SEG_WRITE = int(ida_segment.SEGPERM_WRITE)
    SEG_EXEC = int(ida_segment.SEGPERM_EXEC)
    GOT_SEGMENTS = ('.got', '.got.plt')
    STACK_BASES = ('esp', 'ebp', 'sp', 'bp')

    def seg_name(ea):
        seg = ida_segment.getseg(int(ea))
        return '' if seg is None else (ida_segment.get_segm_name(seg) or '')

    def reg_name(op):
        try:
            return (ida_idp.get_reg_name(int(op.reg), 4) or '').lower()
        except Exception:
            return ''

    def is_writable_data(ea):
        seg = ida_segment.getseg(int(ea))
        if seg is None or int(ea) == 0:
            return False
        perm = int(getattr(seg, 'perm', 0))
        if not (perm & SEG_WRITE) or (perm & SEG_EXEC):
            return False
        return seg_name(ea) not in GOT_SEGMENTS

    def changed(insn, index):
        return bool(insn.get_canon_feature() & int(getattr(ida_idp, 'CF_CHG%d' % (index + 1))))

    def is_memory_operand(op):
        return int(op.type) in (int(idaapi.o_mem), int(idaapi.o_displ), int(idaapi.o_phrase))

    def operand_offset(op, insn):
        offb = int(getattr(op, 'offb', 0) or 0)
        if offb and offb + 4 <= int(insn.size):
            return offb
        return 0

    function = ida_funcs.get_func(int(owner_start))
    if function is None or int(function.start_ea) != int(owner_start):
        raise ValueError('owner function not found')
    if int(function.end_ea) != int(owner_end):
        raise ValueError('owner end mismatch')

    reads = {}
    writes = {}
    materialized = []
    member_offsets = {}

    for ea in idautils.FuncItems(int(owner_start)):
        insn = ida_ua.insn_t()
        if ida_ua.decode_insn(insn, ea) == 0:
            raise ValueError('undecodable instruction at 0x%X' % int(ea))
        ea = int(ea)
        mnemonic = (insn.get_canon_mnem() or '').lower()
        immediates = set()
        for index, op in enumerate(insn.ops):
            if int(op.type) == int(idaapi.o_void):
                break
            if int(op.type) == int(idaapi.o_imm):
                immediates.add(int(op.value) & 0xFFFFFFFF)
            elif int(op.type) == int(idaapi.o_displ):
                reg = reg_name(op)
                disp = int(op.addr) & 0xFFFFFFFF
                if reg and reg not in STACK_BASES and 0 < disp < 0x100:
                    member_offsets.setdefault(disp, ea)
        for target in idautils.DataRefsFrom(ea):
            target = int(target) & 0xFFFFFFFF
            if not is_writable_data(target):
                continue
            if mnemonic == 'lea' or target in immediates:
                for op in insn.ops:
                    if int(op.type) == int(idaapi.o_void):
                        break
                    offset = operand_offset(op, insn)
                    if not offset:
                        continue
                    if int(op.type) == int(idaapi.o_imm) and (int(op.value) & 0xFFFFFFFF) != target:
                        continue
                    if int(op.type) in (int(idaapi.o_mem), int(idaapi.o_displ), int(idaapi.o_phrase)) or int(
                        op.type
                    ) == int(idaapi.o_imm):
                        materialized.append((ea, target, offset, int(insn.size)))
                        break
                continue
            for index, op in enumerate(insn.ops):
                if int(op.type) == int(idaapi.o_void):
                    break
                if not is_memory_operand(op):
                    continue
                offset = operand_offset(op, insn)
                if not offset:
                    break
                entry = (ea, offset, int(insn.size))
                if changed(insn, index):
                    writes.setdefault(target, entry)
                else:
                    reads.setdefault(target, entry)
                break

    entries_used = sorted(set(reads) & set(writes))
    if len(entries_used) != 1:
        raise ValueError('expected one read+write global, got %r' % [hex(v) for v in entries_used])
    entries_ea = entries_used[0]
    entries_insn, entries_disp, entries_len = reads[entries_ea] if reads[entries_ea][0] <= writes[entries_ea][0] else writes[entries_ea]

    materialized.sort()
    buffer = None
    for index in range(len(materialized)):
        ea, target, offset, length = materialized[index]
        if any(other == target + BUFFER_FIELD_GAP for _, other, _, _ in materialized[index + 1:]):
            buffer = (ea, target, offset, length)
            break
    if buffer is None:
        raise ValueError('no materialised vertex-buffer pair found')

    offsets = sorted(member_offsets)
    color_base = None
    for base in offsets:
        if all(base + 4 * lane in member_offsets for lane in range(4)):
            color_base = base
            break
    if color_base is None:
        raise ValueError('no four-lane text-colour member group found')

    return {
        'pointer_size': 8 if idaapi.inf_is_64bit() else 4,
        'entries_used': {
            'gv_ea': hex(entries_ea),
            'insn_ea': hex(entries_insn),
            'insn_len': entries_len,
            'insn_disp': entries_disp,
        },
        'vertex_buffer': {
            'gv_ea': hex(buffer[1]),
            'insn_ea': hex(buffer[0]),
            'insn_len': buffer[3],
            'insn_disp': buffer[2],
        },
        'draw_text_color': {
            'offset': hex(color_base),
            'insn_ea': hex(member_offsets[color_base]),
        },
    }


try:
    result = json.dumps(_locate())
except Exception as exc:
    result = json.dumps({'pointer_size': 8 if idaapi.inf_is_64bit() else 4, 'error': repr(exc)})
"""


def _as_int(value):
    return int(value, 0) if isinstance(value, str) else int(value)


async def preprocess_skill(
    session,
    skill_name,
    expected_outputs,
    old_yaml_map,
    new_binary_dir,
    platform,
    image_base,
    debug=False,
):
    del skill_name, old_yaml_map
    owner = await inspect_owner_artifact(
        session, new_binary_dir, platform, image_base, OWNER, func_name=OWNER_FUNC_NAME
    )
    if owner is None:
        if debug:
            print(f"  {OWNER}: missing or invalid owner artifact")
        return False
    code = (
        LOCATE.replace("OWNER_START_PLACEHOLDER", str(owner["owner_ea"]))
        .replace("OWNER_END_PLACEHOLDER", str(owner["owner_end"]))
        .replace("BUFFER_FIELD_GAP", hex(BUFFER_FIELD_GAP))
    )
    try:
        located = parse_mcp_result(await session.call_tool("py_eval", {"code": code}))
    except Exception as exc:  # noqa: BLE001 - MCP failures fail closed.
        if debug:
            print(f"  {OWNER}: locator call failed: {exc}")
        return False
    if not isinstance(located, dict) or located.get("error") or located.get("pointer_size") != 4:
        if debug:
            print(f"  {OWNER}: locator failed: {located!r}")
        return False
    if debug:
        print(
            f"  {OWNER}: entries_used={located['entries_used']} "
            f"vertex_buffer={located['vertex_buffer']} color={located['draw_text_color']}"
        )

    if not await write_located_globals(
        session,
        expected_outputs,
        platform,
        image_base,
        owner,
        {
            ENTRIES_SYMBOL: located["entries_used"],
            BUFFER_SYMBOL: located["vertex_buffer"],
        },
    ):
        return False

    color_output = _output_for_symbol(expected_outputs, COLOR_SYMBOL)
    if color_output is None:
        return False
    color_insn = _as_int(located["draw_text_color"]["insn_ea"])
    color_offset = _as_int(located["draw_text_color"]["offset"])
    payload = {
        "struct_name": STRUCT,
        "member_name": COLOR_MEMBER,
        "offset": hex(color_offset),
        "size": hex(COLOR_SIZE),
        "offset_sig": owner["function"]["func_sig"],
        "offset_sig_disp": hex(color_insn - owner["owner_ea"]),
    }
    if owner["allow_across"]:
        payload["offset_sig_allow_across_function_boundary"] = True
    write_struct_offset_yaml(color_output, payload)

    written = _load_yaml_mapping(color_output)
    if not written or written.get("struct_name") != STRUCT or written.get("member_name") != COLOR_MEMBER:
        if debug:
            print(f"  {OWNER}: invalid {COLOR_SYMBOL} artifact: {written!r}")
        return False
    return True
