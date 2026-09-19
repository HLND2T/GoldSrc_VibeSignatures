#!/usr/bin/env python3
"""Resolve SvEngine's public fill slots through their forwarding entries.

Issue #147 approved anchor: cl_enginefuncs slots 11/130, not byte scans.
Windows uses JMP thunks (some are undefined IDA functions). ELF uses cdecl
eight-argument wrappers plus a get-PC thunk; 8948 additionally uses PLT/GOT.
Emit the drawing bodies, not Draw_FillRGBA_I / Draw_FillRGBABlend_I wrappers.
The real 8948 ELF names demangle to Draw_FillRGBA / Draw_FillRGBABlend.
"""

import inspect
import json
from pathlib import Path

import ida_analyze_util as u
import ida_preprocessor_scripts.x86_forwarding as flow
from ida_preprocessor_scripts.renderer_draw_signatures import CUSTOM_SIG

SLOTS = {"Draw_FillRGBA": (11, 1), "Draw_FillRGBABlend": (130, 0x303)}
MARKER = "__SVEN_FILL_RGBA__"

WALK = r"""
import ida_bytes, ida_funcs, ida_idp, ida_segment, ida_ua, idaapi, idautils, idc, json

MAX_INSTRUCTIONS = 256
MAX_THUNK_HOPS = 4

def executable(ea):
    seg = ida_segment.getseg(ea)
    return bool(seg and seg.perm & ida_segment.SEGPERM_EXEC)

def decode(ea):
    insn = ida_ua.insn_t()
    if not executable(ea) or not ida_bytes.is_code(ida_bytes.get_flags(ea)) or ida_ua.decode_insn(insn, ea) <= 0:
        raise ValueError('not decoded executable code at ' + hex(ea))
    return insn

def gl_name(ea):
    name = idc.get_name(ea).lstrip('._')
    if name.startswith('imp_'):
        name = name[4:].lstrip('_')
    name = name.split('@')[0]
    return name if name in GL_ARITY else None

def resolve(ea):
    seen = set()
    for _ in range(MAX_THUNK_HOPS):
        if ea in seen:
            raise ValueError('thunk cycle')
        seen.add(ea)
        name = gl_name(ea)
        if name:
            return ('gl', name)
        insn = decode(ea)
        if idc.print_insn_mnem(ea).lower() != 'jmp':
            # Verify the get-PC thunk's exact semantics, not its symbol spelling.
            if (idc.print_insn_mnem(ea).lower() == 'mov' and
                insn.ops[0].type == idaapi.o_reg and
                operand(ea, insn.ops[1], 1) == ('stack', 0)):
                reg = ida_idp.get_reg_name(insn.ops[0].reg, 4)
                end = ea + insn.size
                tail = decode(end)
                if idc.print_insn_mnem(end).lower() in ('ret', 'retn') and tail.ops[0].type == idaapi.o_void:
                    return ('pic', reg)
            return ('body', ea)
        op = insn.ops[0]
        if op.type == idaapi.o_near:
            ea = int(op.addr)
        elif op.type == idaapi.o_mem:
            ea = int(ida_bytes.get_dword(op.addr))
        else:
            raise ValueError('unsupported jump indirection')
    raise ValueError('too many thunk hops')

def operand(ea, op, index):
    if op.type == idaapi.o_imm:
        return ('imm', int(op.value))
    if op.type == idaapi.o_reg and ida_ua.get_dtype_size(op.dtype) == WORD:
        return ('reg', ida_idp.get_reg_name(op.reg, WORD))
    if op.type in (idaapi.o_displ, idaapi.o_phrase):
        # Require ESP base without an index; addr is the raw encoded displacement,
        # independent of IDA's named arg/local rendering and stack analysis.
        text = idc.print_operand(ea, index).lower()
        if '[esp' in text and not any(r in text for r in ('eax','ebx','ecx','edx','esi','edi','ebp')):
            disp = int(op.addr) if op.type == idaapi.o_displ else 0
            if disp & 0x80000000:
                disp -= 0x100000000
            return ('stack', disp)
    if op.type == idaapi.o_mem:
        name = gl_name(int(op.addr))
        if name:
            return ('symbol', name)
    return ('unknown', None)

def instructions(start):
    pc = start
    result = []
    for _ in range(MAX_INSTRUCTIONS):
        owner = ida_funcs.get_func(pc)
        if owner and int(owner.start_ea) != start:
            raise ValueError('overlapping function at ' + hex(pc))
        insn = decode(pc)
        mnem = idc.print_insn_mnem(pc).lower()
        if mnem.startswith('j') or mnem.startswith('loop'):
            raise ValueError('non-straight-line body')
        ops = [operand(pc, op, i) for i,op in enumerate(insn.ops) if op.type != idaapi.o_void]
        target = None
        if mnem == 'call':
            op = insn.ops[0]
            if op.type == idaapi.o_near:
                target = resolve(int(op.addr))
            elif op.type == idaapi.o_mem:
                name = gl_name(int(op.addr))
                if name:
                    target = ('gl', name)
                else:
                    target = resolve(int(ida_bytes.get_dword(op.addr)))
            elif op.type != idaapi.o_reg:
                raise ValueError('unsupported call operand')
        result.append({'mnem':mnem, 'ops':ops, 'target':target})
        pc += insn.size
        if mnem in ('ret', 'retn'):
            return result, pc
    raise ValueError('unterminated body')

def locate(table, slot, factor):
    entry = int(ida_bytes.get_dword(table + slot * WORD))
    if PLATFORM == 'windows':
        insn = decode(entry)
        if idc.print_insn_mnem(entry).lower() != 'jmp' or insn.ops[0].type != idaapi.o_near:
            raise ValueError('expected direct Windows forwarding jump')
        target = resolve(entry)
    else:
        wrapper, _ = instructions(entry)
        target = trace_calls(wrapper, PLATFORM, forwarding=True)[0][0]
    if target[0] != 'body':
        raise ValueError('slot did not resolve to a drawing body')
    body = target[1]
    code, end = instructions(body)
    calls = trace_calls(code, PLATFORM)
    expected = ['glDisable', 'glEnable', 'glTexEnvf', 'glBlendFunc',
                'glColor4f', 'glBegin'] + ['glVertex2f'] * 4 + [
                'glEnd', 'glColor3f', 'glEnable', 'glDisable']
    if [c[0][1] for c in calls] != expected:
        raise ValueError('unexpected drawing operations')
    for index, args in ((0,[0xDE1]), (1,[0xBE2]), (3,[0x302,factor]),
                        (5,[7]), (12,[0xDE1]), (13,[0xBE2])):
        if calls[index][1] != args:
            raise ValueError('incorrect GL arguments at call ' + str(index))
    if calls[2][1][:2] != [0x2300, 0x2200]:
        raise ValueError('incorrect texture environment')
    # Only now promote anonymous decoded code, after the forwarding/ABI/GL checks.
    owner = ida_funcs.get_func(body)
    if owner is None and not ida_funcs.add_func(body, end):
        raise ValueError('cannot define verified drawing function')
    owner = ida_funcs.get_func(body)
    if owner is None or int(owner.start_ea) != body or int(owner.end_ea) != end:
        raise ValueError('conflicting drawing function bounds')
    return hex(body)

out = {}
if idaapi.inf_is_64bit():
    raise ValueError('expected x86-32')
for name, (slot, factor) in SLOTS.items():
    try:
        out[name] = locate(TABLE, slot, factor)
    except ValueError as exc:
        out[name + '_error'] = str(exc)
print(MARKER + json.dumps(out))
"""


async def evaluate(session, code):
    raw = (await session.call_tool("py_eval", {"code": "exec(" + repr(code) + ", {})"})).model_dump(mode="json")
    result = raw.get("structured_content") or {}
    if result.get("stderr"):
        print("SvEngine fill: " + result["stderr"])
        return {}
    for line in (result.get("stdout") or "").splitlines():
        if line.startswith(MARKER):
            return json.loads(line[len(MARKER) :])
    return {}


async def preprocess_skill(
    session, skill_name, expected_outputs, old_yaml_map, new_binary_dir, platform, image_base, debug=False
):
    # No old artifact/signature discovery. Only the current table is an input.
    _ = skill_name, old_yaml_map
    if platform not in ("windows", "linux"):
        return False
    table = u._load_yaml_mapping(Path(new_binary_dir) / f"cl_enginefuncs.{platform}.yaml")
    if not table or "gv_va" not in table:
        return False
    prefix = (
        f"TABLE={u._parse_int(table['gv_va'], 'gv_va')}\nPLATFORM={platform!r}\nSLOTS={SLOTS!r}\nMARKER={MARKER!r}\n"
    )
    located = await evaluate(session, prefix + inspect.getsource(flow) + "\n" + WALK)
    if debug:
        print("SvEngine fill bodies: " + json.dumps(located))
    if any(name not in located for name in SLOTS) or len({located[name] for name in SLOTS}) != len(SLOTS):
        return False
    # Preserve GL immediates so sibling bodies remain distinguishable. This is
    # output generation/uniqueness validation, never the discovery mechanism.
    signatures = await evaluate(session, f"TARGETS={located!r}\nMARKER={MARKER!r}\n" + CUSTOM_SIG)
    for name in SLOTS:
        output = u._output_for_symbol(expected_outputs, name)
        function = signatures.get(name)
        if output is None or not function:
            if debug:
                print("SvEngine fill signature failure: " + json.dumps(signatures))
            return False
        va = int(function["func_va"], 0)
        u.write_func_yaml(
            output,
            {
                "func_name": name,
                "func_va": hex(va),
                "func_rva": hex(va - image_base),
                "func_size": hex(function["func_size"]),
                "func_sig": function["func_sig"],
            },
        )
    return True
