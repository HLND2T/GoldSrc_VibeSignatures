#!/usr/bin/env python3
"""Locate SvEngine's eight-int buffered rectangle body (issue #148).

No owned string or distinctive float set separates this body from the other
RGBA helpers. Reuse the validated buffer-capacity/GL-array semantic anchor,
including Linux's <= 1023 form, then verify actual GL arguments and stack ABI.
No target symbol names, fixed addresses, old artifacts or byte signatures
locate the body. GL import names identify the operations being validated.
"""

import inspect
import json

import ida_analyze_util as u
import ida_preprocessor_scripts.x86_call_arguments as arguments
from ida_preprocessor_scripts.renderer_draw_signatures import CUSTOM_SIG

TARGET = "Draw_FillRGBABuf"
MARKER = "__FILL_RGBA_BUF__"

WALK = r"""
import ida_bytes, ida_frame, ida_funcs, ida_idp, ida_ua, idaapi, idautils, idc

EXPECTED = [
    ('glEnableClientState', [0x8074]), ('glEnableClientState', [0x8076]),
    ('glDisable', [0xDE1]), ('glEnable', [0xBE2]),
    ('glTexEnvf', [0x2300, 0x2200]), ('glBlendFunc', [0x302, 1]),
    ('glVertexPointer', [2, 0x1406, 24]), ('glColorPointer', [4, 0x1406, 24]),
    ('glDrawArrays', [7, 0]),
    ('glDisableClientState', [0x8074]), ('glDisableClientState', [0x8076]),
    ('glEnable', [0xDE1]), ('glDisable', [0xBE2]),
]
GL_NAMES = {name for name, _ in EXPECTED}

def call_name(ea):
    seen = set()
    for _ in range(4):
        if ea in seen: return None
        seen.add(ea)
        name = idc.get_name(ea).lstrip('._')
        if name.startswith('imp_'): name = name[4:].lstrip('_')
        name = name.split('@')[0]
        if name in GL_NAMES: return name
        if idc.print_insn_mnem(ea) != 'jmp': return None
        kind = idc.get_operand_type(ea, 0)
        if kind == idaapi.o_near: ea = idc.get_operand_value(ea, 0)
        elif kind == idaapi.o_mem: ea = ida_bytes.get_dword(idc.get_operand_value(ea, 0))
        else: return None
    return None

def operand(pc, index, op, sp):
    if op.type == idaapi.o_imm: return ('imm', int(op.value))
    if op.type in (idaapi.o_near, idaapi.o_far): return ('imm', int(idc.get_operand_value(pc, index)))
    if op.type == idaapi.o_reg and ida_ua.get_dtype_size(op.dtype) == 4:
        return ('reg', ida_idp.get_reg_name(op.reg, 4))
    text = idc.print_operand(pc, index).lower()
    if op.type in (idaapi.o_displ, idaapi.o_phrase) and '[esp' in text:
        if not any(reg in text for reg in ('eax','ebx','ecx','edx','esi','edi','ebp')):
            disp = int(op.addr) if op.type == idaapi.o_displ else 0
            if disp & 0x80000000: disp -= 0x100000000
            return ('stack', sp + disp)
    return ('unknown', None)

def pic_thunk(target):
    # Only permit GCC's exact get-PC operation; no arbitrary small callee.
    insn = ida_ua.insn_t()
    if ida_ua.decode_insn(insn, target) <= 0: return False
    return (idc.print_insn_mnem(target) == 'mov' and
            insn.ops[0].type == idaapi.o_reg and
            operand(target, 1, insn.ops[1], 0) == ('stack', 0) and
            idc.print_insn_mnem(target + insn.size) in ('ret', 'retn'))

def inspect_body(start):
    f = ida_funcs.get_func(start)
    items = list(idautils.FuncItems(start))
    flow = decode_function_flow(f, items)
    capacity = any(idc.print_insn_mnem(pc) == 'cmp' and
                   idc.get_operand_type(pc, 1) == idaapi.o_imm and
                   idc.get_operand_value(pc, 1) in (1023, 1024) for pc in items[:24])
    if not capacity: return False
    code, calls, incoming, float_args = [], [], set(), set()
    stores = 0
    imports = {}
    for pc in items:
        insn = ida_ua.insn_t()
        if ida_ua.decode_insn(insn, pc) <= 0: return False
        sp = int(ida_frame.get_spd(f, pc))
        mnem = idc.print_insn_mnem(pc).lower()
        ops = [operand(pc, i, op, sp) for i, op in enumerate(insn.ops) if op.type != idaapi.o_void]
        code.append({'mnem':mnem, 'ops':ops, 'sp':sp, 'ea':int(pc), 'successors':flow[pc]})
        if mnem.startswith('j'): imports.clear()
        if ops and ops[0][0] == 'reg' and mnem not in ('cmp','test','push','call'):
            imports.pop(ops[0][1], None)
            if mnem == 'mov' and insn.ops[1].type == idaapi.o_mem:
                name = call_name(int(insn.ops[1].addr))
                if name: imports[ops[0][1]] = name
        if mnem in ('mov', 'add', 'fild'):
            for kind, value in (ops if mnem == 'fild' else ops[1:]):
                if kind == 'stack' and value in range(4, 36, 4):
                    incoming.add((value - 4) // 4)
                    if mnem == 'fild': float_args.add((value - 4) // 4)
        # IDA may expose an implicit ST(0) operand before the memory destination.
        if mnem in ('fst','fstp'):
            for i,op in enumerate(insn.ops):
                if op.type in (idaapi.o_mem, idaapi.o_displ, idaapi.o_phrase):
                    if operand(pc,i,op,sp)[0] == 'unknown': stores += 1
        if mnem in ('ret','retn') and ops: return False
        if mnem != 'call': continue
        target = int(idc.get_operand_value(pc, 0))
        if insn.ops[0].type == idaapi.o_reg:
            name = imports.get(ops[0][1])
        elif insn.ops[0].type in (idaapi.o_near, idaapi.o_mem):
            name = call_name(target)
        else: return False
        for reg in ('eax','ecx','edx'): imports.pop(reg, None)
        if not name:
            if PLATFORM == 'linux' and not calls and pic_thunk(target): continue
            return False
        calls.append((len(code)-1, name))
    if [name for _,name in calls] != [name for name,_ in EXPECTED]:
        return False
    if incoming != set(range(8)) or not {0,1,4,5,6,7}.issubset(float_args):
        return False
    if stores != 24:
        return False
    for (index,_), (_,expected) in zip(calls, EXPECTED):
        if recover_call_arguments(code, index, len(expected)) != expected:
            return False
    return True

if idaapi.inf_is_64bit(): raise ValueError('expected x86-32')
hits = [hex(e) for e in idautils.Functions()
        if 100 <= ida_funcs.get_func(e).end_ea-e <= 900 and inspect_body(e)]
print(MARKER + json.dumps({'hits':hits}))
"""


async def evaluate(session, code):
    raw = (await session.call_tool("py_eval", {"code": "exec(" + repr(code) + ", {})"})).model_dump(mode="json")
    result = raw.get("structured_content") or {}
    if result.get("stderr"):
        print(result["stderr"])
        return {}
    for line in (result.get("stdout") or "").splitlines():
        if line.startswith(MARKER):
            return json.loads(line[len(MARKER) :])
    return {}


async def preprocess_skill(
    session, skill_name, expected_outputs, old_yaml_map, new_binary_dir, platform, image_base, debug=False
):
    _ = skill_name, old_yaml_map, new_binary_dir
    output = u._output_for_symbol(expected_outputs, TARGET)
    if output is None or platform not in ("windows", "linux"):
        return False
    prefix = f"import json\nPLATFORM={platform!r}\nMARKER={MARKER!r}\n"
    result = await evaluate(session, prefix + inspect.getsource(arguments) + "\n" + WALK)
    if debug:
        print("Buffered RGBA candidates: " + json.dumps(result))
    hits = result.get("hits", [])
    if len(hits) != 1:
        return False
    signatures = await evaluate(session, f"TARGETS={ {TARGET: hits[0]}!r}\nMARKER={MARKER!r}\n" + CUSTOM_SIG)
    function = signatures.get(TARGET)
    if not function:
        return False
    va = int(function["func_va"], 0)
    u.write_func_yaml(
        output,
        {
            "func_name": TARGET,
            "func_va": hex(va),
            "func_rva": hex(va - image_base),
            "func_size": hex(function["func_size"]),
            "func_sig": function["func_sig"],
        },
    )
    return True
