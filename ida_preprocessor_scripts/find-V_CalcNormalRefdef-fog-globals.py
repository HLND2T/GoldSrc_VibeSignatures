"""Locate Sven's normal view function and its three private fog globals.

The existing exported ``V_CalcRefdef`` artifact is the ABI root. Its only
direct callee that sets ``GL_FOG_MODE`` to ``GL_LINEAR``, passes three scaled
colour components to ``glFogfv(GL_FOG_COLOR)``, and sets ``GL_FOG_START`` and
``GL_FOG_END`` is ``V_CalcNormalRefdef``. This is the normal, unpaused view
branch in ``cl_dll/view.cpp``; the Sven fog block is confirmed in all four
8948/10257 client binaries. The 8948 ELF symbol table independently names
the function and all three data objects.

The GL argument dataflow identifies each object independently. MSVC uses
absolute scalar loads, 10257 GCC uses GOTOFF LEAs, and 8948 GCC loads pointers
through GOT relocations. Neither the MetaHookSv byte pattern nor the observed
relative order of the globals is used for discovery.
"""

from pathlib import Path

from ida_analyze_util import _inspect_function_via_mcp, _output_for_symbol, write_func_yaml
from ida_preprocessor_scripts._direct_gv_common import inspect_owner_artifact, write_located_globals
from ida_preprocessor_scripts._portal_layout_ida import run_layout_walk

FUNCTION = "V_CalcNormalRefdef"
GLOBALS = ("g_iFogColor", "g_iStartDist", "g_iEndDist")
PREDECESSOR = "V_CalcRefdef"

WALK = r"""
import ida_bytes, ida_funcs, ida_name, ida_segment, ida_ua, idaapi, idautils, idc, re

GL_FOG_MODE = 0x0B65
GL_LINEAR = 0x2601
GL_FOG_COLOR = 0x0B66
GL_FOG_START = 0x0B63
GL_FOG_END = 0x0B64
FLOAT_BYTES = 4
RGB_COMPONENTS = 3
RGB_BYTES = FLOAT_BYTES * RGB_COMPONENTS
X86_ADDRESS_BYTES = 4
X86_U32_MASK = 0xFFFFFFFF

def function_items(ea):
    func = ida_funcs.get_func(ea)
    if func is None or int(func.start_ea) != ea:
        return []
    return [int(item) for item in idautils.FuncItems(ea)
            if int(func.start_ea) <= int(item) < int(func.end_ea)]

def decoded(ea):
    insn = ida_ua.insn_t()
    if ida_ua.decode_insn(insn, ea) <= 0:
        raise ValueError('undecodable instruction at %x' % ea)
    return insn

def mnemonic(ea):
    return (idc.print_insn_mnem(ea) or '').lower()

def operand(ea, index):
    return (idc.print_operand(ea, index) or '').lower()

def writable(ea, size=FLOAT_BYTES):
    seg = ida_segment.getseg(ea)
    return (seg is not None and bool(seg.perm & ida_segment.SEGPERM_WRITE)
            and ea >= int(seg.start_ea) and ea + size <= int(seg.end_ea))

def global_reference(ea):
    # Return the object and the exact instruction displacement that locates it.
    insn = decoded(ea)
    fields = [int(op.offb) for op in insn.ops
              if op.type in (ida_ua.o_mem, ida_ua.o_displ) and op.offb
              and int(op.offb) + X86_ADDRESS_BYTES <= insn.size]
    if len(fields) != 1:
        return None
    targets = []
    for ref in idautils.DataRefsFrom(ea):
        ref = int(ref)
        seg = ida_segment.getseg(ref)
        if seg is None:
            continue
        if ida_segment.get_segm_name(seg) in ('.got', '.got.plt'):
            if not all(ida_bytes.is_loaded(ref + offset) for offset in range(X86_ADDRESS_BYTES)):
                continue
            target = int(ida_bytes.get_dword(ref))
            if writable(target):
                targets.append(target)
        elif writable(ref):
            targets.append(ref)
    if len(set(targets)) != 1:
        return None
    return {'gv_ea': hex(targets[0]), 'insn_ea': hex(ea),
            'insn_len': hex(insn.size), 'insn_disp': hex(fields[0])}

def register_base(ea, index):
    insn = decoded(ea)
    op = insn.ops[index]
    if op.type not in (ida_ua.o_phrase, ida_ua.o_displ) or int(op.addr) & X86_U32_MASK:
        return None
    text = operand(ea, index)
    match = re.search(r'\[(e(?:ax|bx|cx|dx|si|di|bp|sp))(?:\+0)?\]', text)
    return match.group(1) if match else None

def pointer_definition(items, before, register):
    for ea in reversed(items[:before]):
        insn = decoded(ea)
        if insn.ops[0].type != ida_ua.o_reg or operand(ea, 0) != register:
            continue
        if mnemonic(ea) not in ('lea', 'mov'):
            return None
        return global_reference(ea)
    return None

def immediate_values(items, begin, end):
    result = set()
    for ea in items[begin:end]:
        insn = decoded(ea)
        for op in insn.ops:
            if op.type == ida_ua.o_imm:
                result.add(int(op.value) & X86_U32_MASK)
    return result

def call_api(items, index):
    ea = items[index]
    if mnemonic(ea) != 'call':
        return None
    line = (idc.generate_disasm_line(ea, 0) or '').lower()
    if 'glfogfv' in line:
        return 'glFogfv'
    if 'glfogi' in line:
        return 'glFogi'
    if 'glfogf' in line:
        return 'glFogf'
    insn = decoded(ea)
    if insn.ops[0].type != ida_ua.o_reg:
        return None
    register = operand(ea, 0)
    for prior in reversed(items[:index]):
        source = decoded(prior)
        if source.ops[0].type != ida_ua.o_reg or operand(prior, 0) != register:
            continue
        if mnemonic(prior) == 'mov' and 'glfogf' in (idc.generate_disasm_line(prior, 0) or '').lower():
            return 'glFogf'
        break
    return None

def previous_call(items, index):
    for prior in range(index - 1, -1, -1):
        if mnemonic(items[prior]) == 'call':
            return prior
    return -1

def fog_groups(items):
    calls = [(index, call_api(items, index)) for index in range(len(items))
             if mnemonic(items[index]) == 'call']
    modes = [index for index, api in calls if api == 'glFogi'
             and {GL_FOG_MODE, GL_LINEAR} <= immediate_values(items, previous_call(items, index) + 1, index)]
    colours = [index for index, api in calls if api == 'glFogfv'
               and GL_FOG_COLOR in immediate_values(items, previous_call(items, index) + 1, index)]
    starts = [index for index, api in calls if api == 'glFogf'
              and GL_FOG_START in immediate_values(items, previous_call(items, index) + 1, index)]
    ends = [index for index, api in calls if api == 'glFogf'
            and GL_FOG_END in immediate_values(items, previous_call(items, index) + 1, index)]
    groups = [(mode, colour, start, end)
              for mode in modes for colour in colours for start in starts for end in ends
              if mode < colour < start < end]
    return groups

def float_source_offsets(items, begin, end, register):
    offsets = set()
    for ea in items[begin:end]:
        if mnemonic(ea) not in ('fdivr', 'fdiv', 'fmul', 'fmulp'):
            continue
        insn = decoded(ea)
        for index, op in enumerate(insn.ops):
            if op.type not in (ida_ua.o_phrase, ida_ua.o_displ):
                continue
            text = operand(ea, index)
            if not re.search(r'\[' + register + r'(?:\+|\])', text):
                continue
            offsets.add(int(op.addr) & X86_U32_MASK)
    return offsets

def colour_global(items, mode, colour):
    begin, end = mode + 1, colour
    direct = []
    for ea in items[begin:end]:
        insn = decoded(ea)
        if (mnemonic(ea) == 'movss' and insn.ops[0].type == ida_ua.o_reg
                and insn.ops[1].type == ida_ua.o_mem):
            located = global_reference(ea)
            if located:
                direct.append(located)
    if direct:
        addresses = [int(item['gv_ea'], 0) for item in direct]
        divides = sum(mnemonic(ea) == 'divss' for ea in items[begin:end])
        expected_addresses = list(range(addresses[0], addresses[0] + RGB_BYTES, FLOAT_BYTES)) if addresses else []
        if len(addresses) != RGB_COMPONENTS or divides != RGB_COMPONENTS or addresses != expected_addresses:
            raise ValueError('GL_FOG_COLOR scalar loads do not form three scaled components')
        if not writable(addresses[0], RGB_BYTES):
            raise ValueError('GL_FOG_COLOR array is not writable')
        return direct[0]
    candidates = []
    for ea in items[begin:end]:
        insn = decoded(ea)
        if mnemonic(ea) not in ('mov', 'lea') or insn.ops[0].type != ida_ua.o_reg:
            continue
        located = global_reference(ea)
        if not located or not writable(int(located['gv_ea'], 0), RGB_BYTES):
            continue
        register = operand(ea, 0)
        source_offsets = float_source_offsets(items, begin, end, register)
        if set(range(0, RGB_BYTES, FLOAT_BYTES)) <= source_offsets:
            candidates.append(located)
    if len(candidates) != 1:
        raise ValueError('GL_FOG_COLOR pointer candidates: %r' % candidates)
    return candidates[0]

def feeds_argument(items, read_index, enum_index, register):
    for ea in items[read_index + 1:enum_index]:
        insn = decoded(ea)
        if mnemonic(ea) == 'push' and operand(ea, 0) == register:
            return True
        if (mnemonic(ea) in ('mov', 'movss') and insn.ops[1].type == ida_ua.o_reg
                and operand(ea, 1) == register and '[esp' in operand(ea, 0)):
            return True
    return False

def scalar_global(items, call_index, enum_value):
    begin = previous_call(items, call_index) + 1
    enum_indices = [index for index in range(begin, call_index)
                    if enum_value in immediate_values(items, index, index + 1)]
    if len(enum_indices) != 1:
        raise ValueError('fog scalar GL enum is ambiguous: %x' % enum_value)
    enum_index = enum_indices[0]
    candidates = []
    for index in range(begin, enum_index):
        ea = items[index]
        insn = decoded(ea)
        if (mnemonic(ea) not in ('mov', 'movss') or insn.ops[0].type != ida_ua.o_reg
                or insn.ops[1].type not in (ida_ua.o_mem, ida_ua.o_phrase, ida_ua.o_displ)):
            continue
        target_reg = operand(ea, 0)
        if not feeds_argument(items, index, enum_index, target_reg):
            continue
        located = global_reference(ea)
        if located is None:
            base = register_base(ea, 1)
            if base and base != 'esp':
                located = pointer_definition(items, index, base)
        if located:
            candidates.append(located)
    if len(candidates) != 1:
        raise ValueError('fog scalar argument candidates for %x: %r' % (enum_value, candidates))
    return candidates[0]

def located_normal(refdef):
    caller_items = function_items(refdef)
    if not caller_items:
        raise ValueError('V_CalcRefdef is not an exact function start')
    candidates = []
    for ea in caller_items:
        if mnemonic(ea) != 'call':
            continue
        insn = decoded(ea)
        if insn.ops[0].type != ida_ua.o_near:
            continue
        target = resolve_elf_plt(int(insn.ops[0].addr))
        callee_items = function_items(target)
        if not callee_items:
            continue
        groups = fog_groups(callee_items)
        if len(groups) != 1:
            continue
        mode, colour, start, end = groups[0]
        try:
            globals_found = {
                'g_iFogColor': colour_global(callee_items, mode, colour),
                'g_iStartDist': scalar_global(callee_items, start, GL_FOG_START),
                'g_iEndDist': scalar_global(callee_items, end, GL_FOG_END),
            }
        except ValueError:
            continue
        addresses = [int(item['gv_ea'], 0) for item in globals_found.values()]
        if len(set(addresses)) != 3:
            continue
        candidates.append({'target': hex(target), 'globals': globals_found,
                           'calls': [hex(callee_items[index]) for index in groups[0]]})
    if len(candidates) != 1:
        raise ValueError('V_CalcNormalRefdef candidates: %r' % candidates)
    return candidates[0]

result = located_normal(int(values['refdef']))
"""


async def preprocess_skill(
    session, skill_name, expected_outputs, old_yaml_map, new_binary_dir, platform, image_base, debug=False
):
    _ = old_yaml_map
    if platform not in {"windows", "linux"}:
        return False
    if any(_output_for_symbol(expected_outputs, name) is None for name in (FUNCTION, *GLOBALS)):
        return False
    predecessor = await inspect_owner_artifact(session, new_binary_dir, platform, image_base, PREDECESSOR)
    if predecessor is None:
        return False
    try:
        found = await run_layout_walk(session, {"refdef": predecessor["owner_ea"]}, WALK)
        target = int(found["target"], 0)
        function = await _inspect_function_via_mcp(session, target, image_base, FUNCTION)
        across = function is None
        if across:
            function = await _inspect_function_via_mcp(
                session, target, image_base, FUNCTION, allow_across_function_boundary=True
            )
        if not function or int(function["func_va"], 0) != target:
            return False
        owner = {
            "owner_ea": target,
            "owner_end": target + int(function["func_size"], 0),
            "function": function,
            "allow_across": across,
        }
        if not await write_located_globals(session, expected_outputs, platform, image_base, owner, found["globals"]):
            return False
        output = _output_for_symbol(expected_outputs, FUNCTION)
        payload = {key: function[key] for key in ("func_name", "func_va", "func_rva", "func_size", "func_sig")}
        if across:
            payload["func_sig_allow_across_function_boundary"] = True
        write_func_yaml(Path(output), payload)
        if debug:
            print(f"{skill_name}: located {found}")
        return True
    except (KeyError, TypeError, ValueError) as exc:
        if debug:
            print(f"{skill_name}: {exc}")
        return False
