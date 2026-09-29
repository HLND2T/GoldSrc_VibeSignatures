#!/usr/bin/env python3
"""Recover the client mouse guards from the verified IN_Accumulate callback.

The source camera guard reads iMouseInUse before asking the VGUI surface about
cursor visibility. HL and Cry of Fear also read g_iVisibleMouse: that object has
a viewport writer which stores both Boolean values and calls
vgui::App::getInstance. CS/CZ retain an unused ELF object with that name but no
matching reader or writer, so those configs request only iMouseInUse.

The reader is an exact export, or slot 13 of the verified 43-entry client blob
ABI. A zero-test must branch to the callback's early return, and the selected
object must have current-binary 0/1 writers. Windows uses absolute operands;
HL 8684 ELF uses R_386_32 relocations, while HL25 ELF uses local absolute
operands. The generated signature only validates the selected instruction.
"""

from ida_analyze_util import _output_for_symbol
from ida_preprocessor_scripts._direct_gv_common import inspect_owner_artifact, write_located_globals
from ida_preprocessor_scripts._engine_private_globals_common import run_walk

ACCUMULATE = "IN_Accumulate"
CAMERA_GUARD = "iMouseInUse"
CURSOR_GUARD = "g_iVisibleMouse"

WALK = r"""
import ida_name, ida_ua

owner = int(values['accumulate'])
exports = {int(ea) for _, _, ea, name in idautils.Entries() if name == 'IN_Accumulate'}
if exports and exports != {owner}:
    raise ValueError('IN_Accumulate export identity changed')
entries = scan(owner)
if entries is None:
    raise ValueError('IN_Accumulate has no decoded function body')


def operand_size(op):
    return int(ida_ua.get_dtype_size(op.dtype))


def early_return(ea):
    for _ in range(5):
        mnemonic = (idc.print_insn_mnem(ea) or '').lower()
        if mnemonic in ('ret', 'retn'):
            return True
        if mnemonic in ('nop', 'pop', 'leave'):
            pass
        elif mnemonic == 'add' and idc.print_operand(ea, 0).lower() == 'esp':
            pass
        elif (mnemonic == 'mov' and idc.print_operand(ea, 0).lower() == 'esp'
              and idc.print_operand(ea, 1).lower() == 'ebp'):
            pass
        else:
            return False
        ea = idc.next_head(ea, idaapi.BADADDR)
    return False


def guard(entry_index):
    entry = entries[entry_index]
    candidates = entry['targets'] - entry['written']
    if len(candidates) != 1 or not entry['disp']:
        return None
    gv = next(iter(candidates))
    if not is_writable_data(gv):
        return None
    insn = entry['insn']
    check_index = entry_index
    if entry['mnem'] == 'cmp':
        if (int(insn.ops[0].type) not in (int(idaapi.o_mem), int(idaapi.o_displ))
                or operand_size(insn.ops[0]) != 4
                or int(insn.ops[1].type) != int(idaapi.o_imm)
                or int(insn.ops[1].value) != 0):
            return None
    elif entry['mnem'] == 'mov':
        if (int(insn.ops[0].type) != int(idaapi.o_reg)
                or int(insn.ops[1].type) not in (int(idaapi.o_mem), int(idaapi.o_displ))
                or operand_size(insn.ops[1]) != 4):
            return None
        register = reg4(insn.ops[0])
        for index in range(entry_index + 1, min(entry_index + 4, len(entries))):
            item = entries[index]
            probe = item['insn']
            if (item['mnem'] == 'test'
                    and int(probe.ops[0].type) == int(idaapi.o_reg)
                    and int(probe.ops[1].type) == int(idaapi.o_reg)
                    and reg4(probe.ops[0]) == register == reg4(probe.ops[1])):
                check_index = index
                break
            if (int(probe.ops[0].type) == int(idaapi.o_reg)
                    and reg4(probe.ops[0]) == register and changed_operand(probe, 0)):
                return None
        if check_index == entry_index:
            return None
    else:
        return None
    if check_index + 1 >= len(entries):
        return None
    branch = entries[check_index + 1]
    if branch['mnem'] not in ('je', 'jz', 'jne', 'jnz'):
        return None
    target = int(idc.get_operand_value(branch['ea'], 0))
    fallthrough = int(branch['ea'] + branch['len'])
    if early_return(target) == early_return(fallthrough):
        return None
    return gv


def code_owners(gv):
    owners = set()
    for ref in idautils.XrefsTo(gv, 0):
        sites = [int(ref.frm)]
        if is_got(ref.frm):
            if int(ida_bytes.get_dword(ref.frm)) != gv:
                continue
            sites = [int(site.frm) for site in idautils.XrefsTo(ref.frm, 0)]
        for site in sites:
            function = ida_funcs.get_func(site)
            if function is not None and is_code_address(site):
                owners.add(int(function.start_ea))
    return owners


def calls_vgui_app(body):
    names = {'?getInstance@App@vgui@@SAPAV12@XZ', '_ZN4vgui3App11getInstanceEv'}
    for entry in body:
        if entry['mnem'] != 'call':
            continue
        operand = entry['insn'].ops[0]
        if int(operand.type) in (int(idaapi.o_near), int(idaapi.o_far)):
            if ida_name.get_name(int(operand.addr)).removeprefix('.') in names:
                return True
    return False


def source_constant(body, index):
    source = body[index]['insn'].ops[1]
    if int(source.type) == int(idaapi.o_imm):
        return int(source.value) & 0xffffffff
    if int(source.type) != int(idaapi.o_reg):
        return None
    register = reg4(source)
    for previous in reversed(body[max(0, index - 8):index]):
        if previous['mnem'] == 'call' or previous['mnem'].startswith('j'):
            return None
        instruction = previous['insn']
        destination = instruction.ops[0]
        if (int(destination.type) != int(idaapi.o_reg)
                or reg4(destination) != register or not changed_operand(instruction, 0)):
            continue
        origin = instruction.ops[1]
        if previous['mnem'] == 'mov' and int(origin.type) == int(idaapi.o_imm):
            return int(origin.value) & 0xffffffff
        if (previous['mnem'] == 'xor' and int(origin.type) == int(idaapi.o_reg)
                and reg4(origin) == register):
            return 0
        return None
    return None


def writer_evidence(gv):
    found = []
    values = set()
    for start in sorted(code_owners(gv) - {owner}):
        body = scan(start)
        if body is None:
            continue
        constants = set()
        for index, entry in enumerate(body):
            if gv in entry['written'] and entry['mnem'] == 'mov':
                value = source_constant(body, index)
                if value in (0, 1):
                    constants.add(value)
        values.update(constants)
        if {0, 1} <= constants:
            found.append((start, calls_vgui_app(body)))
    return found, values


def unowned_writer_values(gv):
    # Old decrypted blobs may decode the camera store as code without creating
    # its containing function. Validate the immediate source in the same local
    # instruction run rather than inventing a function boundary.
    values = set()
    sites = []
    for ref in idautils.XrefsTo(gv, 0):
        site = int(ref.frm)
        if ida_funcs.get_func(site) is not None or not is_code_address(site):
            continue
        if (idc.print_insn_mnem(site) or '').lower() != 'mov':
            continue
        insn = idautils.DecodeInstruction(site)
        if (insn is None or int(insn.ops[0].type) != int(idaapi.o_mem)
                or int(insn.ops[0].addr) != gv or operand_size(insn.ops[0]) != 4
                or not changed_operand(insn, 0)):
            continue
        source = insn.ops[1]
        value = None
        if int(source.type) == int(idaapi.o_imm):
            value = int(source.value) & 0xffffffff
        elif int(source.type) == int(idaapi.o_reg):
            register = reg4(source)
            cursor = site
            for _ in range(8):
                previous = int(idc.prev_head(cursor, 0))
                if not is_code_address(previous) or ida_funcs.get_func(previous) is not None:
                    break
                mnemonic = (idc.print_insn_mnem(previous) or '').lower()
                if mnemonic in ('call', 'ret', 'retn', 'nop', 'int3') or mnemonic.startswith('j'):
                    break
                instruction = idautils.DecodeInstruction(previous)
                if instruction is None:
                    break
                destination = instruction.ops[0]
                if (int(destination.type) == int(idaapi.o_reg)
                        and reg4(destination) == register and changed_operand(instruction, 0)):
                    origin = instruction.ops[1]
                    if mnemonic == 'mov' and int(origin.type) == int(idaapi.o_imm):
                        value = int(origin.value) & 0xffffffff
                    elif (mnemonic == 'xor' and int(origin.type) == int(idaapi.o_reg)
                          and reg4(origin) == register):
                        value = 0
                    break
                cursor = previous
        if value in (0, 1):
            values.add(value)
            sites.append(hex(site))
    return values, sites


guards = []
for index, entry in enumerate(entries):
    gv = guard(index)
    if gv is not None:
        guards.append((gv, entry))

if not guards:
    result = {'error': 'IN_Accumulate has no early-return data guard'}
else:
    # The camera guard is the first source-level guard. Confirm its own 0/1
    # writers and reject a viewport-owned object even if a build reorders it.
    camera_gv, camera_entry = guards[0]
    camera_writers, camera_values = writer_evidence(camera_gv)
    unowned_values, unowned_sites = unowned_writer_values(camera_gv)
    if not {0, 1} <= camera_values | unowned_values or any(app for _, app in camera_writers):
        result = {'error': 'first guard has no camera-state writer',
                  'guards': [hex(gv) for gv, _ in guards]}
    else:
        result = {'globals': {'iMouseInUse': access(camera_entry, camera_gv)},
                  'camera_writers': [hex(start) for start, _ in camera_writers],
                  'unowned_writes': unowned_sites}
        if values['want_cursor']:
            cursor = []
            for gv, entry in guards[1:]:
                writers, _ = writer_evidence(gv)
                for start, app in writers:
                    if app:
                        cursor.append((gv, entry, start))
            if len(cursor) != 1:
                result = {'error': 'viewport cursor guard is absent or ambiguous',
                          'guards': [hex(gv) for gv, _ in guards],
                          'writers': [(hex(gv), hex(start)) for gv, _, start in cursor]}
            else:
                gv, entry, start = cursor[0]
                result['globals']['g_iVisibleMouse'] = access(entry, gv)
                result['cursor_writer'] = hex(start)
"""


async def preprocess_skill(
    session, skill_name, expected_outputs, old_yaml_map, new_binary_dir, platform, image_base, debug=False
):
    _ = old_yaml_map
    if platform not in {"windows", "linux"}:
        return False
    owner = await inspect_owner_artifact(session, new_binary_dir, platform, image_base, ACCUMULATE)
    if owner is None:
        return False
    want_cursor = _output_for_symbol(expected_outputs, CURSOR_GUARD) is not None
    located = await run_walk(session, WALK, {"accumulate": owner["owner_ea"], "want_cursor": want_cursor})
    if debug:
        print(f"{skill_name}: {located}")
    if located.get("error") or not isinstance(located.get("globals"), dict):
        return False
    expected = {CAMERA_GUARD, CURSOR_GUARD} if want_cursor else {CAMERA_GUARD}
    if set(located["globals"]) != expected:
        return False
    return await write_located_globals(session, expected_outputs, platform, image_base, owner, located["globals"])
