"""Locate the Sven client's copy of the engine function table.

The exported ``Initialize`` copies the engine-provided table into ``gEngfuncs``.
Both Sven builds copy 0x86 x86 words and require interface version 7.  The
destination is recovered from that copy, not from a particular event-API
forwarder or from the table's address in another build.  The 8948 ELF symbol
table independently identifies the destination as ``gEngfuncs`` (536 bytes).
"""

from ida_preprocessor_scripts._direct_gv_common import write_located_globals
from ida_preprocessor_scripts._engine_private_globals_common import owner_context, run_walk

NAME = "gEngfuncs"

WALK = r"""
CLIENT_ENGINE_FUNCS_WORDS = 0x86
CLIENT_INTERFACE_VERSION = 7
COPY_SETUP_INSTRUCTIONS = 12
REP_MOVSD = b'\xf3\xa5'
exports = []
for _, _, ea, name in idautils.Entries():
    function = ida_funcs.get_func(int(ea))
    if name == 'Initialize' and function and int(function.start_ea) == int(ea):
        exports.append(int(ea))
if len(set(exports)) != 1:
    result = {'error': 'expected one exported Initialize', 'exports': [hex(ea) for ea in exports]}
else:
    start = exports[0]
    entries = scan(start)
    if entries is None:
        result = {'error': 'Initialize is not an exact function start'}
    else:
        versions = []
        copies = []
        for index, entry in enumerate(entries):
            insn = entry['insn']
            immediates = [int(op.value) for op in insn.ops if int(op.type) == int(idaapi.o_imm)]
            if entry['mnem'] == 'cmp' and CLIENT_INTERFACE_VERSION in immediates:
                versions.append(entry['ea'])
            if ida_bytes.get_bytes(entry['ea'], entry['len']) != REP_MOVSD:
                continue
            before = entries[max(0, index - COPY_SETUP_INSTRUCTIONS):index]
            if not any(CLIENT_ENGINE_FUNCS_WORDS in [int(op.value) for op in item['insn'].ops
                                  if int(op.type) == int(idaapi.o_imm)] for item in before):
                continue
            candidates = []
            for pos, item in enumerate(before):
                decoded = item['insn']
                if item['mnem'] not in ('mov', 'lea') or int(decoded.ops[0].type) != int(idaapi.o_reg):
                    continue
                register = reg4(decoded.ops[0])
                if register not in ('edi', 'edx'):
                    continue
                address = None
                if len(item['targets']) == 1:
                    address = next(iter(item['targets']))
                elif int(decoded.ops[1].type) == int(idaapi.o_imm):
                    immediate = int(decoded.ops[1].value)
                    if is_writable_data(immediate):
                        address = immediate
                if address is None or not item['disp']:
                    continue
                if register == 'edx' and not any(
                    later['mnem'] == 'mov' and
                    reg4(later['insn'].ops[0]) == 'edi' and
                    reg4(later['insn'].ops[1]) == 'edx'
                    for later in before[pos + 1:]
                ):
                    continue
                candidates.append((address, item))
            if len(candidates) == 1:
                copies.append(candidates[0])
        addresses = {address for address, _ in copies}
        if not versions or not copies or len(addresses) != 1:
            result = {'error': 'Initialize table copy is ambiguous',
                      'version_checks': [hex(ea) for ea in versions],
                      'destinations': [hex(address) for address in addresses]}
        else:
            address, instruction = copies[0]
            result = {'owner': hex(start), 'global': access(instruction, address),
                      'copy_sites': [hex(item['ea']) for _, item in copies]}
"""


async def preprocess_skill(
    session, skill_name, expected_outputs, old_yaml_map, new_binary_dir, platform, image_base, debug=False
):
    _ = old_yaml_map, new_binary_dir
    if platform not in {"windows", "linux"}:
        return False
    located = await run_walk(session, WALK)
    if located.get("error") or not located.get("global"):
        if debug:
            print(f"{skill_name}: {located}")
        return False
    owner = await owner_context(session, int(located["owner"], 0), image_base, "Initialize")
    if owner is None:
        return False
    if debug:
        print(f"{skill_name}: {located}")
    return await write_located_globals(
        session, expected_outputs, platform, image_base, owner, {NAME: located["global"]}
    )
