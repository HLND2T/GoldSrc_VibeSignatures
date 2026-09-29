#!/usr/bin/env python3
"""Find the multiplayer options-page constructor.

SpraypaintList belongs to the constructor in every target. CoF's IDA database
marks the reference as code but leaves its large enclosing routine without a
function owner. Recover that routine from return boundaries, then verify its
COptionsSubMultiplayer RTTI vptr store before creating or reusing the IDA function.
"""

from pathlib import Path

from ida_analyze_util import _output_for_symbol, preprocess_common_skill, write_func_yaml
from ida_preprocessor_scripts._client_vgui_private_common import inspect_unique_function, run_walk
from ida_preprocessor_scripts._gameui_dialog_common import prepare_c_strings


TARGET = "COptionsSubMultiplayer_ctor"
REAL_NAME = "COptionsSubMultiplayer::COptionsSubMultiplayer(vgui2::Panel*)"


async def preprocess_skill(
    session, skill_name, expected_outputs, old_yaml_map, new_binary_dir, platform, image_base, debug=False
):
    _ = skill_name, old_yaml_map
    if not await prepare_c_strings(session):
        return False
    output = _output_for_symbol(expected_outputs, TARGET)
    if output is None:
        return False
    if Path(new_binary_dir).parent.name != "cof-5936":
        found = await preprocess_common_skill(
            session,
            expected_outputs,
            old_yaml_map=None,
            new_binary_dir=new_binary_dir,
            platform=platform,
            image_base=image_base,
            func_names=[TARGET],
            func_xrefs=[{"func_name": TARGET, "xref_strings": ["FULLMATCH:SpraypaintList"]}],
            generate_yaml_desired_fields=[
                (
                    TARGET,
                    [
                        "func_name",
                        "func_va",
                        "func_rva",
                        "func_size",
                        "func_sig",
                        "func_sig_allow_across_function_boundary:true",
                    ],
                )
            ],
            debug=debug,
        )
        if not found:
            return False
        from ida_analyze_util import _load_yaml_mapping

        data = _load_yaml_mapping(output)
        if data is None:
            return False
        data["func_name"] = REAL_NAME
        write_func_yaml(output, data)
        return True

    found = await run_walk(
        session,
        """
import ida_name
table = int(ida_name.get_name_ea(idaapi.BADADDR, '??_7COptionsSubMultiplayer@@6B@'))
if table == idaapi.BADADDR or not valid_vtable_slots(table, maximum=256):
    raise ValueError('CoF multiplayer RTTI vtable missing or invalid')
spray = exact_string_eas('SpraypaintList')
if len(spray) != 1:
    raise ValueError('SpraypaintList literal is not unique')
sites = sorted({int(x.frm) for x in idautils.XrefsTo(spray[0], 0)
                if ida_bytes.is_code(ida_bytes.get_flags(int(x.frm)))})
if len(sites) != 1:
    raise ValueError('SpraypaintList has no unique executable reference')
site = sites[0]
segment = ida_segment.getseg(site)
if segment is None or not segment.perm & ida_segment.SEGPERM_EXEC:
    raise ValueError('SpraypaintList reference is outside executable code')
cursor = site
while cursor > segment.start_ea:
    cursor = int(ida_bytes.prev_head(cursor, segment.start_ea))
    if cursor == idaapi.BADADDR:
        raise ValueError('previous return boundary missing')
    if idc.print_insn_mnem(cursor).lower() in ('ret', 'retn'):
        break
else:
    raise ValueError('previous return boundary missing')
entry = int(ida_bytes.next_head(cursor, site))
if idc.print_insn_mnem(entry).lower() != 'push':
    raise ValueError('constructor entry does not begin with a prologue')
cursor = site
while cursor < segment.end_ea:
    if idc.print_insn_mnem(cursor).lower() in ('ret', 'retn'):
        break
    cursor = int(ida_bytes.next_head(cursor, segment.end_ea))
    if cursor == idaapi.BADADDR:
        raise ValueError('following return boundary missing')
else:
    raise ValueError('following return boundary missing')
last = cursor
end = int(ida_bytes.next_head(last, segment.end_ea))
stores = sorted({int(x.frm) for x in idautils.XrefsTo(table, 0)
                 if entry < int(x.frm) < site})
if len(stores) != 1:
    raise ValueError('constructor RTTI vptr store is not unique: '+repr(stores))
instruction = idautils.DecodeInstruction(stores[0])
if (instruction is None or instruction.get_canon_mnem() != 'mov'
        or instruction.ops[0].type not in (ida_ua.o_phrase, ida_ua.o_displ)
        or instruction.ops[1].type != ida_ua.o_imm
        or imm_value(instruction.ops[1]) != table):
    raise ValueError('RTTI reference is not a constructor vptr store')
function = ida_funcs.get_func(site)
if function is None:
    if not ida_funcs.add_func(entry, end):
        raise ValueError('unable to restore CoF constructor function')
    function = ida_funcs.get_func(site)
if function is None or int(function.start_ea) != entry or int(function.end_ea) != end:
    raise ValueError('CoF function does not match the validated constructor boundaries')
result = {'target': entry, 'vtable': table, 'literal_site': site, 'vptr_site': stores[0], 'end': end}
""",
        {},
    )
    if found.get("error") or not isinstance(found.get("target"), int):
        if debug:
            print(f"  CoF multiplayer page validation failed: {found}")
        return False
    inspected = await inspect_unique_function(session, REAL_NAME, found["target"], image_base, debug)
    if inspected is None:
        return False
    write_func_yaml(output, inspected)
    return True
