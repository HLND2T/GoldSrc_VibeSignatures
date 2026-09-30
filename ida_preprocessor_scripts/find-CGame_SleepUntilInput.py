#!/usr/bin/env python3
"""Inherit CGame::SleepUntilInput; omit signatures for native short wait bodies.

The current interface slot and CGame table prove the callable entry. Recover
missing IDA function boundaries through the existing exact-entry inspector.
Per issue #303 approval, the native MsgWaitForMultipleObjects wrapper has no
func_sig; SDL event loops retain normal unique signatures. No version list,
fixed slot or function-size threshold controls this policy.
"""

from ida_analyze_util import (
    _load_yaml_mapping,
    _output_for_symbol,
    build_runtime_address_inspection_py_eval,
    parse_mcp_result,
    preprocess_common_skill,
    write_func_yaml,
)
from ida_preprocessor_scripts._engine_private_globals_common import run_walk
from ida_preprocessor_scripts._vgui_paint_common import artifact

INSPECT_WAIT = r"""
import ida_funcs, ida_nalt, ida_ua, idautils, idc
entry = values['entry']
fn = ida_funcs.get_func(entry)
if fn is None or int(fn.start_ea) != entry:
    raise ValueError('inherited entry has no exact function boundary')
imports = set()
def collect(ea, name, ordinal):
    if name == 'MsgWaitForMultipleObjects':
        imports.add(int(ea))
    return True
for index in range(ida_nalt.get_import_module_qty()):
    ida_nalt.enum_import_names(index, collect)
dispatches = []
for ea in idautils.FuncItems(entry):
    if idc.print_insn_mnem(ea) not in ('call', 'jmp'):
        continue
    target = int(idc.get_operand_value(ea, 0))
    target_fn = ida_funcs.get_func(target)
    if target_fn is not None and target_fn.flags & ida_funcs.FUNC_THUNK:
        resolved, slot = ida_funcs.calc_thunk_func_target(target_fn)
        native = int(resolved) in imports or int(slot) in imports
    else:
        native = target in imports and idc.get_operand_type(ea, 0) in (ida_ua.o_mem, ida_ua.o_near)
    dispatches.append(native)
result = dict(native_wait=values['platform'] == 'windows' and dispatches == [True])
"""


async def preprocess_skill(
    session, skill_name, expected_outputs, old_yaml_map, new_binary_dir, platform, image_base, debug=False
):
    _ = old_yaml_map
    name = "CGame_SleepUntilInput"
    slot = artifact(new_binary_dir, "IGame_SleepUntilInput", platform)
    table = artifact(new_binary_dir, "CGame_vtable", platform)
    if platform not in {"windows", "linux"} or not slot or not table or table.get("vtable_class") != "CGame":
        return False
    try:
        index = slot["vfunc_index"]
        if (
            isinstance(index, bool)
            or not isinstance(index, int)
            or index < 0
            or int(slot["vfunc_offset"], 0) != index * 4
        ):
            return False
        entries = table["vtable_entries"]
        entry = int(entries.get(index, entries.get(str(index))), 0)
    except (KeyError, TypeError, ValueError):
        return False
    inspection = parse_mcp_result(
        await session.call_tool(
            "py_eval", {"code": build_runtime_address_inspection_py_eval(entry, require_function=True)}
        )
    )
    if not isinstance(inspection, dict) or not inspection.get("is_function_start"):
        return False
    policy = await run_walk(session, INSPECT_WAIT, {"entry": entry, "platform": platform})
    if not isinstance(policy.get("native_wait"), bool):
        return False
    signature = not policy["native_wait"]
    fields = ["func_name", "func_va", "func_rva", "func_size", "vtable_name", "vfunc_offset", "vfunc_index"]
    if signature:
        fields.append("func_sig")
    found = await preprocess_common_skill(
        session=session,
        expected_outputs=expected_outputs,
        old_yaml_map=None,
        new_binary_dir=new_binary_dir,
        platform=platform,
        image_base=image_base,
        inherit_vfuncs=[(name, "CGame_vtable", "IGame_SleepUntilInput", signature)],
        generate_yaml_desired_fields=[(name, fields)],
        debug=debug,
    )
    if not found:
        return False
    output = _output_for_symbol(expected_outputs, name)
    data = _load_yaml_mapping(output)
    if not data:
        return False
    data.update(func_name="CGame::SleepUntilInput", vtable_name="CGame")
    write_func_yaml(output, data)
    if debug:
        print(f"{skill_name}: native_wait={policy['native_wait']} func_sig={signature}")
    return True
