#!/usr/bin/env python3
"""Identify retained initializer copies that reference the console callback.

HL Linux and Sven inline launcher initialization into Sys_InitGame but keep
two out-of-line bodies referencing the slot and a local function pointer.
Use neutral ordinal identities: stripped Sven builds have identical bodies
whose original names cannot be distinguished from current-binary evidence.
"""

import json
from pathlib import Path

from ida_elf import ELF_RESOLVER_PY
from ida_analyze_util import (
    _inspect_function_via_mcp,
    _load_yaml_mapping,
    _output_for_symbol,
    parse_mcp_result,
    write_func_yaml,
)

INITIALIZER_NAMES = ["Launcher_ConsolePrintf_Initializer_0", "Launcher_ConsolePrintf_Initializer_1"]
LOCATE_PY = (
    ELF_RESOLVER_PY
    + r"""
import ida_bytes, ida_funcs, ida_segment, idaapi, idautils, json
gv = GV_PLACEHOLDER
owner = OWNER_PLACEHOLDER
result = []
if not idaapi.inf_is_64bit():
    excluded = {owner}
    for item in idautils.Strings():
        text = str(item)
        if 'FATAL ERROR (shutting down): %s' not in text and 'ERROR: %s' not in text:
            continue
        for source in elf_data_refs_to(item.ea):
            function = ida_funcs.get_func(source)
            if function is not None:
                excluded.add(int(function.start_ea))
    candidates = set()
    for source in elf_data_refs_to(gv):
        function = ida_funcs.get_func(source)
        if function is not None and int(function.start_ea) not in excluded:
            candidates.add(int(function.start_ea))
    for ea in sorted(candidates):
        function_pointers = set()
        for insn_ea in idautils.FuncItems(ea):
            for target in idautils.DataRefsFrom(insn_ea):
                segment = ida_segment.getseg(target)
                if segment is not None and ida_segment.get_segm_name(segment) in ('.got', '.got.plt'):
                    loaded = True
                    for offset in range(4):
                        if not ida_bytes.is_loaded(target + offset):
                            loaded = False
                            break
                    if not loaded:
                        continue
                    target = int(ida_bytes.get_dword(target))
                    segment = ida_segment.getseg(target)
                callback = ida_funcs.get_func(target)
                if (segment is not None and segment.perm & ida_segment.SEGPERM_EXEC
                        and callback is not None and int(callback.start_ea) == target):
                    function_pointers.add(int(target))
        if function_pointers:
            result.append(hex(ea))
json.dumps(result)
"""
)


async def preprocess_skill(
    session, skill_name, expected_outputs, old_yaml_map, new_binary_dir, platform, image_base, debug=False
):
    _ = old_yaml_map
    if not new_binary_dir:
        return False
    callback = _load_yaml_mapping(Path(new_binary_dir) / f"Launcher_ConsolePrintf.{platform}.yaml")
    owner = _load_yaml_mapping(Path(new_binary_dir) / f"Sys_InitGame.{platform}.yaml")
    if (
        not callback
        or callback.get("gv_name") != "Launcher_ConsolePrintf"
        or not owner
        or owner.get("func_name") != "Sys_InitGame"
    ):
        return False
    code = LOCATE_PY.replace("GV_PLACEHOLDER", str(int(callback["gv_va"], 0))).replace(
        "OWNER_PLACEHOLDER", str(int(owner["func_va"], 0))
    )
    located = parse_mcp_result(await session.call_tool("py_eval", {"code": code}))
    if isinstance(located, str):
        located = json.loads(located)
    if debug:
        print(f"{skill_name}: initializer candidates={located}")
    if not isinstance(located, list) or len(located) != len(INITIALIZER_NAMES) or len(set(located)) != len(located):
        return False
    prepared = {}
    for name, ea in zip(INITIALIZER_NAMES, located):
        output = _output_for_symbol(expected_outputs, name)
        function = await _inspect_function_via_mcp(
            session, int(ea, 0), image_base, name, allow_across_function_boundary=True
        )
        if output is None or not function:
            if debug:
                print(f"{skill_name}: no unique function signature for {name} at {ea}")
            return False
        function["func_sig_allow_across_function_boundary"] = True
        prepared[output] = function
    for output, function in prepared.items():
        write_func_yaml(output, function)
    return True
