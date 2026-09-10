#!/usr/bin/env python3
"""Resolve CS's unique inner-player virtual slot from its prediction wrapper.

CGameStudioModelRenderer::StudioDrawPlayer saves/setup/restores local-player
animation around _StudioDrawPlayer. The wrapper has one distinct indirect
virtual slot, even when GCC turns the early returns into tail jumps. Use the
current vtable and require a unique runtime signature for the resolved entry.
"""

from pathlib import Path

from ida_analyze_util import (
    _inspect_function_via_mcp,
    _load_yaml_mapping,
    _output_for_symbol,
    parse_mcp_result,
    write_func_yaml,
)
from ida_preprocessor_scripts._indirect_vcall_target_common import _SCAN_TEMPLATE


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
    _ = skill_name, old_yaml_map, debug
    directory = Path(new_binary_dir)
    owner = _load_yaml_mapping(directory / f"GameStudioRenderer_StudioDrawPlayer.{platform}.yaml")
    table = _load_yaml_mapping(directory / f"GameStudioRenderer_vtable.{platform}.yaml")
    if not owner or not table:
        return False
    code = (
        _SCAN_TEMPLATE.replace("SOURCE_VA_PLACEHOLDER", str(int(owner["func_va"], 0)))
        .replace("ALLOWED_PLACEHOLDER", repr(["call", "jmp"]))
        .replace("RESOLVE_LOAD_PLACEHOLDER", "True")
    )
    result = parse_mcp_result(await session.call_tool("py_eval", {"code": code}))
    if not isinstance(result, dict) or result.get("pointer_size") != 4 or len(result.get("targets", [])) != 1:
        return False
    slot = result["targets"][0]
    index = int(slot["vfunc_index"])
    entries = table.get("vtable_entries", {})
    value = entries.get(index, entries.get(str(index)))
    if value is None:
        return False
    name = "GameStudioRenderer__StudioDrawPlayer"
    function = await _inspect_function_via_mcp(session, int(value, 0), image_base, name)
    output = _output_for_symbol(expected_outputs, name)
    if not function or not output:
        return False
    payload = {key: function[key] for key in ("func_name", "func_va", "func_rva", "func_size")}
    payload.update(
        vtable_name="GameStudioRenderer", vfunc_offset=hex(index * 4), vfunc_index=index, vfunc_sig=function["func_sig"]
    )
    write_func_yaml(output, payload)
    return True
