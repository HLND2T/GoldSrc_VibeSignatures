"""Shared fail-closed writer for semantic direct global-variable locators."""

from pathlib import Path

from ida_analyze_util import (
    _inspect_function_via_mcp,
    _load_yaml_mapping,
    _output_for_symbol,
    gv_resolution_fields_via_mcp,
    write_gv_yaml,
)


async def inspect_owner_artifact(
    session, new_binary_dir, platform, image_base, owner_name, *, allow_relative_call_discriminator=False
):
    """Reload and revalidate one predecessor function artifact in the active IDB."""
    artifact = _load_yaml_mapping(Path(new_binary_dir) / f"{owner_name}.{platform}.yaml")
    if not artifact or artifact.get("func_name") != owner_name:
        return None
    try:
        owner_ea = int(artifact["func_va"], 0)
    except (KeyError, TypeError, ValueError):
        return None
    if owner_ea < int(image_base):
        return None
    allow_across = bool(artifact.get("func_sig_allow_across_function_boundary"))
    function = await _inspect_function_via_mcp(
        session,
        owner_ea,
        image_base,
        owner_name,
        allow_across_function_boundary=allow_across,
        allow_relative_call_discriminator=allow_relative_call_discriminator,
    )
    if not function or not function.get("func_sig"):
        return None
    try:
        if int(function["func_va"], 0) != owner_ea:
            return None
        owner_end = owner_ea + int(function["func_size"], 0)
    except (KeyError, TypeError, ValueError):
        return None
    return {
        "artifact": artifact,
        "function": function,
        "owner_ea": owner_ea,
        "owner_end": owner_end,
        "allow_across": allow_across,
    }


async def write_located_globals(
    session,
    expected_outputs,
    platform,
    image_base,
    owner,
    located_by_name,
):
    """Write one or more GV artifacts anchored to one revalidated owner signature."""
    outputs = {name: _output_for_symbol(expected_outputs, name) for name in located_by_name}
    if any(output is None for output in outputs.values()):
        return False
    owner_ea = owner["owner_ea"]
    owner_end = owner["owner_end"]
    prepared = {}
    for name, item in located_by_name.items():
        try:
            gv_ea = int(item["gv_ea"], 0) if isinstance(item["gv_ea"], str) else int(item["gv_ea"])
            insn_ea = int(item["insn_ea"], 0) if isinstance(item["insn_ea"], str) else int(item["insn_ea"])
            insn_len = int(item["insn_len"], 0) if isinstance(item["insn_len"], str) else int(item["insn_len"])
            insn_disp = int(item["insn_disp"], 0) if isinstance(item["insn_disp"], str) else int(item["insn_disp"])
        except (KeyError, TypeError, ValueError):
            return False
        if gv_ea < int(image_base) or not owner_ea <= insn_ea < owner_end or insn_ea + insn_len > owner_end:
            return False
        resolution = await gv_resolution_fields_via_mcp(session, insn_ea, insn_disp, gv_ea, image_base, platform)
        if resolution is None:
            return False
        prepared[name] = (gv_ea, insn_ea, insn_len, insn_disp, resolution)
    function = owner["function"]
    for name, (gv_ea, insn_ea, insn_len, insn_disp, resolution) in prepared.items():
        payload = {
            "gv_name": name,
            "gv_va": hex(gv_ea),
            "gv_rva": hex(gv_ea - int(image_base)),
            "gv_sig": function["func_sig"],
            "gv_sig_va": function["func_va"],
            "gv_inst_offset": hex(insn_ea - owner_ea),
            "gv_inst_length": hex(insn_len),
            "gv_inst_disp": hex(insn_disp),
            **resolution,
        }
        if owner["allow_across"]:
            payload["gv_sig_allow_across_function_boundary"] = True
        write_gv_yaml(outputs[name], payload)
    return True
