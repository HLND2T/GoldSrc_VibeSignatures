#!/usr/bin/env python3
"""Validate Part B objects and derive this binary's model/area layouts.

sv_models is the embedded server_t.models member, not a separate ELF object.
Its address and the independently produced sv base yield sv_models_offset.
ModelFrames proves four-byte pointer indexing and its actual exclusive upper
bound: slot zero is reserved; usable model indexes are 1..count-1.

SV_LinkContents and SV_LinkEdict prove the node sentinel, float plane distance,
two child pointers and trigger/solid circular list heads. The clear call proves
the allocated array size; count = clear bytes / observed node stride, and
element i is base + i * stride. The root is element zero. These derived values
are valid only for the matching binary, not constants copied between builds.

Both group globals must agree with the first/second int arguments stored by
the unique PF_SetGroupMask setter. No setter address or call ordinal is fixed.
"""

from ida_analyze_util import _load_yaml_mapping, _output_for_symbol, write_scalar_yaml, write_struct_offset_yaml
from ida_preprocessor_scripts._engine_private_globals_common import run_walk
from ida_preprocessor_scripts._server_physics_common import LAYOUT_WALK

SCALARS = [
    "sv_models_offset",
    "sv_models_element_size",
    "sv_models_count",
    "sv_models_size",
    "sv_areanodes_element_size",
    "sv_areanodes_count",
    "sv_areanodes_size",
]
MEMBERS = ["axis", "dist", "children", "trigger_edicts", "solid_edicts"]


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
    values = {"owners": {}, "globals": {}}
    for name in ["ModelFrames", "SV_LinkEdict", "SV_LinkContents"]:
        artifact = _load_yaml_mapping(f"{new_binary_dir}/{name}.{platform}.yaml")
        if not artifact or not artifact.get("func_va"):
            return False
        values["owners"][name] = int(artifact["func_va"], 0)
    for name in ["sv", "sv_models", "sv_areanodes", "g_groupop", "g_groupmask"]:
        artifact = _load_yaml_mapping(f"{new_binary_dir}/{name}.{platform}.yaml")
        if not artifact or not artifact.get("gv_va"):
            return False
        values["globals"][name] = int(artifact["gv_va"], 0)
    located = await run_walk(session, LAYOUT_WALK, values)
    if debug:
        print(f"{skill_name}: {located}")
    if (
        located.get("error")
        or set(located.get("scalars", {})) != set(SCALARS)
        or set(located.get("members", {})) != set(MEMBERS)
    ):
        return False
    outputs = {name: _output_for_symbol(expected_outputs, name) for name in SCALARS}
    members = {name: _output_for_symbol(expected_outputs, f"areanode_t_{name}_offset") for name in MEMBERS}
    if any(output is None for output in list(outputs.values()) + list(members.values())):
        return False
    for name, value in located["scalars"].items():
        write_scalar_yaml(outputs[name], {"scalar_name": name, "scalar_value": value})
    for name, (offset, size) in located["members"].items():
        write_struct_offset_yaml(
            members[name], {"struct_name": "areanode_t", "member_name": name, "offset": hex(offset), "size": size}
        )
    return True
