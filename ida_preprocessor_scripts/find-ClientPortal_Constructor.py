"""Locate the unique portal constructor two call edges below RenderPortals.

The constructor copies three vec3 inputs into the same this object. Argument
roles are confirmed through the portal factory (view origin, view angles,
surface origin). All addresses and member displacements come from this IDB.
"""

from pathlib import Path
from ida_analyze_util import (
    _load_yaml_mapping,
    _parse_int,
    _output_for_symbol,
    _inspect_function_via_mcp,
    write_func_yaml,
)
from ida_preprocessor_scripts._portal_layout_ida import run_layout_walk

NAME = "ClientPortal_Constructor"
PREDECESSOR = "ClientPortalManager_RenderPortals"
WALK = """
candidates = {}
for factory in callees(values['render']):
    for target in callees(factory):
        try:
            offsets = constructor_offsets(decode_function(target), values['platform'])
        except ValueError:
            continue
        candidates[(target, factory)] = offsets
if len(candidates) != 1:
    raise ValueError('portal constructor candidates: %r' % candidates)
(target, factory), offsets = next(iter(candidates.items()))
result = {'target': target, 'factory': factory, **offsets}
"""


async def preprocess_skill(
    session, skill_name, expected_outputs, old_yaml_map, new_binary_dir, platform, image_base, debug=False
):
    name = "PortalSource_Constructor" if _output_for_symbol(expected_outputs, "PortalSource_Constructor") else NAME
    predecessor = _load_yaml_mapping(Path(new_binary_dir) / f"{PREDECESSOR}.{platform}.yaml")
    output = _output_for_symbol(expected_outputs, name)
    if not predecessor or predecessor.get("func_name") != PREDECESSOR or output is None:
        return False
    try:
        result = await run_layout_walk(
            session, {"render": _parse_int(predecessor["func_va"], "func_va"), "platform": platform}, WALK
        )
        if debug:
            print("Portal constructor located:", result)
        function = await _inspect_function_via_mcp(session, result["target"], image_base, name)
        across = function is None
        if across:
            function = await _inspect_function_via_mcp(
                session, result["target"], image_base, name, allow_across_function_boundary=True
            )
        if not function:
            return False
        payload = {key: function[key] for key in ("func_name", "func_va", "func_rva", "func_size", "func_sig")}
        if across:
            payload["func_sig_allow_across_function_boundary"] = True
        write_func_yaml(output, payload)
        if debug:
            print("Portal constructor verified:", result)
        return True
    except (ValueError, KeyError) as exc:
        if debug:
            print(exc)
        return False
