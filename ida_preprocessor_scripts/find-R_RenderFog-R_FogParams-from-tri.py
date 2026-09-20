#!/usr/bin/env python3
"""Recover ``R_RenderFog`` and ``R_FogParams`` from ``cl_enginefuncs.pTriAPI``.

``engine/r_triangle.c`` publishes ``triangleapi_t tri`` through the engine
function table, and ``common/triangleapi.h`` fixes its field order: slot 13 is
``R_RenderFog`` and slot 19 is ``R_FogParams``. ``find-_fog_tri_common`` reads
that pointer from the already-covered ``cl_enginefuncs`` artifact and validates
the table shape, so no byte signature, prior artifact signature or address is
involved in discovery.

SvEngine publishes thin ``tri_R_RenderFog_I``/``tri_R_FogParams_I`` adapters in
those slots, so the slot is followed to the callee that owns the fog global
writes. See ``_fog_tri_common`` for the full anchor rationale.
"""

from pathlib import Path

from ida_analyze_util import _load_yaml_mapping, _output_for_symbol, _parse_int, write_func_yaml
from ida_preprocessor_scripts._engine_private_globals_common import inspect_func, run_walk
from ida_preprocessor_scripts._fog_tri_common import (
    ENGINE_FUNCS_GLOBAL,
    FOG_PARAMS_FUNC,
    LOCATE_WALK,
    RENDER_FOG_FUNC,
    walk_values,
)

TARGET_FUNC_NAMES = (RENDER_FOG_FUNC, FOG_PARAMS_FUNC)


def _enginefuncs_artifact(new_binary_dir, platform, image_base):
    artifact = _load_yaml_mapping(Path(new_binary_dir) / f"{ENGINE_FUNCS_GLOBAL}.{platform}.yaml")
    if not artifact or artifact.get("gv_name") != ENGINE_FUNCS_GLOBAL:
        return None
    try:
        gv_ea = _parse_int(artifact["gv_va"], "gv_va")
    except Exception:  # noqa: BLE001 - malformed predecessor artifact fails closed.
        return None
    if gv_ea < int(image_base):
        return None
    return gv_ea


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
    _ = skill_name, old_yaml_map
    if platform not in {"windows", "linux"}:
        return False
    outputs = {name: _output_for_symbol(expected_outputs, name) for name in TARGET_FUNC_NAMES}
    if any(output is None for output in outputs.values()):
        return False

    enginefuncs = _enginefuncs_artifact(new_binary_dir, platform, image_base)
    if enginefuncs is None:
        if debug:
            print(f"{skill_name}: missing {ENGINE_FUNCS_GLOBAL} artifact")
        return False

    located = await run_walk(session, LOCATE_WALK, walk_values(enginefuncs=enginefuncs))
    if located.get("error") or any(name not in located for name in TARGET_FUNC_NAMES):
        if debug:
            print(f"{skill_name}: {located.get('error') or located}")
        return False

    for name in TARGET_FUNC_NAMES:
        payload = await inspect_func(session, int(located[name]), image_base, name)
        if payload is None:
            if debug:
                print(f"{skill_name}: inspection failed for {name} at {located[name]}")
            return False
        write_func_yaml(outputs[name], payload)
    if debug:
        print(
            f"{skill_name}: tri={located['tri']} " + " ".join(f"{name}={located[name]}" for name in TARGET_FUNC_NAMES)
        )
    return True
