#!/usr/bin/env python3
"""Recover the engine user-fog globals of ``R_RenderFog`` / ``R_FogParams``.

``engine/r_triangle.c`` keeps the user-fog state in file-scope globals
(``g_bUserFogOn``, ``flFinalFogColor``, ``flFogStart``, ``flFogEnd``,
``flFogDensity``, ``g_bFogSkybox``). ``R_RenderFog`` writes the colour array
through its first pointer argument, its second/third arguments into
``flFogStart``/``flFogEnd``, and the boolean flag into ``g_bUserFogOn``;
``R_FogParams`` writes its two arguments into ``flFogDensity`` and
``g_bFogSkybox``.

The owners are the two artifacts produced by
``find-R_RenderFog-R_FogParams-from-tri`` and the globals are recovered from
that argument-to-global assignment, exactly as described in ``_fog_tri_common``:
each global's referencing instruction is the store, and its value traces back to
a caller argument slot through the tracked frame, never to an address order or a
layout guess.

A direct locator is used instead of an LLM predecessor: the argument class — one
colour pointer, two scalar floats and a boolean, all written into file-scope
globals — is a stable source-level invariant, every emitted form (MSVC absolute
stores, gcc non-PIC absolutes, gcc PIC ``gv@GOTOFF(%ebx)`` stores) is fully
decodable, and ``{gamever}`` reference fallback would otherwise need one
reference body per engine family.
"""

from pathlib import Path

from ida_analyze_util import _load_yaml_mapping, _output_for_symbol, _parse_int
from ida_preprocessor_scripts._direct_gv_common import write_located_globals
from ida_preprocessor_scripts._engine_private_globals_common import owner_context, run_walk
from ida_preprocessor_scripts._fog_tri_common import (
    FOG_PARAMS_FUNC,
    FOG_PARAMS_GLOBALS,
    GLOBALS_WALK,
    RENDER_FOG_FUNC,
    RENDER_FOG_GLOBALS,
    TARGET_GLOBAL_NAMES,
    walk_values,
)

OWNERS = (
    (RENDER_FOG_FUNC, RENDER_FOG_GLOBALS),
    (FOG_PARAMS_FUNC, FOG_PARAMS_GLOBALS),
)


def _owner_artifact(new_binary_dir, platform, image_base, owner_name):
    artifact = _load_yaml_mapping(Path(new_binary_dir) / f"{owner_name}.{platform}.yaml")
    if not artifact or artifact.get("func_name") != owner_name:
        return None
    try:
        func_ea = _parse_int(artifact["func_va"], "func_va")
    except Exception:  # noqa: BLE001 - malformed predecessor artifact fails closed.
        return None
    if func_ea < int(image_base):
        return None
    return func_ea


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
    _ = old_yaml_map
    if platform not in {"windows", "linux"}:
        return False
    if any(_output_for_symbol(expected_outputs, name) is None for name in TARGET_GLOBAL_NAMES):
        return False

    owners = {}
    for owner_name, _names in OWNERS:
        owner_ea = _owner_artifact(new_binary_dir, platform, image_base, owner_name)
        if owner_ea is None:
            if debug:
                print(f"{skill_name}: missing {owner_name} artifact")
            return False
        owners[owner_name] = owner_ea

    located = await run_walk(
        session,
        GLOBALS_WALK,
        walk_values(render_fog=owners[RENDER_FOG_FUNC], fog_params=owners[FOG_PARAMS_FUNC]),
    )
    if located.get("error"):
        if debug:
            print(f"{skill_name}: {located['error']}")
        return False

    for owner_name, names in OWNERS:
        owner = await owner_context(session, owners[owner_name], image_base, owner_name)
        if owner is None:
            if debug:
                print(f"{skill_name}: could not revalidate {owner_name} at {owners[owner_name]:#x}")
            return False
        if not await write_located_globals(
            session,
            expected_outputs,
            platform,
            image_base,
            owner,
            {name: located[owner_name][name] for name in names},
        ):
            return False
    if debug:
        for owner_name, names in OWNERS:
            print(
                f"{skill_name}: {owner_name}="
                + " ".join(f"{name}={located[owner_name][name]['gv_ea']}" for name in names)
            )
    return True
