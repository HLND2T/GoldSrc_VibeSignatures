#!/usr/bin/env python3
"""Recover the engine scissor-test globals of ``Draw_Frame``.

``engine/gl_draw.c`` keeps the software-sprite clip rectangle in file-scope
statics (``scissor_x``, ``scissor_y``, ``scissor_width``, ``scissor_height``,
``giScissorTest``) and ``Draw_Frame`` is their only reader:

    if ( giScissorTest )
    {
        qglScissor( scissor_x, scissor_y, scissor_width, scissor_height );
        qglEnable( GL_SCISSOR_TEST );
    }

The owner is the ``Draw_Frame`` artifact produced by the sprite-frame family
finder; the five globals are recovered from the ``qglScissor`` argument group
and the guard branch that controls it, exactly as described in
``_draw_frame_scissor_common``. That module owns the shape so the same
invariant is also what locates Draw_Frame on the SvEngine Linux builds.

A direct locator is used instead of an LLM predecessor: the argument class —
four adjacent int statics read together with the test boolean — is a stable
source-level invariant, every emitted form (MSVC pushes, gcc outgoing-argument
slots, gcc PIC ``gv@GOTOFF(%ebx)`` accesses) is fully decodable, and
``{gamever}`` reference fallback would otherwise need one reference body per
engine family.
"""

from pathlib import Path

from ida_analyze_util import _load_yaml_mapping, _output_for_symbol, _parse_int
from ida_preprocessor_scripts._direct_gv_common import write_located_globals
from ida_preprocessor_scripts._draw_frame_scissor_common import GLOBALS_WALK, walk_values
from ida_preprocessor_scripts._engine_private_globals_common import owner_context, run_walk

OWNER_FUNC_NAME = "Draw_Frame"
TARGET_GLOBAL_NAMES = ["giScissorTest", "scissor_x", "scissor_y", "scissor_width", "scissor_height"]


def _owner_artifact(new_binary_dir, platform, image_base):
    artifact = _load_yaml_mapping(Path(new_binary_dir) / f"{OWNER_FUNC_NAME}.{platform}.yaml")
    if not artifact or artifact.get("func_name") != OWNER_FUNC_NAME:
        return None
    try:
        func_ea = _parse_int(artifact["func_va"], "func_va")
    except Exception:  # noqa: BLE001 - malformed artifact fails closed.
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
    owner_ea = _owner_artifact(new_binary_dir, platform, image_base)
    if owner_ea is None:
        if debug:
            print(f"{skill_name}: missing {OWNER_FUNC_NAME} artifact")
        return False

    located = await run_walk(session, GLOBALS_WALK, walk_values(owner_ea))
    if located.get("error") or located.get("pointer_size") != 4:
        if debug:
            print(f"{skill_name}: {located.get('error') or located}")
        return False

    owner = await owner_context(session, owner_ea, image_base, OWNER_FUNC_NAME)
    if owner is None:
        if debug:
            print(f"{skill_name}: could not revalidate {OWNER_FUNC_NAME} at {owner_ea:#x}")
        return False
    if not await write_located_globals(
        session,
        expected_outputs,
        platform,
        image_base,
        owner,
        {name: located[name] for name in TARGET_GLOBAL_NAMES},
    ):
        return False
    if debug:
        print(
            f"{skill_name}: owner={owner_ea:#x} "
            + " ".join(f"{name}={located[name]['gv_ea']}" for name in TARGET_GLOBAL_NAMES)
        )
    return True
