#!/usr/bin/env python3
"""Recover the engine ``currenttexture`` slot from GL_Bind.

engine/gl_draw.c GL_Bind reads ``currenttexture`` for its early-out
(``if (currenttexture == texnum) return;``) and writes it immediately before
``qglBindTexture``.  The only other writable global the body touches is
``g_currentpalette``, whose reference is later, so the earliest global that the
body both reads and writes is ``currenttexture``.  The anchor is the first
reference to that global that carries a four-byte displacement; on PIC builds
whose store is register-indirect this is the ``lea``/GOT load that materialises
the address.
"""

from ida_preprocessor_scripts._renderer_private_globals_common import (
    preprocess_currenttexture,
)


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
    return await preprocess_currenttexture(
        session,
        expected_outputs,
        new_binary_dir,
        platform,
        image_base,
        predecessor="GL_Bind",
        debug=debug,
    )
