#!/usr/bin/env python3
"""Recover host_basepal from the Hunk_AllocName(2048) palette store.

engine/host.c assigns ``host_basepal = Hunk_AllocName(2048, "palette.lmp")``.
GoldSrc keeps that store in Host_Init; SvEngine moved it to
Host_LoadBasePalette. The locator requires the revalidated Hunk_AllocName
callee, both C arguments (size 0x800 and a ``palette.lmp`` pointer, including
the Linux ``gfx/palette.lmp`` suffix), and EAX/return-register dataflow into
the unique writable-global store. SvEngine Linux may call through a PIC PLT
stub (``jmp [ebx+GOTOFF]``) whose lazy ``.got.plt`` slot still holds stub+6;
the walk resolves that stub with the owner's GOT base before matching
``Hunk_AllocName``.
"""

from ida_preprocessor_scripts._host_palette_common import preprocess_host_basepal


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
    return await preprocess_host_basepal(session, expected_outputs, new_binary_dir, platform, image_base, debug=debug)
