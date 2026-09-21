#!/usr/bin/env python3
"""Recover particletexture from the unique GL_Bind in R_DrawParticles.

engine/r_part.c opens the GLQUAKE particle pass with

    GL_Bind(particletexture);
    qglEnable(GL_ALPHA_TEST);

so the renderer body contains exactly one direct call to the already-located
GL_Bind, the call's sole argument is the particle texture id, and the next
GL token is 0x0BC0. The load that feeds that argument is the global: an
absolute ``push [gv]`` / ``mov eax, [gv]`` on Windows and GoldSrc Linux, or a
GOT-relative lea/load on SvEngine Linux. Security-cookie loads (followed by
``xor eax, ebp/esp``) are ignored.
"""

from pathlib import Path

from ida_analyze_util import _load_yaml_mapping, _output_for_symbol
from ida_preprocessor_scripts._direct_gv_common import inspect_owner_artifact, write_located_globals
from ida_preprocessor_scripts._engine_private_globals_common import owner_context, run_walk

GV_NAME = "particletexture"
OWNER_FUNC_NAME = "R_DrawParticles"
GL_BIND_NAME = "GL_Bind"
GL_ALPHA_TEST = 0x0BC0

WALK = r"""
OWNER = int(values['owner'], 0)
GL_BIND = int(values['gl_bind'], 0)
GL_ALPHA_TEST = int(values['gl_alpha_test'])
COOKIE_XORS = {b'\x33\xc5', b'\x33\xc4', b'\x31\xc5', b'\x31\xc4'}

entries = scan(OWNER)
if entries is None:
    result = {'error': 'R_DrawParticles is not a function start'}
else:
    binds = [index for index, entry in enumerate(entries)
             if entry['mnem'] == 'call' and local_call_target(entry['ea']) == GL_BIND]
    if len(binds) != 1:
        result = {'error': 'GL_Bind call is not unique: %s' % [hex(entries[i]['ea']) for i in binds]}
    else:
        bind = binds[0]
        has_alpha = False
        for entry in entries[bind + 1:bind + 12]:
            raw = ida_bytes.get_bytes(entry['ea'], entry['len']) or b''
            if GL_ALPHA_TEST.to_bytes(4, 'little') in raw:
                has_alpha = True
                break
            for op in entry['insn'].ops:
                if int(op.type) == int(idaapi.o_imm) and (int(op.value) & 0xFFFFFFFF) == GL_ALPHA_TEST:
                    has_alpha = True
                    break
            if has_alpha:
                break
        if not has_alpha:
            result = {'error': 'GL_Bind is not followed by GL_ALPHA_TEST'}
        else:
            reads = []
            for index, entry in enumerate(entries[:bind]):
                if entry['mnem'] not in ('mov', 'lea', 'push'):
                    continue
                loaded = entry['targets'] - entry['written']
                if len(loaded) != 1:
                    continue
                gv = next(iter(loaded))
                if not is_writable_data(gv) or is_got(gv):
                    continue
                nxt = entries[index + 1] if index + 1 < bind else None
                if nxt is not None and nxt['mnem'] == 'xor':
                    raw = (ida_bytes.get_bytes(nxt['ea'], nxt['len']) or b'')[:2].lower()
                    if raw in COOKIE_XORS:
                        continue
                reads.append((gv, index))
            unique = {gv for gv, _ in reads}
            if len(unique) != 1:
                result = {'error': 'particletexture load is not unique: %s' % [hex(x) for x in sorted(unique)]}
            else:
                gv = next(iter(unique))
                indexes = [index for loaded, index in reads if loaded == gv]
                located = access(first_addressable(entries, indexes), gv)
                if located is None:
                    result = {'error': 'no addressable particletexture operand'}
                else:
                    result = {'pointer_size': 4, 'gv': located}
"""


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
    if _output_for_symbol(expected_outputs, GV_NAME) is None:
        return False
    owner = await inspect_owner_artifact(session, new_binary_dir, platform, image_base, OWNER_FUNC_NAME)
    gl_bind = _load_yaml_mapping(Path(new_binary_dir) / f"{GL_BIND_NAME}.{platform}.yaml")
    if owner is None or not gl_bind or gl_bind.get("func_name") != GL_BIND_NAME:
        if debug:
            print(f"{skill_name}: missing {OWNER_FUNC_NAME} or {GL_BIND_NAME} artifact")
        return False
    try:
        gl_bind_ea = int(gl_bind["func_va"], 0)
    except (KeyError, TypeError, ValueError):
        return False
    if gl_bind_ea < int(image_base):
        return False
    located = await run_walk(
        session,
        WALK,
        {
            "owner": hex(owner["owner_ea"]),
            "gl_bind": hex(gl_bind_ea),
            "gl_alpha_test": GL_ALPHA_TEST,
        },
    )
    if located.get("error") or located.get("pointer_size") != 4:
        if debug:
            print(f"{skill_name}: {located.get('error')}")
        return False
    context = await owner_context(session, owner["owner_ea"], image_base, OWNER_FUNC_NAME)
    if context is None:
        return False
    if debug:
        print(f"{skill_name}: {GV_NAME}={located['gv']['gv_ea']} via {located['gv']['insn_disasm']}")
    return await write_located_globals(
        session, expected_outputs, platform, image_base, context, {GV_NAME: located["gv"]}
    )
