#!/usr/bin/env python3
"""Locate Sven's CParticleEngine::EngineThink() through its LOD-bias setup.

No target-owned literal or distinctive floating-point coefficient set exists.
The two ordered discovery patterns encode the arguments of
glTexEnvf(GL_TEXTURE_FILTER_CONTROL, GL_TEXTURE_LOD_BIAS, cl_texture_lod->value):
pushes on both Windows builds and 8948 Linux, stack stores on 10257 Linux.
These are OpenGL API constants, not particle-object layout offsets. The first
pattern with matches must have exactly one function owner; ambiguity or failed
semantic validation stops discovery, rather than trying a weaker pattern.

Independently require the following call to use the imported glTexEnvf and the
verified HUD_DrawTransparentTriangles predecessor to call this body (resolving
8948 ELF PLT/GOT indirection). No call ordinal or bounded byte window is used.
The reviewed bodies update frametime, traverse active particle systems and
remove inactive systems. 8948 ELF names the body
_ZN15CParticleEngine11EngineThinkEv; 10257's equivalent is stripped.
"""

import json

from ida_analyze_util import parse_mcp_result, preprocess_common_skill
from ida_elf import ELF_RESOLVER_PY
from ida_preprocessor_scripts._direct_gv_common import inspect_owner_artifact

TARGET = "CParticleEngine_EngineThink"
PREDECESSOR = "HUD_DrawTransparentTriangles"
SIGNATURES = [
    "68 01 85 00 00 68 00 85 00 00",
    "C7 44 24 04 01 85 00 00 C7 04 24 00 85 00 00 E8 ?? ?? ?? ??",
]
GENERATE_YAML_DESIRED_FIELDS = [(TARGET, ["func_name", "func_sig", "func_va", "func_rva", "func_size"])]

LOCATE = (
    ELF_RESOLVER_PY
    + r"""
def locate(values):
    import ida_bytes, ida_funcs, ida_ida, ida_nalt, ida_ua, idaapi, idautils

    if idaapi.inf_is_64bit():
        return {'error': 'expected x86-32'}
    imports = set()
    def collect_import(ea, name, ordinal):
        if name == 'glTexEnvf':
            imports.add(int(ea))
        return True
    for index in range(ida_nalt.get_import_module_qty()):
        ida_nalt.enum_import_names(index, collect_import)
    if not imports:
        return {'error': 'glTexEnvf import missing'}

    def decode(ea):
        insn = ida_ua.insn_t()
        return insn if ida_ua.decode_insn(insn, ea) else None

    def calls_texenv(ea):
        insn = decode(ea)
        if insn is None or insn.get_canon_mnem() != 'call':
            return False
        op = insn.ops[0]
        if op.type == ida_ua.o_mem:
            return int(op.addr) in imports
        if op.type != ida_ua.o_near:
            return False
        target = int(op.addr)
        if target in imports:
            return True
        thunk = ida_funcs.get_func(target)
        if thunk is None or int(thunk.start_ea) != target:
            return False
        destination, slot = ida_funcs.calc_thunk_func_target(thunk)
        return int(destination) in imports or int(slot) in imports

    for signature in values['signatures']:
        cursor = ida_ida.inf_get_min_ea()
        hits = []
        while cursor < ida_ida.inf_get_max_ea():
            hit = ida_bytes.find_bytes(signature, cursor, range_end=ida_ida.inf_get_max_ea())
            if hit == idaapi.BADADDR:
                break
            hits.append(int(hit))
            cursor = int(hit) + 1
        if not hits:
            continue
        owners = set()
        for hit in hits:
            function = ida_funcs.get_func(hit)
            if function is None or not ida_bytes.is_code(ida_bytes.get_full_flags(hit)):
                return {'error': 'pattern is not a decoded function instruction'}
            owners.add(int(function.start_ea))
        if len(owners) != 1:
            return {'error': 'ambiguous pattern owners', 'owners': sorted(owners)}
        owner = next(iter(owners))
        for hit in hits:
            # Both encodings materialise the two API arguments immediately
            # before the call. Derive its address from instruction lengths.
            cursor = hit
            for _ in range(2):
                insn = decode(cursor)
                if insn is None:
                    return {'error': 'invalid argument instruction'}
                cursor += insn.size
            function = ida_funcs.get_func(cursor)
            if function is None or int(function.start_ea) != owner or not calls_texenv(cursor):
                return {'error': 'LOD-bias arguments do not call imported glTexEnvf'}
        callers = []
        for ea in idautils.FuncItems(values['predecessor']):
            insn = decode(ea)
            if (insn is not None and insn.get_canon_mnem() == 'call'
                    and insn.ops[0].type == ida_ua.o_near
                    and resolve_elf_plt(insn.ops[0].addr) == owner):
                callers.append(int(ea))
        if not callers:
            return {'error': 'HUD does not call the selected particle update body'}
        return {'signature': signature, 'owner': owner, 'hud_calls': callers}
    return {'error': 'no LOD-bias pattern matched'}

import json
result = json.dumps(locate(VALUES))
"""
)


async def preprocess_skill(
    session, skill_name, expected_outputs, old_yaml_map, new_binary_dir, platform, image_base, debug=False
):
    _ = skill_name, old_yaml_map
    predecessor = await inspect_owner_artifact(session, new_binary_dir, platform, image_base, PREDECESSOR)
    if not predecessor:
        return False
    values = {"predecessor": predecessor["owner_ea"], "signatures": SIGNATURES}
    located = parse_mcp_result(
        await session.call_tool("py_eval", {"code": LOCATE.replace("VALUES", json.dumps(values))})
    )
    if not isinstance(located, dict) or located.get("error") or located.get("signature") not in SIGNATURES:
        if debug:
            print(f"  {TARGET}: {located}")
        return False
    return await preprocess_common_skill(
        session=session,
        expected_outputs=expected_outputs,
        old_yaml_map=None,
        new_binary_dir=new_binary_dir,
        platform=platform,
        image_base=image_base,
        func_names=[TARGET],
        func_xrefs=[{"func_name": TARGET, "xref_signatures": [located["signature"]]}],
        generate_yaml_desired_fields=GENERATE_YAML_DESIRED_FIELDS,
        debug=debug,
    )
