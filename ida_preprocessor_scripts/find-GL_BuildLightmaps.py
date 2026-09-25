#!/usr/bin/env python3
"""Locate GL_BuildLightmaps with per-branch confirmed anchors.

Three confirmed discovery branches (issue #114 batch8):

* ``hl-10210/windows``: the assertion ``surface->polys->next == NULL`` is a
  UTF-16LE literal uniquely owned by GL_BuildLightmaps, resolved through the
  shared ``xref_unicode_strings`` STRTYPE_C_16 collector.
* ``svencoop-10257/linux``: ``AllocBlock: full`` is a single-owner ASCII
  literal inside GL_BuildLightmaps' lightmap block allocator.
* every other validated branch: the covered R_NewMap body calls
  GL_BuildLightmaps directly, so a real LLM_DECOMPILE found_call against the
  annotated R_NewMap reference resolves the entry (call or tail jmp).

The branch is selected from the current gamever/platform tag; unknown tags
default to the R_NewMap chain. Addresses, byte patterns, and call ordinals are
never used for discovery; signatures are generated afterwards for validation.

Because a wrong found_call still yields a self-consistent artifact for the wrong
function, discovery is followed by ``_verified_body``: the accepted candidate
must carry the surface-name asterisk compare and the lightmap texparameter
arguments that only the lightmap rebuilder contains. A candidate that fails the
guard is rejected here, before downstream consumers inherit the wrong entry.
"""

from pathlib import Path

from ida_analyze_util import (
    _load_yaml_mapping,
    _output_for_symbol,
    _resolve_jmp_thunk_target_via_mcp,
    parse_mcp_result,
    preprocess_common_skill,
)

TARGET_FUNC_NAME = "GL_BuildLightmaps"
UNICODE_BRANCH = ("hl-10210", "windows")
ASCII_BRANCH = ("svencoop-10257", "linux")

FUNC_FIELDS = ["func_name", "func_sig", "func_va", "func_rva", "func_size"]

# GL_BuildLightmaps skips models whose name starts with '*':
#   if (m->name[0] == '*') continue;
ASTERISK_IMMEDIATE = 0x2A
# The lightmap upload loop rebinds every used lightmap texture through
# qglTexParameterf(GL_TEXTURE_2D, GL_TEXTURE_MIN_FILTER, ...) and
# qglTexParameterf(GL_TEXTURE_2D, GL_TEXTURE_MAG_FILTER, ...).
TEXTURE_UNIT_IMMEDIATE = 0x0DE1
FILTER_IMMEDIATES = (0x2800, 0x2801)

UNICODE_FUNC_XREFS = [
    {
        "func_name": TARGET_FUNC_NAME,
        "xref_strings": [],
        "xref_unicode_strings": ["FULLMATCH:surface->polys->next == NULL"],
        "xref_gvs": [],
        "xref_signatures": [],
        "xref_funcs": [],
    },
]
ASCII_FUNC_XREFS = [
    {
        "func_name": TARGET_FUNC_NAME,
        "xref_strings": ["FULLMATCH:AllocBlock: full"],
        "xref_gvs": [],
        "xref_signatures": [],
        "xref_funcs": [],
    },
]
R_NEWMAP_LLM_DECOMPILE = [
    {
        "symbol_name": TARGET_FUNC_NAME,
        "prompt_path": "prompt/call_llm_decompile.md",
        "reference_yaml_paths": [
            "references/{gamever}/engine/R_NewMap.{platform}.yaml",
        ],
        "expected_result_sections": ["found_call"],
        "dependency_policy": {"R_NewMap.{platform}.yaml": "required"},
    },
]

BODY_GUARD_PY = r"""
import json
import traceback

FUNC_EA = FUNC_EA_PLACEHOLDER
ASTERISK_IMMEDIATE = ASTERISK_IMMEDIATE_PLACEHOLDER
TEXTURE_UNIT_IMMEDIATE = TEXTURE_UNIT_IMMEDIATE_PLACEHOLDER
FILTER_IMMEDIATES = FILTER_IMMEDIATES_PLACEHOLDER


def main(func_ea, asterisk_immediate, texture_unit_immediate, filter_immediates):
    # MCP py_eval runs this code with separate global and local namespaces, so
    # module-level names are not visible inside a function defined here: take
    # everything as a parameter and keep the imports function-local.
    import ida_funcs, ida_lines, ida_ua, idaapi, idautils, idc

    def render(ea):
        return ida_lines.tag_remove(idc.generate_disasm_line(ea, 0) or '').split(';', 1)[0].strip()

    if idaapi.inf_is_64bit():
        return {'error': 'the body guard requires a 32-bit database'}
    func = ida_funcs.get_func(func_ea)
    if func is None or int(func.start_ea) != func_ea:
        return {'error': 'func_va is not a function start in the current database'}
    immediates = set()
    asterisk_lines = []
    for ea in idautils.FuncItems(func_ea):
        if not func_ea <= ea < int(func.end_ea):
            continue
        insn = ida_ua.insn_t()
        if ida_ua.decode_insn(insn, ea) <= 0:
            continue
        mnemonic = (idc.print_insn_mnem(ea) or '').strip().lower()
        for op in insn.ops:
            if op.type != ida_ua.o_imm:
                continue
            value = int(op.value) & 0xFFFFFFFF
            immediates.add(value)
            if mnemonic == 'cmp' and value == asterisk_immediate:
                asterisk_lines.append(render(ea))
    missing = []
    if not asterisk_lines:
        missing.append('the surface-name asterisk compare')
    if texture_unit_immediate not in immediates:
        missing.append('the GL_TEXTURE_2D texparameter target')
    if not set(filter_immediates) & immediates:
        missing.append('the lightmap texture filter texparameter arguments')
    if missing:
        return {'error': 'the candidate body is missing ' + ', '.join(missing)}
    return {
        'pointer_size': 4,
        'func_end': hex(int(func.end_ea)),
        'asterisk_lines': asterisk_lines[:4],
    }


try:
    result = json.dumps(main(FUNC_EA, ASTERISK_IMMEDIATE, TEXTURE_UNIT_IMMEDIATE, FILTER_IMMEDIATES))
except Exception:
    result = json.dumps({'error': traceback.format_exc()})
"""


def _remove_output(output):
    if output is not None and Path(output).is_file():
        Path(output).unlink()


async def _inspect_body(session, func_va):
    """Return the body-guard payload for func_va, or None when the scan cannot run."""
    code = (
        BODY_GUARD_PY.replace("FUNC_EA_PLACEHOLDER", str(int(func_va)))
        .replace("ASTERISK_IMMEDIATE_PLACEHOLDER", hex(ASTERISK_IMMEDIATE))
        .replace("TEXTURE_UNIT_IMMEDIATE_PLACEHOLDER", hex(TEXTURE_UNIT_IMMEDIATE))
        .replace("FILTER_IMMEDIATES_PLACEHOLDER", repr(list(FILTER_IMMEDIATES)))
    )
    try:
        payload = parse_mcp_result(await session.call_tool("py_eval", {"code": code}))
    except Exception:  # noqa: BLE001 - MCP tool failures must fail closed.
        return None
    return payload if isinstance(payload, dict) else None


async def _verified_body(session, output, debug=False):
    """Accept the artifact only when its function body is the lightmap rebuilder.

    Discovery can settle on the wrong R_NewMap callee, and the resulting
    artifact is self-consistent for that wrong function, so nothing downstream
    can tell it apart. The body guard re-checks the accepted entry against
    lightmap-rebuilder evidence that no sibling callee carries.
    """
    artifact = _load_yaml_mapping(output)
    try:
        func_va = int(str(artifact["func_va"]), 0)
    except (KeyError, TypeError, ValueError):
        return False
    resolved_va = await _resolve_jmp_thunk_target_via_mcp(session, func_va, debug=debug)
    if resolved_va is None:
        return False
    payload = await _inspect_body(session, resolved_va)
    if payload is None or payload.get("pointer_size") != 4:
        if debug:
            reason = (payload or {}).get("error") or "the body guard could not inspect the candidate"
            print(f"  find-GL_BuildLightmaps: rejected {TARGET_FUNC_NAME} at {hex(resolved_va)}: {reason}")
        return False
    return True


async def preprocess_skill(
    session,
    skill_name,
    expected_outputs,
    old_yaml_map,
    new_binary_dir,
    platform,
    image_base,
    llm_config=None,
    debug=False,
):
    _ = skill_name, old_yaml_map
    gamever = Path(new_binary_dir).resolve().parent.name if new_binary_dir else ""
    branch = (gamever, platform)
    if branch == UNICODE_BRANCH:
        func_xrefs, llm_specs = UNICODE_FUNC_XREFS, None
    elif branch == ASCII_BRANCH:
        func_xrefs, llm_specs = ASCII_FUNC_XREFS, None
    else:
        func_xrefs, llm_specs = None, R_NEWMAP_LLM_DECOMPILE
    success = await preprocess_common_skill(
        session=session,
        expected_outputs=expected_outputs,
        old_yaml_map=None,
        new_binary_dir=new_binary_dir,
        platform=platform,
        image_base=image_base,
        func_names=[TARGET_FUNC_NAME],
        func_xrefs=func_xrefs,
        llm_decompile_specs=llm_specs,
        llm_config=llm_config,
        generate_yaml_desired_fields=[(TARGET_FUNC_NAME, FUNC_FIELDS)],
        debug=debug,
    )
    if not success:
        return False
    output = _output_for_symbol(expected_outputs, TARGET_FUNC_NAME)
    if output is None or not await _verified_body(session, output, debug=debug):
        # Never leave the rejected artifact behind: a wrong entry must not
        # reach the -decompiles consumer or the artifact comparison.
        _remove_output(output)
        return False
    return True
