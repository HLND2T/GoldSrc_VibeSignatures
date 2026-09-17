#!/usr/bin/env python3
"""Locate legacy ``mov eax, texture_extension_number`` rewrite sites.

The MetaHook renderer replaces selected five-byte A1 loads with a call to the
real OpenGL texture allocator.  Discovery starts from the verified
texture_extension_number global, enumerates decoded A1 references, and accepts
only sites whose reachable same-function flow writes EAX back to that global or
passes the value to GL_Bind.  Each accepted source role is emitted as a separate
patch artifact with a unique signature that wildcards the global address.
"""

from pathlib import Path

from ida_analyze_util import (
    _find_unique_bytes,
    _load_yaml_mapping,
    _output_for_symbol,
    parse_mcp_result,
    write_patch_yaml,
)

GLOBAL_NAME = "texture_extension_number"
REQUIRED_FUNCTION_NAMES = (
    "GL_Bind",
    "GL_LoadTexture2",
    "GL_LoadFilterTexture",
    "GL_BuildLightmaps",
    "R_InitParticleTexture",
    "R_Init",
)
OPTIONAL_FUNCTION_NAMES = ("LoadTransPic", "GL_GenTexture")

PATCH_NAMES = (
    "texture_extension_number_mov_site_GL_LoadTexture2",
    "texture_extension_number_mov_site_LoadTransPic_bind",
    "texture_extension_number_mov_site_LoadTransPic_increment",
    "texture_extension_number_mov_site_GL_LoadFilterTexture",
    "texture_extension_number_mov_site_R_InitParticleTexture",
    "texture_extension_number_mov_site_R_Init_playertextures",
    "texture_extension_number_mov_site_GL_BuildLightmaps",
)

LOCATE_PY = r"""
import ida_bytes
import ida_funcs
import ida_gdl
import ida_idp
import ida_segment
import ida_ua
import idaapi
import idautils
import idc
import json
import traceback

GLOBAL_EA = GLOBAL_EA_PLACEHOLDER
GL_BIND_EA = GL_BIND_EA_PLACEHOLDER
OWNER_ROLES = OWNER_ROLES_PLACEHOLDER
MAX_FLOW_BYTES = 0x100
MIN_SIG_BYTES = 6
MAX_SIG_BYTES = 96
MAX_SIG_INSTRUCTIONS = 64


def raw_bin_search(ea, max_ea, data, data_mask, flags=0):
    if hasattr(ida_bytes, 'find_bytes'):
        return ida_bytes.find_bytes(data, ea, range_end=max_ea, mask=data_mask, flags=flags)
    return ida_bytes.bin_search(ea, max_ea, data, data_mask, len(data), flags)


def database_limits():
    if hasattr(idaapi, 'inf_get_min_ea') and hasattr(idaapi, 'inf_get_max_ea'):
        return int(idaapi.inf_get_min_ea()), int(idaapi.inf_get_max_ea())
    inf = getattr(getattr(idaapi, 'cvar', None), 'inf', None)
    if inf is not None:
        return int(inf.min_ea), int(inf.max_ea)
    return 0, 0xFFFFFFFF


def exec_ranges():
    ranges = []
    for start in idautils.Segments():
        seg = ida_segment.getseg(int(start))
        if seg is None:
            continue
        perms = int(getattr(seg, 'perm', 0))
        if perms & int(getattr(ida_segment, 'SEGPERM_EXEC', 4)):
            ranges.append((int(seg.start_ea), int(seg.end_ea)))
    return ranges or [database_limits()]


def count_matches(tokens, expected_addr):
    data = bytes(0 if token == '??' else int(token, 16) for token in tokens)
    mask = bytes(0 if token == '??' else 0xFF for token in tokens)
    flags = ida_bytes.BIN_SEARCH_FORWARD | ida_bytes.BIN_SEARCH_NOBREAK
    matches = []
    for start, end in exec_ranges():
        ea = raw_bin_search(start, end, data, mask, flags)
        while ea != idaapi.BADADDR and len(matches) < 3:
            matches.append(int(ea))
            ea = raw_bin_search(int(ea) + 1, end, data, mask, flags)
        if len(matches) >= 3:
            break
    return 1 if sorted(set(matches)) == [int(expected_addr)] else len(set(matches))


def wildcard_instruction(insn, raw):
    wild = set()
    for op in insn.ops:
        op_type = int(op.type)
        if op_type == int(idaapi.o_void):
            break
        if op_type in (int(idaapi.o_imm), int(idaapi.o_near), int(idaapi.o_far), int(idaapi.o_mem), int(idaapi.o_displ)):
            offb = int(getattr(op, 'offb', 0) or 0)
            if 0 < offb < int(insn.size):
                size = ida_ua.get_dtype_size(getattr(op, 'dtype', getattr(op, 'dtyp', 0)))
                if size <= 0:
                    size = int(insn.size) - offb
                wild.update(range(offb, min(int(insn.size), offb + size)))
    if raw[0] in (0xE8, 0xE9, 0xEB):
        wild.update(range(1, int(insn.size)))
    elif raw[0] == 0x0F and len(raw) >= 2 and (raw[1] & 0xF0) == 0x80:
        wild.update(range(2, int(insn.size)))
    elif 0x70 <= raw[0] <= 0x7F:
        wild.update(range(1, int(insn.size)))
    return ['??' if index in wild else '%02X' % raw[index] for index in range(int(insn.size))]


def generate_patch_sig(target_ea):
    cursor = int(target_ea)
    limit = cursor + MAX_SIG_BYTES
    tokens = []
    boundaries = []
    target_len = None
    for _ in range(MAX_SIG_INSTRUCTIONS):
        if cursor >= limit:
            break
        insn = idautils.DecodeInstruction(cursor)
        if not insn or insn.size <= 0:
            break
        raw = ida_bytes.get_bytes(cursor, int(insn.size)) or b''
        if not raw:
            break
        if cursor == int(target_ea):
            if int(insn.size) != 5 or raw[0] != 0xA1:
                return None, 'target is not A1 moffs32'
            target_len = int(insn.size)
            current = ['A1', '??', '??', '??', '??']
        else:
            current = wildcard_instruction(insn, raw)
        for token in current:
            if len(tokens) < MAX_SIG_BYTES:
                tokens.append(token)
        boundaries.append(len(tokens))
        cursor += int(insn.size)
    if target_len is None:
        return None, 'failed to decode target'
    for boundary in boundaries:
        if boundary < max(MIN_SIG_BYTES, target_len):
            continue
        candidate = tokens[:boundary]
        if count_matches(candidate, target_ea) == 1:
            return {
                'patch_sig': ' '.join(candidate),
                'patch_sig_disp': 0,
                'insn_len': target_len,
            }, None
    return None, 'no unique forward signature'


def reg_name(op):
    try:
        return (ida_idp.get_reg_name(int(op.reg), 4) or '').lower()
    except Exception:
        return None


def call_target(ea):
    if (idc.print_insn_mnem(int(ea)) or '').lower() != 'call':
        return None
    target = int(idc.get_operand_value(int(ea), 0))
    fn = ida_funcs.get_func(target)
    return int(fn.start_ea) if fn is not None else target


def writes_eax_to_global(ea):
    insn = idautils.DecodeInstruction(int(ea))
    if not insn or (idc.print_insn_mnem(int(ea)) or '').lower() != 'mov':
        return False
    if int(insn.ops[0].type) != int(idaapi.o_mem):
        return False
    if int(insn.ops[1].type) != int(idaapi.o_reg) or reg_name(insn.ops[1]) != 'eax':
        return False
    return int(insn.ops[0].addr) == int(GLOBAL_EA)


def reachable_eas(fn, start_ea):
    blocks = list(ida_gdl.FlowChart(fn))
    start_block = next((block for block in blocks if int(block.start_ea) <= int(start_ea) < int(block.end_ea)), None)
    if start_block is None:
        return []
    queue = [start_block]
    visited = set()
    eas = set()
    limit = int(start_ea) + MAX_FLOW_BYTES
    while queue:
        block = queue.pop(0)
        key = (int(block.start_ea), int(block.end_ea))
        if key in visited:
            continue
        visited.add(key)
        for ea in idautils.Heads(int(block.start_ea), int(block.end_ea)):
            if int(start_ea) < int(ea) < limit:
                eas.add(int(ea))
        for successor in block.succs():
            if int(successor.start_ea) < limit and int(successor.end_ea) > int(start_ea):
                queue.append(successor)
    return sorted(eas)


globals().update(locals())

try:
    if idaapi.inf_is_64bit():
        raise RuntimeError('expected 32-bit x86')
    sites = []
    raw_candidate_count = 0
    for owner, role in OWNER_ROLES.items():
        fn = ida_funcs.get_func(int(owner))
        if fn is None or int(fn.start_ea) != int(owner):
            raise RuntimeError('owner is not a function start: %x' % int(owner))
        for ea in idautils.FuncItems(int(owner)):
            insn = idautils.DecodeInstruction(int(ea))
            if not insn or int(insn.size) != 5:
                continue
            raw = ida_bytes.get_bytes(int(ea), 5) or b''
            if len(raw) != 5 or raw[0] != 0xA1:
                continue
            if int.from_bytes(raw[1:5], 'little') != int(GLOBAL_EA):
                continue
            raw_candidate_count += 1
            validators = []
            for follower in reachable_eas(fn, int(ea)):
                if writes_eax_to_global(follower):
                    validators.append(('writeback', follower))
                if call_target(follower) == int(GL_BIND_EA):
                    validators.append(('GL_Bind', follower))
            if not validators:
                continue
            generated, error = generate_patch_sig(int(ea))
            if generated is None:
                raise RuntimeError('signature failure at %x: %s' % (int(ea), error))
            if role is None:
                raise RuntimeError('unexpected redirectable site in excluded owner %x' % int(owner))
            sites.append({
                'ea': int(ea),
                'owner': owner,
                'owner_name': idc.get_func_name(owner) or '',
                'role': role,
                'validators': [{'kind': kind, 'ea': hex(validator_ea)} for kind, validator_ea in validators],
                'has_writeback': any(kind == 'writeback' for kind, _ in validators),
                'has_bind': any(kind == 'GL_Bind' for kind, _ in validators),
                'disasm': idc.generate_disasm_line(int(ea), 0) or '',
                **generated,
            })
    transpic = [site for site in sites if site['role'] == 'LoadTransPic']
    if transpic:
        group = transpic
        binds = [site for site in group if site['has_bind']]
        increments = [site for site in group if site['has_writeback'] and not site['has_bind']]
        if len(increments) != 1 or len(binds) != 1:
            raise RuntimeError('LoadTransPic roles are ambiguous: %r' % group)
        increments[0]['role'] = 'texture_extension_number_mov_site_LoadTransPic_increment'
        binds[0]['role'] = 'texture_extension_number_mov_site_LoadTransPic_bind'
    roles = [site['role'] for site in sites]
    if len(roles) != len(set(roles)):
        raise RuntimeError('duplicate source roles: %r' % roles)
    result = json.dumps({
        'pointer_size': 4,
        'global_ea': hex(int(GLOBAL_EA)),
        'raw_candidate_count': raw_candidate_count,
        'sites': [
            {
                **site,
                'ea': hex(site['ea']),
                'owner': hex(site['owner']),
            }
            for site in sorted(sites, key=lambda value: value['ea'])
        ],
    })
except Exception as exc:
    result = json.dumps({'error': str(exc), 'trace': traceback.format_exc()})
"""


def _artifact(new_binary_dir, platform, symbol_name, identity_field, image_base):
    artifact = _load_yaml_mapping(Path(new_binary_dir) / f"{symbol_name}.{platform}.yaml")
    if not artifact or artifact.get(identity_field) != symbol_name:
        return None
    address_field = "gv_va" if identity_field == "gv_name" else "func_va"
    try:
        address = int(artifact[address_field], 0)
    except (KeyError, TypeError, ValueError):
        return None
    if address < int(image_base):
        return None
    return artifact, address


def _expected_outputs(expected_outputs):
    outputs = {}
    for name in PATCH_NAMES:
        output = _output_for_symbol(expected_outputs, name)
        if output is not None:
            outputs[name] = output
    return outputs or None


async def _locate(session, global_ea, functions):
    roles = {
        functions["GL_LoadTexture2"]: "texture_extension_number_mov_site_GL_LoadTexture2",
        functions["GL_LoadFilterTexture"]: "texture_extension_number_mov_site_GL_LoadFilterTexture",
        functions["GL_BuildLightmaps"]: "texture_extension_number_mov_site_GL_BuildLightmaps",
        functions["R_InitParticleTexture"]: "texture_extension_number_mov_site_R_InitParticleTexture",
        functions["R_Init"]: "texture_extension_number_mov_site_R_Init_playertextures",
    }
    if "LoadTransPic" in functions:
        roles[functions["LoadTransPic"]] = "LoadTransPic"
    if "GL_GenTexture" in functions:
        roles[functions["GL_GenTexture"]] = None
    code = (
        LOCATE_PY.replace("GLOBAL_EA_PLACEHOLDER", str(int(global_ea)))
        .replace("GL_BIND_EA_PLACEHOLDER", str(int(functions["GL_Bind"])))
        .replace("OWNER_ROLES_PLACEHOLDER", repr(roles))
    )
    try:
        payload = parse_mcp_result(await session.call_tool("py_eval", {"code": code}))
    except Exception:  # noqa: BLE001 - MCP failures fail closed.
        return None
    return payload if isinstance(payload, dict) else None


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
    if platform != "windows":
        return False
    outputs = _expected_outputs(expected_outputs)
    global_artifact = _artifact(new_binary_dir, platform, GLOBAL_NAME, "gv_name", image_base)
    function_artifacts = {
        name: _artifact(new_binary_dir, platform, name, "func_name", image_base) for name in REQUIRED_FUNCTION_NAMES
    }
    for name in OPTIONAL_FUNCTION_NAMES:
        artifact = _artifact(new_binary_dir, platform, name, "func_name", image_base)
        if artifact is not None:
            function_artifacts[name] = artifact
    if outputs is None or global_artifact is None or any(value is None for value in function_artifacts.values()):
        if debug:
            print("  find-texture_extension_number-mov-sites: missing outputs or dependency artifacts")
        return False
    _global_data, global_ea = global_artifact
    function_addresses = {name: value[1] for name, value in function_artifacts.items()}
    located = await _locate(session, global_ea, function_addresses)
    if located is None or located.get("error") or located.get("pointer_size") != 4:
        if debug:
            print(f"  find-texture_extension_number-mov-sites: locator failed {located}")
        return False
    sites = located.get("sites")
    if not isinstance(sites, list):
        return False
    by_role = {site.get("role"): site for site in sites if isinstance(site, dict)}
    if set(by_role) != set(outputs):
        if debug:
            print(
                f"  find-texture_extension_number-mov-sites: found roles {sorted(by_role)} expected {sorted(outputs)}"
            )
        return False
    for name, output in outputs.items():
        site = by_role[name]
        try:
            patch_ea = int(site["ea"], 0)
            patch_sig_disp = int(site["patch_sig_disp"])
            insn_len = int(site["insn_len"])
        except (KeyError, TypeError, ValueError):
            return False
        patch_sig = site.get("patch_sig")
        if not isinstance(patch_sig, str) or not patch_sig.strip() or patch_sig_disp != 0 or insn_len != 5:
            return False
        if await _find_unique_bytes(session, patch_sig) != patch_ea:
            return False
        if debug:
            print(
                f"  find-texture_extension_number-mov-sites: {name}={hex(patch_ea)} "
                f"owner={site.get('owner_name')} validators={site.get('validators')}"
            )
        write_patch_yaml(
            output,
            {
                "patch_name": name,
                "patch_va": hex(patch_ea),
                "patch_rva": hex(patch_ea - int(image_base)),
                "patch_sig": patch_sig,
                "patch_sig_disp": patch_sig_disp,
            },
        )
    return True
