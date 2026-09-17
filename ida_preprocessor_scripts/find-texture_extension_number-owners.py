#!/usr/bin/env python3
"""Name every direct owner of the legacy texture-name counter.

The verified texture_extension_number artifact supplies the exact global.
Decoded A1 references to it are then partitioned by source role.  Existing
GL_LoadTexture2, GL_LoadFilterTexture and GL_BuildLightmaps artifacts identify
three owners.  Target-owned R_Init command strings identify R_Init; the sole
two-reference owner is LoadTransPic; the remaining GL_Bind owner is
R_InitParticleTexture.  CoF additionally keeps a tiny standalone
GL_GenTexture counter allocator whose function boundary is reconstructed from
its canonical prologue/load/increment/store/return body.
"""

from pathlib import Path

from ida_analyze_util import (
    _inspect_function_via_mcp,
    _load_yaml_mapping,
    _output_for_symbol,
    parse_mcp_result,
    write_func_yaml,
)

GLOBAL_NAME = "texture_extension_number"
EXISTING_OWNER_NAMES = ("GL_LoadTexture2", "GL_LoadFilterTexture", "GL_BuildLightmaps", "GL_Bind")
NEW_OWNER_NAMES = ("LoadTransPic", "R_InitParticleTexture", "R_Init", "GL_GenTexture")

LOCATE_PY = r"""
import ida_bytes
import ida_funcs
import ida_idp
import ida_segment
import idaapi
import idautils
import idc
import json
import traceback

GLOBAL_EA = GLOBAL_EA_PLACEHOLDER
GL_BIND_EA = GL_BIND_EA_PLACEHOLDER
KNOWN_OWNERS = KNOWN_OWNERS_PLACEHOLDER
EXPECTED_NAMES = EXPECTED_NAMES_PLACEHOLDER
R_INIT_STRINGS = {'timerefresh', 'envmap', 'pointfile', 'gl_dump'}


def executable_ranges():
    result = []
    for start in idautils.Segments():
        seg = ida_segment.getseg(int(start))
        if seg is None:
            continue
        perms = int(getattr(seg, 'perm', 0))
        if perms & int(getattr(ida_segment, 'SEGPERM_EXEC', 4)):
            result.append((int(seg.start_ea), int(seg.end_ea)))
    return result


def call_target(ea):
    if (idc.print_insn_mnem(int(ea)) or '').lower() != 'call':
        return None
    target = int(idc.get_operand_value(int(ea), 0))
    fn = ida_funcs.get_func(target)
    return int(fn.start_ea) if fn is not None else target


def calls_target(fn, target):
    return any(call_target(ea) == int(target) for ea in idautils.FuncItems(int(fn.start_ea)))


def function_strings(fn):
    values = set()
    for ea in idautils.FuncItems(int(fn.start_ea)):
        for ref in idautils.DataRefsFrom(int(ea)):
            raw = idc.get_strlit_contents(int(ref), -1, idc.STRTYPE_C)
            if raw:
                try:
                    values.add(raw.decode('utf-8', errors='replace'))
                except Exception:
                    pass
    return values


def is_legacy_allocator_body(a1_ea):
    start = int(a1_ea) - 3
    raw = ida_bytes.get_bytes(start, 0x19) or b''
    if len(raw) != 0x19 or raw[:3] != b'\x55\x8B\xEC' or raw[3] != 0xA1 or raw[-2:] != b'\x5D\xC3':
        return None
    target = int(GLOBAL_EA).to_bytes(4, 'little')
    if raw[4:8] != target or raw.count(target) != 3:
        return None
    if b'\x83\xC1\x01' not in raw and b'\x41' not in raw:
        return None
    return start


globals().update(locals())

try:
    if idaapi.inf_is_64bit():
        raise RuntimeError('expected 32-bit x86')
    raw_sites = []
    needle = b'\xA1' + int(GLOBAL_EA).to_bytes(4, 'little')
    for start, end in executable_ranges():
        data = ida_bytes.get_bytes(start, end - start) or b''
        offset = data.find(needle)
        while offset != -1:
            raw_sites.append(start + offset)
            offset = data.find(needle, offset + 1)
    grouped = {}
    standalone = []
    for ea in raw_sites:
        fn = ida_funcs.get_func(int(ea))
        if fn is None:
            recovered = is_legacy_allocator_body(ea)
            if recovered is None or not ida_funcs.add_func(int(recovered), idc.BADADDR):
                raise RuntimeError('unowned A1 site at %x' % int(ea))
            fn = ida_funcs.get_func(int(recovered))
            if fn is None:
                raise RuntimeError('failed to define GL_GenTexture at %x' % int(recovered))
            standalone.append(int(fn.start_ea))
        elif is_legacy_allocator_body(ea) == int(fn.start_ea):
            standalone.append(int(fn.start_ea))
        grouped.setdefault(int(fn.start_ea), []).append(int(ea))
    assignments = dict(KNOWN_OWNERS)
    unknown = {owner: sites for owner, sites in grouped.items() if owner not in assignments}
    if standalone:
        if len(set(standalone)) != 1:
            raise RuntimeError('GL_GenTexture candidates are not unique: %r' % [hex(ea) for ea in standalone])
        assignments[standalone[0]] = 'GL_GenTexture'
        unknown.pop(standalone[0], None)
    for owner in list(unknown):
        fn = ida_funcs.get_func(int(owner))
        if fn is not None and R_INIT_STRINGS.issubset(function_strings(fn)):
            assignments[owner] = 'R_Init'
            unknown.pop(owner)
    transpic = [(owner, sites) for owner, sites in unknown.items() if len(sites) == 2]
    if transpic:
        if len(transpic) != 1:
            raise RuntimeError('LoadTransPic candidates are not unique: %r' % transpic)
        assignments[transpic[0][0]] = 'LoadTransPic'
        unknown.pop(transpic[0][0])
    particle = []
    for owner, sites in unknown.items():
        fn = ida_funcs.get_func(int(owner))
        if len(sites) == 1 and fn is not None and calls_target(fn, GL_BIND_EA):
            particle.append(owner)
    if particle:
        if len(particle) != 1:
            raise RuntimeError('R_InitParticleTexture candidates are not unique: %r' % [hex(ea) for ea in particle])
        assignments[particle[0]] = 'R_InitParticleTexture'
        unknown.pop(particle[0])
    if unknown:
        raise RuntimeError('unclassified texture counter owners: %r' % {
            hex(owner): [hex(ea) for ea in sites] for owner, sites in unknown.items()})
    inverse = {}
    for owner, name in assignments.items():
        if name in inverse and inverse[name] != owner:
            raise RuntimeError('duplicate owner role %s' % name)
        inverse[name] = owner
    missing = sorted(set(EXPECTED_NAMES) - set(inverse))
    unexpected = sorted(set(inverse) - set(EXPECTED_NAMES) - set(KNOWN_OWNERS.values()))
    if missing or unexpected:
        raise RuntimeError('owner inventory mismatch missing=%r unexpected=%r' % (missing, unexpected))
    result = json.dumps({
        'pointer_size': 4,
        'global_ea': hex(int(GLOBAL_EA)),
        'raw_sites': [hex(ea) for ea in sorted(raw_sites)],
        'owners': {
            name: {
                'func_va': hex(owner),
                'func_end': hex(int(ida_funcs.get_func(owner).end_ea)),
                'sites': [hex(ea) for ea in sorted(grouped.get(owner, []))],
                'func_name': idc.get_func_name(owner) or '',
            }
            for name, owner in sorted(inverse.items())
        },
    })
except Exception as exc:
    result = json.dumps({'error': str(exc), 'trace': traceback.format_exc()})
"""


def _artifact(new_binary_dir, platform, symbol_name, identity_field, image_base):
    artifact = _load_yaml_mapping(Path(new_binary_dir) / f"{symbol_name}.{platform}.yaml")
    if not artifact or artifact.get(identity_field) != symbol_name:
        return None
    field = "gv_va" if identity_field == "gv_name" else "func_va"
    try:
        address = int(artifact[field], 0)
    except (KeyError, TypeError, ValueError):
        return None
    if address < int(image_base):
        return None
    return artifact, address


def _expected(expected_outputs):
    values = {}
    for name in NEW_OWNER_NAMES:
        output = _output_for_symbol(expected_outputs, name)
        if output is not None:
            values[name] = output
    return values or None


async def _locate(session, global_ea, known, expected_names):
    role_map = {value: name for name, value in known.items() if name != "GL_Bind"}
    code = (
        LOCATE_PY.replace("GLOBAL_EA_PLACEHOLDER", str(int(global_ea)))
        .replace("GL_BIND_EA_PLACEHOLDER", str(int(known["GL_Bind"])))
        .replace("KNOWN_OWNERS_PLACEHOLDER", repr(role_map))
        .replace("EXPECTED_NAMES_PLACEHOLDER", repr(sorted(expected_names)))
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
    expected = _expected(expected_outputs)
    global_artifact = _artifact(new_binary_dir, platform, GLOBAL_NAME, "gv_name", image_base)
    known_artifacts = {
        name: _artifact(new_binary_dir, platform, name, "func_name", image_base) for name in EXISTING_OWNER_NAMES
    }
    if expected is None or global_artifact is None or any(value is None for value in known_artifacts.values()):
        if debug:
            print("  find-texture_extension_number-owners: missing outputs or dependency artifacts")
        return False
    _global_data, global_ea = global_artifact
    known = {name: value[1] for name, value in known_artifacts.items()}
    located = await _locate(session, global_ea, known, expected)
    if located is None or located.get("error") or located.get("pointer_size") != 4:
        if debug:
            print(f"  find-texture_extension_number-owners: locator failed {located}")
        return False
    owners = located.get("owners")
    if not isinstance(owners, dict) or not set(expected).issubset(owners):
        return False
    for name, output in expected.items():
        record = owners[name]
        try:
            func_ea = int(record["func_va"], 0)
        except (KeyError, TypeError, ValueError):
            return False
        function = await _inspect_function_via_mcp(session, func_ea, image_base, name)
        if not function or not function.get("func_sig"):
            function = await _inspect_function_via_mcp(
                session,
                func_ea,
                image_base,
                name,
                allow_across_function_boundary=True,
            )
        if not function or not function.get("func_sig") or int(function["func_va"], 0) != func_ea:
            if debug:
                print(f"  find-texture_extension_number-owners: failed to inspect {name} at {hex(func_ea)}")
            return False
        if debug:
            print(f"  find-texture_extension_number-owners: {name}={hex(func_ea)} sites={record.get('sites')}")
        payload = {
            "func_name": name,
            "func_va": function["func_va"],
            "func_rva": function["func_rva"],
            "func_size": function["func_size"],
            "func_sig": function["func_sig"],
        }
        if function.get("func_sig_allow_across_function_boundary"):
            payload["func_sig_allow_across_function_boundary"] = True
        write_func_yaml(output, payload)
    return True
