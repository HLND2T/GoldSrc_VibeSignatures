#!/usr/bin/env python3
"""Locate the GL_SetMode call dword ptr [qwglCreateContext] patch site.

The non-SvEngine Windows GL startup creates its context inside GL_SetMode (or
the legacy GL_SetModeLegacy wrapper) with `mov reg,[reg2]; push reg; call
dword ptr [qwglCreateContext]`. The consumer redirects exactly this indirect
call, so the artifact is a patch whose unique signature starts at the call
instruction.

The host function is consumed from its existing artifact (GL_SetMode on the
SDL-era builds, GL_SetModeLegacy on the pre-SDL/WON builds). The locator then
resolves the call site in the host body either through the exported
qwglCreateContext pointer variable (PE builds that keep the qgl wrapper export
table) or, on the decrypted WON blobs that have no export directory, through
the unique register-indirect push+`FF 15` argument shape that precedes the
context-creation call. Discovery never uses a byte signature or an old artifact
signature.
"""

from pathlib import Path

from ida_analyze_util import (
    _find_unique_bytes,
    _inspect_function_via_mcp,
    _load_yaml_mapping,
    _output_for_symbol,
    parse_mcp_result,
    write_patch_yaml,
)

PATCH_NAME = "GL_SetMode_call_qwglCreateContext"
HOST_FUNC_NAMES = ("GL_SetModeLegacy", "GL_SetMode")
SELECTPF_FUNC_NAME = "GL_SelectPixelFormat"
QGL_EXPORT_NAME = "qwglCreateContext"
MIN_SIG_BYTES = 6
MAX_SIG_BYTES = 96
MAX_INSTRUCTIONS = 64

LOCATE_PY = r"""
import ida_bytes
import ida_entry
import ida_funcs
import idaapi
import idautils
import idc
import json
import struct
import traceback

HOST_EA = HOST_EA_PLACEHOLDER
SELECTPF_EA = SELECTPF_EA_PLACEHOLDER
QGL_EXPORT_NAME = QGL_EXPORT_NAME_PLACEHOLDER
MIN_SIG_BYTES = MIN_SIG_BYTES_PLACEHOLDER
MAX_SIG_BYTES = MAX_SIG_BYTES_PLACEHOLDER
MAX_INSTRUCTIONS = MAX_INSTRUCTIONS_PLACEHOLDER


def database_limits():
    if hasattr(idaapi, 'inf_get_min_ea') and hasattr(idaapi, 'inf_get_max_ea'):
        return int(idaapi.inf_get_min_ea()), int(idaapi.inf_get_max_ea())
    inf = getattr(getattr(idaapi, 'cvar', None), 'inf', None)
    if inf is not None:
        return int(inf.min_ea), int(inf.max_ea)
    return 0, 0xFFFFFFFF


def raw_bin_search(ea, max_ea, data, data_mask, flags=0):
    if hasattr(ida_bytes, 'find_bytes'):
        return ida_bytes.find_bytes(data, ea, range_end=max_ea, mask=data_mask, flags=flags)
    return ida_bytes.bin_search(ea, max_ea, data, data_mask, len(data), flags)


def exec_ranges():
    import ida_segment
    ranges = []
    for start in idautils.Segments():
        seg = ida_segment.getseg(int(start))
        if seg is None:
            continue
        perms = int(getattr(seg, 'perm', 0))
        executable = int(ida_segment.SEGPERM_EXEC)
        if perms & executable:
            ranges.append((int(seg.start_ea), int(seg.end_ea)))
    if ranges:
        return ranges
    return [database_limits()]


def count_matches(tokens, expected_addr):
    if not tokens or all(token == '??' for token in tokens):
        return 0
    data = bytes(0 if token == '??' else int(token, 16) for token in tokens)
    mask = bytes(0x00 if token == '??' else 0xFF for token in tokens)
    flags = ida_bytes.BIN_SEARCH_FORWARD | ida_bytes.BIN_SEARCH_NOBREAK
    matches = []
    for start, end in exec_ranges():
        ea = raw_bin_search(start, end, data, mask, flags)
        while ea != idaapi.BADADDR and len(matches) < 3:
            matches.append(int(ea))
            ea = raw_bin_search(int(ea) + 1, end, data, mask, flags)
        if len(matches) >= 3:
            break
    unique = sorted(set(matches))
    if expected_addr is not None and unique == [int(expected_addr)]:
        return 1
    return len(unique)


def wildcard_instruction(insn, raw_bytes):
    import ida_ua
    wild = set()
    for op in insn.ops:
        ot = int(op.type)
        if ot == int(idaapi.o_void):
            continue
        if ot in (int(idaapi.o_imm), int(idaapi.o_near), int(idaapi.o_far), int(idaapi.o_mem), int(idaapi.o_displ)):
            offb = int(getattr(op, 'offb', 0))
            if offb > 0 and offb < insn.size:
                dsz = ida_ua.get_dtype_size(getattr(op, 'dtype', getattr(op, 'dtyp', 0)))
                if dsz <= 0:
                    dsz = insn.size - offb
                for index in range(offb, min(insn.size, offb + dsz)):
                    wild.add(index)
    b0 = raw_bytes[0]
    if b0 in (0xE8, 0xE9, 0xEB):
        for index in range(1, insn.size):
            wild.add(index)
    elif b0 == 0x0F and insn.size >= 2 and (raw_bytes[1] & 0xF0) == 0x80:
        for index in range(2, insn.size):
            wild.add(index)
    elif 0x70 <= b0 <= 0x7F:
        for index in range(1, insn.size):
            wild.add(index)
    return ['??' if index in wild else '%02X' % raw_bytes[index] for index in range(insn.size)]


def generate_patch_sig(target_inst):
    insn0 = idautils.DecodeInstruction(int(target_inst))
    if not insn0 or insn0.size <= 0:
        return None, 'failed to decode target instruction'
    raw0 = ida_bytes.get_bytes(int(target_inst), insn0.size)
    if not raw0:
        return None, 'failed to read target instruction bytes'
    search_end = database_limits()[1]
    limit_end = int(target_inst) + MAX_SIG_BYTES
    fwd_tokens = []
    fwd_boundaries = []
    cursor = int(target_inst)
    inst_count = 0
    target_inst_len = None
    while (
        cursor < search_end
        and cursor < limit_end
        and len(fwd_tokens) < MAX_SIG_BYTES
        and inst_count < MAX_INSTRUCTIONS
    ):
        insn = idautils.DecodeInstruction(cursor)
        if not insn or insn.size <= 0:
            break
        raw = ida_bytes.get_bytes(cursor, insn.size)
        if not raw:
            break
        if cursor == int(target_inst):
            target_inst_len = insn.size
            # The FF 15 slot displacement is an absolute address that the
            # loader relocates, so it is wildcarded like every other
            # relocatable operand; uniqueness comes from the surrounding
            # instruction stream.
            for token in wildcard_instruction(insn, raw):
                if len(fwd_tokens) < MAX_SIG_BYTES:
                    fwd_tokens.append(token)
        else:
            for token in wildcard_instruction(insn, raw):
                if len(fwd_tokens) < MAX_SIG_BYTES:
                    fwd_tokens.append(token)
        fwd_boundaries.append(len(fwd_tokens))
        cursor += insn.size
        inst_count += 1
    if target_inst_len is None:
        return None, 'no signature bytes collected'
    min_boundary = max(MIN_SIG_BYTES, target_inst_len)
    for boundary in fwd_boundaries:
        if boundary < min_boundary:
            continue
        prefix = fwd_tokens[:boundary]
        if count_matches(prefix, target_inst) == 1:
            return {
                'patch_sig': ' '.join(prefix),
                'patch_inst_length': target_inst_len,
                'original_bytes': ' '.join('%02X' % byte for byte in raw0),
            }, None
    return None, 'no unique signature found with forward-only expansion'


def insn_is_direct_call_to(ea, target):
    raw = ida_bytes.get_bytes(int(ea), 5) or b''
    if len(raw) < 5 or raw[0] != 0xE8:
        return False
    rel = struct.unpack('<i', raw[1:5])[0]
    return int(ea) + 5 + rel == int(target)


def slot_segment_name(slot):
    import ida_segment
    seg = ida_segment.getseg(int(slot))
    return (ida_segment.get_segm_name(seg) or '').lower() if seg is not None else ''


def is_data_slot(slot):
    name = slot_segment_name(slot)
    return bool(name) and not name.startswith('.idata') and 'idata' not in name


def qgl_export_ea():
    qty = ida_entry.get_entry_qty()
    for i in range(qty):
        ordn = ida_entry.get_entry_ordinal(i)
        name = ida_entry.get_entry_name(ordn) or ''
        if name == QGL_EXPORT_NAME:
            return int(ida_entry.get_entry(ordn))
    return None


globals().update(locals())

try:
    if idaapi.inf_is_64bit():
        raise RuntimeError('expected 32-bit x86')
    host = ida_funcs.get_func(int(HOST_EA))
    if host is None or int(host.start_ea) != int(HOST_EA):
        raise RuntimeError('host is not a function start')
    items = [int(ea) for ea in idautils.FuncItems(int(host.start_ea))]
    sites = []
    if SELECTPF_EA:
        # Preferred locator: the context creation is the first non-import
        # indirect call after the GL_SelectPixelFormat call inside the host
        # (maindc = GetDC(hwnd); GL_SelectPixelFormat(maindc); baseRC =
        # qwglCreateContext(maindc)).
        selectpf_call_index = None
        for index, ea in enumerate(items):
            if insn_is_direct_call_to(ea, int(SELECTPF_EA)):
                selectpf_call_index = index
        if selectpf_call_index is not None:
            for ea in items[selectpf_call_index + 1:]:
                raw = ida_bytes.get_bytes(ea, 6) or b''
                if len(raw) < 6 or raw[0] != 0xFF or raw[1] != 0x15:
                    continue
                slot = struct.unpack('<I', raw[2:6])[0]
                if not is_data_slot(slot):
                    continue
                sites.append({
                    'ea': hex(ea),
                    'slot': hex(slot),
                    'slot_name': idc.get_name(slot) or '',
                    'mode': 'post-selectpf',
                })
                break
    if not sites:
        export_slot = qgl_export_ea()
        for index, ea in enumerate(items):
            raw = ida_bytes.get_bytes(ea, 6) or b''
            if len(raw) < 6 or raw[0] != 0xFF or raw[1] != 0x15:
                continue
            slot = struct.unpack('<I', raw[2:6])[0]
            matched = export_slot is not None and slot == export_slot
            if not matched and export_slot is not None:
                continue
            if not matched:
                if not is_data_slot(slot):
                    continue
                shape = False
                for back in range(1, 4):
                    if index - back < 0:
                        break
                    prev = items[index - back]
                    push = idautils.DecodeInstruction(prev)
                    if push is None or (idc.print_insn_mnem(prev) or '').lower() != 'push':
                        continue
                    if int(push.ops[0].type) != int(idaapi.o_reg):
                        continue
                    pushed_reg = int(push.ops[0].reg)
                    for deeper in range(1, 4):
                        if index - back - deeper < 0:
                            break
                        load = idautils.DecodeInstruction(items[index - back - deeper])
                        if load is None or (idc.print_insn_mnem(items[index - back - deeper]) or '').lower() != 'mov':
                            continue
                        if (
                            int(load.ops[0].type) == int(idaapi.o_reg)
                            and int(load.ops[0].reg) == pushed_reg
                            and int(load.ops[1].type) in (int(idaapi.o_phrase), int(idaapi.o_displ))
                            and (int(getattr(load.ops[1], 'phrase', 0) or 0) or int(getattr(load.ops[1], 'reg', 0))) != 4
                        ):
                            shape = True
                        if shape:
                            break
                    if shape:
                        break
                if not shape:
                    continue
            sites.append({
                'ea': hex(ea),
                'slot': hex(slot),
                'slot_name': idc.get_name(slot) or '',
                'mode': 'export' if matched else 'shape',
            })
    if len(sites) != 1:
        result = json.dumps({
            'error': 'qwglCreateContext call site is not unique in host',
            'host': hex(int(host.start_ea)),
            'export_slot': hex(export_slot) if export_slot is not None else None,
            'sites': sites,
        })
    else:
        target = int(sites[0]['ea'], 0)
        generated, error = generate_patch_sig(target)
        if generated is None:
            result = json.dumps({
                'error': error,
                'host': hex(int(host.start_ea)),
                'sites': sites,
            })
        else:
            sites[0].update(generated)
            result = json.dumps({
                'pointer_size': 4,
                'host': hex(int(host.start_ea)),
                'site': sites[0],
            })
except Exception as exc:
    result = json.dumps({'error': str(exc), 'trace': traceback.format_exc()})
"""


def _function_artifact_path(new_binary_dir, platform, func_name):
    return Path(new_binary_dir) / f"{func_name}.{platform}.yaml"


def _function_artifact(new_binary_dir, platform, func_name, image_base):
    artifact = _load_yaml_mapping(_function_artifact_path(new_binary_dir, platform, func_name))
    if not artifact or artifact.get("func_name") != func_name:
        return None
    try:
        value = artifact["func_va"]
        func_ea = int(value, 0) if isinstance(value, str) else int(value)
    except (TypeError, ValueError, KeyError):
        return None
    if func_ea < int(image_base):
        return None
    return artifact, func_ea


def _function_allows_across_boundary(artifact):
    return bool(artifact.get("func_sig_allow_across_function_boundary"))


def _selectpf_ea(new_binary_dir, platform, image_base):
    artifact = _load_yaml_mapping(_function_artifact_path(new_binary_dir, platform, SELECTPF_FUNC_NAME))
    if not artifact or artifact.get("func_name") != SELECTPF_FUNC_NAME:
        return 0
    try:
        value = artifact["func_va"]
        func_ea = int(value, 0) if isinstance(value, str) else int(value)
    except (TypeError, ValueError, KeyError):
        return 0
    if func_ea < int(image_base):
        return 0
    return func_ea


async def _locate_callsite(session, host_ea, selectpf_ea):
    code = (
        LOCATE_PY.replace("HOST_EA_PLACEHOLDER", str(int(host_ea)))
        .replace("SELECTPF_EA_PLACEHOLDER", str(int(selectpf_ea or 0)))
        .replace("QGL_EXPORT_NAME_PLACEHOLDER", repr(QGL_EXPORT_NAME))
        .replace("MIN_SIG_BYTES_PLACEHOLDER", str(MIN_SIG_BYTES))
        .replace("MAX_SIG_BYTES_PLACEHOLDER", str(MAX_SIG_BYTES))
        .replace("MAX_INSTRUCTIONS_PLACEHOLDER", str(MAX_INSTRUCTIONS))
    )
    try:
        payload = parse_mcp_result(await session.call_tool("py_eval", {"code": code}))
    except Exception:  # noqa: BLE001 - MCP failures fail closed.
        return None
    if not isinstance(payload, dict):
        return None
    return payload


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
    output = _output_for_symbol(expected_outputs, PATCH_NAME)
    if output is None:
        return False
    host = None
    for host_name in HOST_FUNC_NAMES:
        host = _function_artifact(new_binary_dir, platform, host_name, image_base)
        if host is not None:
            break
    if host is None:
        if debug:
            print(f"  {skill_name}: missing {' or '.join(HOST_FUNC_NAMES)} artifact")
        return False
    host_data, host_ea = host
    host_name = host_data["func_name"]
    host_function = await _inspect_function_via_mcp(
        session,
        host_ea,
        image_base,
        host_name,
        allow_across_function_boundary=_function_allows_across_boundary(host_data),
    )
    if not host_function or not host_function.get("func_sig"):
        if debug:
            print(f"  {skill_name}: failed to verify {host_name} artifact")
        return False
    try:
        inspected_host_ea = int(host_function["func_va"], 0)
    except (TypeError, ValueError):
        return False
    if inspected_host_ea != host_ea:
        return False
    located = await _locate_callsite(session, host_ea, _selectpf_ea(new_binary_dir, platform, image_base))
    if located is None or located.get("error") or located.get("pointer_size") != 4:
        if debug:
            print(f"  {skill_name}: locator failed {located}")
        return False
    site = located.get("site")
    if not isinstance(site, dict):
        return False
    patch_sig = site.get("patch_sig")
    if not isinstance(patch_sig, str) or not patch_sig.strip():
        return False
    try:
        patch_ea = int(site["ea"], 0)
    except (TypeError, ValueError, KeyError):
        return False
    if patch_ea < host_ea:
        return False
    unique_ea = await _find_unique_bytes(session, patch_sig)
    if unique_ea != patch_ea:
        if debug:
            print(f"  {skill_name}: signature is not unique at {site.get('ea')}: {unique_ea}")
        return False
    if debug:
        print(f"  {skill_name}: ea={site['ea']} slot={site.get('slot')} mode={site.get('mode')}")
    write_patch_yaml(
        output,
        {
            "patch_name": PATCH_NAME,
            "patch_va": hex(patch_ea),
            "patch_rva": hex(patch_ea - int(image_base)),
            "patch_sig": patch_sig,
            "patch_sig_disp": 0,
        },
    )
    return True
