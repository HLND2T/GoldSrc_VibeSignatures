#!/usr/bin/env python3
"""Locate the GL_Shutdown call performed by the Sys_ShutdownGame shutdown path.

MetaHookSv redirects exactly this branch to its own GL_Shutdown, so the
artifact is a patch whose unique signature starts at the call instruction:

    Sys_ShutdownGame_to_GL_Shutdown_callsite_0

The call is not always inside Sys_ShutdownGame's own body. Source is
Sys_ShutdownGame -> TRACESHUTDOWN(Sys_Shutdown()) -> GL_Shutdown(*pmainwindow,
maindc, baseRC), and the compiler emits that last step three different ways:

* inlined into Sys_ShutdownGame (hl-8684/hl-10210 Linux and the HL25 Windows
  builds), where the call sits in the owner body or in an IDA tail chunk that
  still belongs to the owner function;
* outlined as a separate Sys_Shutdown body that Sys_ShutdownGame calls (CoF).

The locator therefore enumerates direct rel32 calls to the GL_Shutdown artifact
inside the owner body plus the bodies of the owner's direct rel32 callees, and
requires exactly one candidate. Any other count fails closed.

`Sys_ShutdownGame` and `GL_Shutdown` both come from their verified current-run
artifacts; a byte signature or an old artifact never locates the target.
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

PATCH_NAME = "Sys_ShutdownGame_to_GL_Shutdown_callsite_0"
OWNER_FUNC_NAME = "Sys_ShutdownGame"
CALLEE_FUNC_NAME = "GL_Shutdown"
MAX_OWNER_CALLEES = 64
MIN_SIG_BYTES = 6
MAX_SIG_BYTES = 96
MAX_INSTRUCTIONS = 64

LOCATE_PY = r"""
import ida_bytes
import ida_funcs
import ida_segment
import idaapi
import idautils
import idc
import json
import struct
import traceback

OWNER_EA = OWNER_EA_PLACEHOLDER
CALLEE_EA = CALLEE_EA_PLACEHOLDER
MAX_OWNER_CALLEES = MAX_OWNER_CALLEES_PLACEHOLDER
MIN_SIG_BYTES = MIN_SIG_BYTES_PLACEHOLDER
MAX_SIG_BYTES = MAX_SIG_BYTES_PLACEHOLDER
MAX_INSTRUCTIONS = MAX_INSTRUCTIONS_PLACEHOLDER

def insn_mnem(ea):
    return (idc.print_insn_mnem(int(ea)) or '').lower()

def rel32_target(ea):
    raw = ida_bytes.get_bytes(int(ea), 5) or b''
    if len(raw) < 5 or raw[0] not in (0xE8, 0xE9):
        return None
    return int(ea) + 5 + struct.unpack('<i', raw[1:5])[0]


def direct_callees(start):
    callees = []
    for ea in idautils.FuncItems(int(start)):
        if insn_mnem(ea) not in ('call', 'jmp'):
            continue
        target = rel32_target(ea)
        if target is None:
            continue
        callee = ida_funcs.get_func(target)
        if callee is not None and int(callee.start_ea) == target:
            callees.append(target)
        if len(callees) >= int(MAX_OWNER_CALLEES):
            break
    return callees


def exec_ranges():
    ranges = []
    for start in idautils.Segments():
        seg = ida_segment.getseg(int(start))
        if seg is None:
            continue
        if int(getattr(seg, 'perm', 0)) & int(ida_segment.SEGPERM_EXEC):
            ranges.append((int(seg.start_ea), int(seg.end_ea)))
    return ranges


def raw_bin_search(ea, max_ea, data, data_mask, flags=0):
    if hasattr(ida_bytes, 'find_bytes'):
        return ida_bytes.find_bytes(data, ea, range_end=max_ea, mask=data_mask, flags=flags)
    return ida_bytes.bin_search(ea, max_ea, data, data_mask, len(data), flags)


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
    # Forward-only expansion from the branch, pinning the branch instruction
    # itself and wildcarding relocatable operands plus later branch
    # displacements. Matches the repository's other callsite patches, whose
    # per-version signature starts at the branch and wildcards what follows.
    insn0 = idautils.DecodeInstruction(int(target_inst))
    if not insn0 or insn0.size <= 0:
        return None, 'failed to decode target instruction'
    raw0 = ida_bytes.get_bytes(int(target_inst), insn0.size)
    if not raw0:
        return None, 'failed to read target instruction bytes'
    fwd_tokens = []
    fwd_boundaries = []
    cursor = int(target_inst)
    inst_count = 0
    target_inst_len = None
    max_ea = int(idaapi.inf_get_max_ea())
    while cursor < max_ea and len(fwd_tokens) < int(MAX_SIG_BYTES) and inst_count < int(MAX_INSTRUCTIONS):
        insn = idautils.DecodeInstruction(cursor)
        if not insn or insn.size <= 0:
            break
        raw = ida_bytes.get_bytes(cursor, insn.size)
        if not raw:
            break
        if cursor == int(target_inst):
            target_inst_len = insn.size
            for idx in range(insn.size):
                if len(fwd_tokens) < int(MAX_SIG_BYTES):
                    fwd_tokens.append('%02X' % raw[idx])
        else:
            for token in wildcard_instruction(insn, raw):
                if len(fwd_tokens) < int(MAX_SIG_BYTES):
                    fwd_tokens.append(token)
        fwd_boundaries.append(len(fwd_tokens))
        cursor += insn.size
        inst_count += 1
    if target_inst_len is None:
        return None, 'no signature bytes collected'
    min_boundary = max(int(MIN_SIG_BYTES), target_inst_len)
    for boundary in fwd_boundaries:
        if boundary < min_boundary:
            continue
        prefix = fwd_tokens[:boundary]
        if count_matches(prefix, target_inst) == 1:
            return {
                'patch_sig': ' '.join(prefix),
                'patch_sig_disp': 0,
                'patch_inst_length': target_inst_len,
                'original_bytes': ' '.join('%02X' % byte for byte in raw0),
            }, None
    return None, 'no unique signature found with forward-only expansion'


globals().update(locals())

try:
    if idaapi.inf_is_64bit():
        raise RuntimeError('expected 32-bit x86')
    owner = ida_funcs.get_func(int(OWNER_EA))
    if owner is None or int(owner.start_ea) != int(OWNER_EA):
        raise RuntimeError('owner is not a function start')
    callee = ida_funcs.get_func(int(CALLEE_EA))
    if callee is None or int(callee.start_ea) != int(CALLEE_EA):
        raise RuntimeError('callee is not a function start')
    scan_set = [int(owner.start_ea)]
    for direct in direct_callees(int(owner.start_ea)):
        if direct not in scan_set:
            scan_set.append(direct)
    sites = []
    errors = []
    for start in scan_set:
        for ea in idautils.FuncItems(int(start)):
            if insn_mnem(ea) != 'call':
                continue
            if rel32_target(ea) != int(callee.start_ea):
                continue
            generated, error = generate_patch_sig(ea)
            rec = {
                'ea': hex(int(ea)),
                'enclosing': hex(int(start)),
                'enclosing_name': idc.get_func_name(int(start)) or '',
                'disasm': idc.generate_disasm_line(int(ea), 0) or '',
            }
            if generated is None:
                rec['error'] = error
                errors.append(rec)
            else:
                rec.update(generated)
                sites.append(rec)
    if errors:
        result = json.dumps({
            'error': 'failed to generate a unique patch signature',
            'owner': hex(int(owner.start_ea)),
            'callee': hex(int(callee.start_ea)),
            'sites': sites,
            'errors': errors,
        })
    else:
        result = json.dumps({
            'pointer_size': 4,
            'owner': hex(int(owner.start_ea)),
            'owner_end': hex(int(owner.end_ea)),
            'callee': hex(int(callee.start_ea)),
            'sites': sites,
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


async def _locate_callsite(session, owner_ea, callee_ea):
    code = (
        LOCATE_PY.replace("OWNER_EA_PLACEHOLDER", str(int(owner_ea)))
        .replace("CALLEE_EA_PLACEHOLDER", str(int(callee_ea)))
        .replace("MAX_OWNER_CALLEES_PLACEHOLDER", str(MAX_OWNER_CALLEES))
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
    if platform not in {"windows", "linux"}:
        return False
    output = _output_for_symbol(expected_outputs, PATCH_NAME)
    if output is None:
        return False
    owner_artifact = _function_artifact(new_binary_dir, platform, OWNER_FUNC_NAME, image_base)
    callee_artifact = _function_artifact(new_binary_dir, platform, CALLEE_FUNC_NAME, image_base)
    if owner_artifact is None or callee_artifact is None:
        if debug:
            print(f"  {skill_name}: missing {OWNER_FUNC_NAME} or {CALLEE_FUNC_NAME} artifact")
        return False
    owner_data, owner_ea = owner_artifact
    _callee_data, callee_ea = callee_artifact
    owner_function = await _inspect_function_via_mcp(
        session,
        owner_ea,
        image_base,
        OWNER_FUNC_NAME,
        allow_across_function_boundary=_function_allows_across_boundary(owner_data),
    )
    if not owner_function or not owner_function.get("func_sig"):
        if debug:
            print(f"  {skill_name}: failed to verify {OWNER_FUNC_NAME} artifact")
        return False
    try:
        inspected_owner_ea = int(owner_function["func_va"], 0)
    except (TypeError, ValueError):
        return False
    if inspected_owner_ea != owner_ea:
        return False
    located = await _locate_callsite(session, owner_ea, callee_ea)
    if located is None or located.get("error") or located.get("pointer_size") != 4:
        if debug:
            print(f"  {skill_name}: locator failed {located}")
        return False
    sites = located.get("sites")
    if not isinstance(sites, list) or len(sites) != 1:
        if debug:
            print(f"  {skill_name}: expected exactly one GL_Shutdown callsite, got {sites}")
        return False
    site = sites[0]
    if not isinstance(site, dict):
        return False
    try:
        patch_ea = int(site["ea"], 0)
        patch_sig_disp = int(site["patch_sig_disp"])
        insn_len = int(site["patch_inst_length"])
    except (TypeError, ValueError, KeyError):
        return False
    patch_sig = site.get("patch_sig")
    if not isinstance(patch_sig, str) or not patch_sig.strip():
        return False
    # The locator only reports instructions drawn from the owner's own item set
    # or a direct callee's, so no address-order comparison against owner_ea is
    # valid: an IDA tail chunk can sit below the owner entry.
    if patch_ea <= 0 or patch_sig_disp != 0 or insn_len <= 0:
        return False
    unique_ea = await _find_unique_bytes(session, patch_sig)
    if unique_ea != patch_ea:
        if debug:
            print(f"  {skill_name}: signature is not unique at {site.get('ea')}: {unique_ea}")
        return False
    if debug:
        print(f"  {skill_name}: {PATCH_NAME} ea={site['ea']} in {site.get('enclosing_name')} {site.get('disasm', '')}")
    write_patch_yaml(
        output,
        {
            "patch_name": PATCH_NAME,
            "patch_va": hex(patch_ea),
            "patch_rva": hex(patch_ea - int(image_base)),
            "patch_sig": patch_sig,
            "patch_sig_disp": patch_sig_disp,
        },
    )
    return True
