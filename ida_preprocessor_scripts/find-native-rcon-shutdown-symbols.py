#!/usr/bin/env python3
"""Locate the engine shutdown entries Host_Shutdown and NET_Shutdown.

Family coverage is data-driven, never address- or signature-based:

* ``Host_Shutdown`` owns the unique recursive-shutdown guard literal. Classic
  HL/CoF builds print the lowercase ``recursive shutdown`` (on the Linux
  ``hw.so`` bodies the literal has no trailing newline), while Sven renamed it
  to ``Recursive shutdown!``. Both spellings are offered as needles and the
  single owning function is accepted only when exactly one string owns them.
* ``NET_Shutdown`` is ``Host_Shutdown``'s direct callee that tears the network
  stack down. On the classic engines that helper calls ``NET_Config(0)``; on
  Sven it calls ``Sock_Config``. The classic Linux bodies inline ``NET_Config``,
  so there the callee is recognised by the ``ip_sockets`` transport array it
  references. Callees and their own calls are PLT-resolved on ELF so GCC's
  indirection does not hide the edge.

Discovery consumes only the deterministic artifacts the DAG already produces
for every engine input: ``NET_Config``, ``ip_sockets`` and (Sven) ``Sock_Config``.
No byte signature, previous address or fixed offset is ever read.

Scope: the engine module of every game version that ships one (hl-3248..10210,
including the four decrypted BLOB builds, cof-5936 and svencoop-8948/10257) on
Windows PE32 and Linux ELF32. cstrike/czero/czeror ship no engine module and
are therefore not applicable.
"""

from pathlib import Path

from ida_analyze_util import (
    _inspect_function_via_mcp,
    _load_yaml_mapping,
    _output_for_symbol,
    parse_mcp_result,
    write_func_yaml,
)

NAMES = ["Host_Shutdown", "NET_Shutdown"]
FIELDS = ["func_name", "func_va", "func_rva", "func_size", "func_sig"]
MAX_CALLEES = 128

# The recursive-shutdown guard literal, one per engine family. Matching is a
# case-sensitive substring so the classic PE newline suffix and the trimmed
# Linux body both resolve without accepting each other's spelling.
RECURSIVE_NEEDLES = ["recursive shutdown", "Recursive shutdown!"]

LOCATE_PY = r"""
import ida_bytes
import ida_funcs
import ida_segment
import idaapi
import idautils
import idc
import json
import traceback

RECURSIVE_NEEDLES = RECURSIVE_NEEDLES_PLACEHOLDER
CONFIG_EAS = CONFIG_EAS_PLACEHOLDER
IPSOCK_EA = IPSOCK_EA_PLACEHOLDER
MAX_CALLEES = MAX_CALLEES_PLACEHOLDER


def resolve_elf_plt(ea):
    ea = int(ea)
    segment = ida_segment.getseg(ea)
    if segment is None or not ida_segment.get_segm_name(segment).startswith('.plt'):
        return ea
    function = ida_funcs.get_func(ea)
    if function is None or int(function.start_ea) != ea:
        return ea
    target, slot = ida_funcs.calc_thunk_func_target(function)
    if target == idaapi.BADADDR or slot == idaapi.BADADDR:
        return ea
    target_segment = ida_segment.getseg(target)
    target_function = ida_funcs.get_func(target)
    if (target_segment is None or not (target_segment.perm & ida_segment.SEGPERM_EXEC)
            or ida_segment.get_segm_name(target_segment).startswith('.plt')
            or target_function is None or int(target_function.start_ea) != target):
        return ea
    for offset in range(4):
        if not ida_bytes.is_loaded(slot + offset):
            return ea
    return int(target) if int(ida_bytes.get_dword(slot)) == target else ea


def direct_callees(start):
    targets = set()
    for ea in idautils.FuncItems(int(start)):
        if (idc.print_insn_mnem(ea) or '').lower() not in ('call', 'jmp'):
            continue
        for ref in idautils.CodeRefsFrom(ea, False):
            target = resolve_elf_plt(int(ref))
            function = ida_funcs.get_func(target)
            if function is not None and int(function.start_ea) == target:
                targets.add(target)
        if len(targets) >= int(MAX_CALLEES):
            break
    return targets


def references_data(start, target):
    if target is None:
        return False
    for ea in idautils.FuncItems(int(start)):
        for ref in idautils.DataRefsFrom(ea):
            if int(ref) == int(target):
                return True
    return False


def locate():
    if idaapi.inf_is_64bit():
        raise RuntimeError('expected 32-bit x86')

    owners = {}
    for item in idautils.Strings(default_setup=False):
        text = str(item)
        matched = False
        for needle in RECURSIVE_NEEDLES:
            if needle in text:
                matched = True
                break
        if not matched:
            continue
        owner_functions = set()
        for xref in idautils.XrefsTo(int(item.ea), 0):
            function = ida_funcs.get_func(int(xref.frm))
            if function is not None:
                owner_functions.add(int(function.start_ea))
        owners[int(item.ea)] = sorted(owner_functions)

    host_candidates = set()
    for functions in owners.values():
        host_candidates.update(functions)
    host_values = sorted(host_candidates)
    if len(host_values) != 1:
        raise RuntimeError(
            'expected exactly one recursive-shutdown owner, got '
            + repr([hex(value) for value in host_values])
        )
    host = host_values[0]

    callee_detail = []
    net_candidates = []
    for callee in sorted(direct_callees(host)):
        if callee in CONFIG_EAS:
            continue
        calls_config = False
        for config in CONFIG_EAS:
            if config in direct_callees(callee):
                calls_config = True
                break
        refs_sockets = references_data(callee, IPSOCK_EA)
        callee_detail.append({
            'ea': hex(callee),
            'name': idc.get_func_name(callee) or '',
            'calls_config': calls_config,
            'refs_sockets': refs_sockets,
        })
        if calls_config or refs_sockets:
            net_candidates.append(callee)

    literals = {}
    for ea in sorted(owners):
        literals[hex(ea)] = [hex(fn) for fn in owners[ea]]
    return {
        'pointer_size': 4,
        'host': hex(host),
        'host_literals': literals,
        'config_eas': [hex(value) for value in CONFIG_EAS],
        'callees': callee_detail,
        'net': [hex(callee) for callee in net_candidates],
    }


globals().update(locals())
try:
    result = json.dumps(locate())
except Exception as exc:
    result = json.dumps({'error': str(exc), 'trace': traceback.format_exc()})
"""


def _artifact_va(new_binary_dir, platform, name):
    artifact = _load_yaml_mapping(Path(new_binary_dir) / f"{name}.{platform}.yaml")
    if not artifact:
        return None
    for key in ("func_va", "gv_va"):
        if key in artifact:
            try:
                return int(artifact[key], 0)
            except (TypeError, ValueError):
                return None
    return None


async def _locate(session, config_eas, ipsock_ea):
    code = (
        LOCATE_PY.replace("RECURSIVE_NEEDLES_PLACEHOLDER", repr(RECURSIVE_NEEDLES))
        .replace("CONFIG_EAS_PLACEHOLDER", repr([int(value) for value in config_eas]))
        .replace("IPSOCK_EA_PLACEHOLDER", repr(int(ipsock_ea) if ipsock_ea is not None else None))
        .replace("MAX_CALLEES_PLACEHOLDER", str(MAX_CALLEES))
    )
    try:
        payload = parse_mcp_result(await session.call_tool("py_eval", {"code": code}))
    except Exception:  # noqa: BLE001 - MCP failures fail closed.
        return None
    return payload if isinstance(payload, dict) else None


async def preprocess_skill(
    session, skill_name, expected_outputs, old_yaml_map, new_binary_dir, platform, image_base, debug=False
):
    _ = skill_name, old_yaml_map
    if platform not in {"windows", "linux"}:
        return False
    outputs = {}
    for name in NAMES:
        output = _output_for_symbol(expected_outputs, name)
        if output is None:
            return False
        outputs[name] = output

    config_eas = []
    for name in ("Sock_Config", "NET_Config"):
        value = _artifact_va(new_binary_dir, platform, name)
        if value is not None:
            config_eas.append(value)
    if not config_eas:
        if debug:
            print(f"  {skill_name}: neither Sock_Config nor NET_Config artifact is available")
        return False
    ipsock_ea = _artifact_va(new_binary_dir, platform, "ip_sockets")

    located = await _locate(session, config_eas, ipsock_ea)
    if not located or located.get("error") or located.get("pointer_size") != 4:
        if debug:
            print(f"  {skill_name}: locator failed {located}")
        return False
    try:
        host_ea = int(located["host"], 0)
        net_eas = [int(value, 0) for value in located["net"]]
    except (TypeError, ValueError, KeyError):
        return False
    if host_ea < int(image_base) or len(net_eas) != 1:
        if debug:
            print(f"  {skill_name}: expected exactly one NET_Shutdown, got {located.get('net')}")
        return False
    net_ea = net_eas[0]
    if net_ea < int(image_base) or net_ea == host_ea:
        return False

    for name, ea in (("Host_Shutdown", host_ea), ("NET_Shutdown", net_ea)):
        function = await _inspect_function_via_mcp(session, ea, image_base, name)
        if not function or not function.get("func_sig"):
            if debug:
                print(f"  {skill_name}: failed to inspect {name} at {hex(ea)}")
            return False
        try:
            verified_ea = int(function["func_va"], 0)
        except (TypeError, ValueError):
            return False
        if verified_ea != ea:
            return False
        # _inspect_function_via_mcp tags the payload with its pointer-size probe;
        # the normal preprocess_common_skill emit path drops it, so drop it here
        # too or the artifact byte comparison against the isolated rebuild fails.
        function.pop("_pointer_size", None)
        write_func_yaml(outputs[name], function)
    if debug:
        print(f"  {skill_name}: Host_Shutdown={hex(host_ea)} NET_Shutdown={hex(net_ea)}")
    return True
