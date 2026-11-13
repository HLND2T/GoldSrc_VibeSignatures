#!/usr/bin/env python3
"""Locate callable MapStarted/ClearSoundArrays entries, never inline copies.

Neither body owns a useful string or distinctive float set. Each target uses
three ordered body patterns across Sven 8948/10257 Windows/Linux, below the
four-pattern budget. Member displacements and call targets are wildcarded.

ClearSoundArrays: MSVC memset(size=0x104000, value=0), GCC 8948's aligned
rep-stos expansion of the same statement, GCC 10257's stack-argument memset.
The size is independently verified as 4096 sound paths of 260 bytes in all
four current binaries. Subsequent channel/sound/sentence destruction and the
trailing count/flag/time resets distinguish the method from generic memset.

MapStarted: MSVC's conditional ClearSoundArrays call followed by engine time
and an x87 member store; GCC 8948's stack-adjusting equivalent; GCC 10257's
outgoing-stack equivalent. Windows inlines IsNewMap (strip level name then
compare cached name); Linux calls it. The guard skips clearing on the same
map, but always writes map-start time. Cross-check the direct callee (through
the 8948 ELF PLT when needed) against the independently located clear entry.

Both methods are void __thiscall(void *this) on Windows and
void __cdecl(void *this) on Linux i386. No extra x87 input argument exists:
Hex-Rays can infer one incorrectly from an untyped engine GetClientTime.
All four binaries retain independent full entries; no absent/inline alias is
needed. Only output-signature generation may extend a function boundary.
"""

from ida_analyze_util import parse_mcp_result
from ida_preprocessor_scripts._client_body_patterns import preprocess_body_patterns

SIGNATURES = {
    "CClient_SoundEngine_ClearSoundArrays": [
        "68 00 40 10 00 6A 00 8D 83 ?? ?? ?? ?? 50 E8 ?? ?? ?? ?? 8B B3 ?? ?? ?? ?? 83 C4 0C 85 F6",
        "81 C1 00 40 10 00 C1 E9 02 31 C0 F3 AB",
        "C7 44 24 08 00 40 10 00 C7 44 24 04 00 00 00 00 89 34 24 E8 ?? ?? ?? ??",
    ],
    "CClient_SoundEngine_MapStarted": [
        "85 C0 74 ?? 8B CE E8 ?? ?? ?? ?? FF 15 ?? ?? ?? ?? 8B 8C 24 ?? ?? ?? ?? D9 9E ?? ?? ?? ??",
        "84 C0 74 ?? 83 EC 0C 56 E8 ?? ?? ?? ?? 83 C4 10 8B 83 ?? ?? ?? ?? FF 90 D8 00 00 00 D9 9E ?? ?? ?? ??",
        "84 C0 74 ?? 89 1C 24 E8 ?? ?? ?? ?? 8D 86 ?? ?? ?? ?? FF 90 D8 00 00 00 D9 9B ?? ?? ?? ??",
    ],
}
TARGET_FUNCTION_NAMES = list(SIGNATURES)

VERIFY = r"""
def verify(owners):
    import ida_bytes, ida_funcs, ida_segment, ida_ua, idautils, idc
    clear, started = [owners['CClient_SoundEngine_' + n] for n in ('ClearSoundArrays', 'MapStarted')]
    def instructions(ea):
        result = []
        for item in idautils.FuncItems(ea):
            insn = ida_ua.insn_t()
            if not ida_ua.decode_insn(insn, item):
                raise ValueError('undecodable instruction')
            result.append((item, idc.print_insn_mnem(item).lower(), insn))
        return result
    def direct_target(insn):
        if insn.ops[0].type != ida_ua.o_near:
            return None
        target = int(insn.ops[0].addr)
        segment = ida_segment.getseg(target)
        if segment and ida_segment.get_segm_name(segment).startswith('.plt'):
            targets = {int(x.to) for x in idautils.XrefsFrom(target) if not x.iscode}
            targets = {int(ida_bytes.get_dword(t)) for t in targets}
            targets = {t for t in targets if ida_funcs.get_func(t) and ida_funcs.get_func(t).start_ea == t}
            return next(iter(targets)) if len(targets) == 1 else None
        return target
    clear_code, map_code = instructions(clear), instructions(started)
    zeroes = {(int(i.ops[0].addr), ida_ua.get_dtype_size(i.ops[0].dtype))
              for _, m, i in clear_code if m == 'mov' and i.ops[0].type == ida_ua.o_displ
              and i.ops[1].type == ida_ua.o_imm and int(i.ops[1].value) == 0}
    # Verified object layout: list head, sentence/material counts and loaded flag.
    if not {(0x11b00c, 4), (0x11b09c, 4), (0x11b0a0, 4), (0x11b011, 1)} <= zeroes:
        return False
    def time_stores(code):
        # IDA may expose st(0) before the printed memory destination.
        return [(ea, int(op.addr)) for ea, m, i in code if m == 'fstp'
                for op in i.ops if op.type == ida_ua.o_displ
                and ida_ua.get_dtype_size(op.dtype) == 4]
    if [offset for _, offset in time_stores(clear_code)] != [0x11b014]:
        return False
    if [offset for _, offset in time_stores(map_code)] != [0x11b018]:
        return False
    calls = [ea for ea, m, i in map_code if m == 'call' and direct_target(i) == clear]
    if len(calls) != 1:
        return False
    call = calls[0]
    # An equality guard must bypass precisely the clearing arm, before time update.
    guards = [int(i.ops[0].addr) for ea, m, i in map_code
              if m in ('jz', 'je') and ea < call < int(i.ops[0].addr)]
    time_ea = time_stores(map_code)[0][0]
    return len(guards) == 1 and any(guards[0] <= ea < time_ea and m == 'call'
                                  and i.ops[0].type in (ida_ua.o_mem, ida_ua.o_displ)
                                  for ea, m, i in map_code)
import json
result = json.dumps({'valid': verify(OWNERS)})
"""


async def validate_owners(session, owners):
    payload = parse_mcp_result(await session.call_tool("py_eval", {"code": VERIFY.replace("OWNERS", repr(owners))}))
    return isinstance(payload, dict) and payload.get("valid") is True


async def preprocess_skill(
    session, skill_name, expected_outputs, old_yaml_map, new_binary_dir, platform, image_base, debug=False
):
    _ = skill_name, old_yaml_map, new_binary_dir, platform
    return await preprocess_body_patterns(
        session, expected_outputs, SIGNATURES, image_base, debug, validate_owners=validate_owners
    )
