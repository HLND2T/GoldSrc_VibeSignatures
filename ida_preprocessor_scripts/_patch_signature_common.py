"""Shared unique-instruction signatures for the engine patch finders.

Both engine patch finders locate one exact instruction and need a unique
``patch_sig`` for it. ``CANDIDATE_PY`` returns progressively longer forward byte
tokens for the instruction (operand displacements wildcarded); ``run_signature``
validates each candidate with the MCP byte search and returns the first that
matches exactly one location, so callers fail closed on any MCP failure.
"""

import json

from ida_analyze_util import _find_unique_bytes, parse_mcp_result

CANDIDATE_PY = r"""
import ida_bytes, idaapi, idautils, json

TARGET_EA = TARGET_EA_PLACEHOLDER
MAX_SIG_BYTES = 96
MAX_INSTRUCTIONS = 64


def wildcard_instruction(insn, raw_bytes):
    wild = set()
    offsets = sorted({int(getattr(op, 'offb', 0)) for op in insn.ops
                      if int(op.type) != int(idaapi.o_void) and int(getattr(op, 'offb', 0)) > 0}
                     | {int(insn.size)})
    for op in insn.ops:
        ot = int(op.type)
        if ot == int(idaapi.o_void):
            continue
        if ot in (int(idaapi.o_imm), int(idaapi.o_near), int(idaapi.o_far), int(idaapi.o_mem), int(idaapi.o_displ)):
            offb = int(getattr(op, 'offb', 0))
            if offb > 0 and offb < insn.size:
                # dtype describes the data, not the encoded address/immediate.
                # Bound the field by the next operand or the instruction end.
                end = next(offset for offset in offsets if offset > offb)
                for index in range(offb, end):
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

def candidates(target):
    tokens = []
    boundaries = []
    cursor = int(target)
    count = 0
    while len(tokens) < MAX_SIG_BYTES and count < MAX_INSTRUCTIONS:
        insn = idautils.DecodeInstruction(cursor)
        if not insn or insn.size <= 0:
            break
        raw = ida_bytes.get_bytes(cursor, insn.size)
        if not raw:
            break
        for token in wildcard_instruction(insn, raw):
            if len(tokens) < MAX_SIG_BYTES:
                tokens.append(token)
        boundaries.append(len(tokens))
        cursor += insn.size
        count += 1
    return [' '.join(tokens[:boundary]) for boundary in boundaries]


json.dumps(candidates(TARGET_EA))
"""


async def run_signature(session, ea):
    """Return {'patch_sig', 'patch_sig_disp'} for one instruction, else None."""
    code = CANDIDATE_PY.replace("TARGET_EA_PLACEHOLDER", str(int(ea)))
    try:
        payload = parse_mcp_result(await session.call_tool("py_eval", {"code": code}))
    except Exception:  # noqa: BLE001 - MCP failures must fail closed.
        return None
    if isinstance(payload, str):
        try:
            payload = json.loads(payload)
        except (TypeError, ValueError):
            return None
    if not isinstance(payload, list):
        return None
    candidates = payload
    for pattern in candidates:
        if not isinstance(pattern, str) or not pattern.strip():
            continue
        if len(pattern.split()) < 4:
            continue
        if await _find_unique_bytes(session, pattern) == int(ea):
            return {"patch_sig": pattern, "patch_sig_disp": 0}
    return None
