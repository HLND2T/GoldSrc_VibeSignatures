"""Pinned GL-enum signature generation shared by the renderer draw finders."""

CUSTOM_SIG = r"""
import idautils, ida_funcs, ida_bytes, ida_ua, ida_segment, idaapi, json

def unique_at(ea, tokens, seg_end):
    signature = " ".join(tokens)
    cur = idaapi.get_imagebase()
    match = None
    while True:
        found = ida_bytes.find_bytes(signature, cur, range_end=seg_end, radix=16,
                                     flags=ida_bytes.BIN_SEARCH_FORWARD | ida_bytes.BIN_SEARCH_NOSHOW)
        if found == idaapi.BADADDR:
            break
        if match is not None:
            return False
        match = found
        cur = found + 1
    return match == ea

out = {}
for name, ea in TARGETS.items():
    ea = int(ea, 0)
    function = ida_funcs.get_func(ea)
    if not function or int(function.start_ea) != ea:
        out[name + "_error"] = "not a function start"
        continue
    segment = ida_segment.getseg(ea)
    seg_end = int(segment.end_ea) if segment else ea + 0x10000
    tokens, bounds = [], []
    for pc in idautils.FuncItems(ea):
        insn = ida_ua.insn_t()
        if ida_ua.decode_insn(insn, pc) <= 0:
            break
        raw = list(ida_bytes.get_bytes(pc, insn.size) or b"")
        wild = set()
        operands = [op for op in insn.ops if int(op.type) != 0]
        for index, op in enumerate(operands):
            op_type = int(op.type)
            # Immediates stay fixed (GL enum ABI); only relocatable operands
            # (absolute memory/rel32/disp32) move, and registers never do.
            if op_type not in (int(idaapi.o_mem), int(idaapi.o_near), int(idaapi.o_far), int(idaapi.o_displ)):
                continue
            offb = int(op.offb or 0)
            end = int(operands[index + 1].offb or 0) if index + 1 < len(operands) else insn.size
            if end <= offb:
                end = insn.size
            wild.update(range(offb, end))
        for index, byte in enumerate(raw):
            tokens.append("??" if index in wild else "%02X" % byte)
        bounds.append(len(tokens))
    lo, hi = 0, len(bounds) - 1
    best = None
    while lo <= hi:
        mid = (lo + hi) // 2
        if bounds[mid] >= 6 and unique_at(ea, tokens[:bounds[mid]], seg_end):
            best = tokens[:bounds[mid]]
            hi = mid - 1
        else:
            lo = mid + 1
    if best is None:
        out[name + "_error"] = "no unique signature"
    else:
        out[name] = {"func_va": hex(ea), "func_size": int(function.end_ea) - ea, "func_sig": " ".join(best)}
print(MARKER + json.dumps(out))
"""
