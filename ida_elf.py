"""Self-contained IDA-side helpers for locally resolved ELF indirections."""

ELF_RESOLVER_PY = r"""
def resolve_elf_got_thunk(ea):
    import ida_bytes, ida_funcs, ida_segment, idaapi, ida_ida
    invalid = (idaapi.BADADDR, idaapi.BADADDR)
    if ida_ida.inf_is_64bit():
        return invalid
    ea = int(ea)
    segment = ida_segment.getseg(ea)
    function = ida_funcs.get_func(ea)
    if (segment is None or ida_segment.get_segm_name(segment) != '.plt.got'
            or function is None or int(function.start_ea) != ea
            or int(function.end_ea) - ea != 6):
        return invalid
    raw = ida_bytes.get_bytes(ea, 6)
    # Only the ELF32 i386 ABI's jmp [ebx+disp32], not an arbitrary PIC jump.
    if raw is None or raw[:2] != b'\xff\xa3':
        return invalid
    got = ida_segment.get_segm_by_name('.got.plt')
    if got is None or got.perm & ida_segment.SEGPERM_EXEC:
        return invalid
    base = int(got.start_ea)
    if any(not ida_bytes.is_loaded(base + offset) for offset in range(4)):
        return invalid
    # GOT[0] points at _DYNAMIC even when IDA folds .dynamic into a LOAD segment.
    dynamic = int(ida_bytes.get_dword(base))
    dynamic_segment = ida_segment.getseg(dynamic)
    if dynamic_segment is None or dynamic_segment.perm & ida_segment.SEGPERM_EXEC:
        return invalid
    got_values = []
    terminated = False
    for address in range(dynamic, int(dynamic_segment.end_ea) - 7, 8):
        if any(not ida_bytes.is_loaded(address + offset) for offset in range(8)):
            return invalid
        tag = int(ida_bytes.get_dword(address))
        if tag == 0:  # DT_NULL
            terminated = True
            break
        if tag == 3:  # DT_PLTGOT
            got_values.append(int(ida_bytes.get_dword(address + 4)))
    if not terminated or got_values != [base]:
        return invalid
    slot = (base + int.from_bytes(raw[2:], 'little', signed=True)) & 0xffffffff
    slot_segment = ida_segment.getseg(slot)
    if (slot % 4 or slot_segment is None
            or ida_segment.get_segm_name(slot_segment) not in ('.got', '.got.plt')
            or slot + 4 > slot_segment.end_ea
            or any(not ida_bytes.is_loaded(slot + offset) for offset in range(4))):
        return invalid
    target = int(ida_bytes.get_dword(slot))
    import idautils
    # Require the loader's relocated code-pointer evidence, not just a dword.
    if set(int(ref) for ref in idautils.DataRefsFrom(slot)) != {target}:
        return invalid
    target_segment = ida_segment.getseg(target)
    target_function = ida_funcs.get_func(target)
    if (target_segment is None or not target_segment.perm & ida_segment.SEGPERM_EXEC
            or ida_segment.get_segm_name(target_segment).startswith('.plt')
            or target_function is None or int(target_function.start_ea) != target):
        return invalid
    return target, slot

def resolve_elf_plt(ea):
    import ida_bytes, ida_funcs, ida_segment, idaapi
    ea = int(ea)
    segment = ida_segment.getseg(ea)
    if segment is None or not ida_segment.get_segm_name(segment).startswith('.plt'):
        return ea
    function = ida_funcs.get_func(ea)
    if function is None or int(function.start_ea) != ea:
        return ea
    target, slot = ida_funcs.calc_thunk_func_target(function)
    if target == idaapi.BADADDR or slot == idaapi.BADADDR:
        target, slot = resolve_elf_got_thunk(ea)
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

def elf_code_refs_to(ea):
    import ida_bytes, ida_segment, idautils
    refs = set()
    for ref in idautils.CodeRefsTo(ea, 0):
        segment = ida_segment.getseg(ref)
        if segment is None or not ida_segment.get_segm_name(segment).startswith('.plt'):
            refs.add(int(ref))
    for slot in idautils.DataRefsTo(ea):
        segment = ida_segment.getseg(slot)
        if (segment is None or ida_segment.get_segm_name(segment) not in ('.got', '.got.plt')
                or int(ida_bytes.get_dword(slot)) != ea):
            continue
        for stub in idautils.DataRefsTo(slot):
            if resolve_elf_plt(stub) == ea:
                refs.update(int(ref) for ref in idautils.CodeRefsTo(stub, 0))
    return sorted(refs)

def elf_data_refs_to(ea):
    import ida_bytes, ida_segment, idautils
    refs = set(int(ref.frm) for ref in idautils.XrefsTo(ea, 0))
    for slot in list(refs):
        segment = ida_segment.getseg(slot)
        if (segment is not None and ida_segment.get_segm_name(segment) in ('.got', '.got.plt')
                and int(ida_bytes.get_dword(slot)) == ea):
            refs.update(int(ref.frm) for ref in idautils.XrefsTo(slot, 0))
    return sorted(refs)
globals().update({'resolve_elf_got_thunk': resolve_elf_got_thunk, 'resolve_elf_plt': resolve_elf_plt, 'elf_code_refs_to': elf_code_refs_to, 'elf_data_refs_to': elf_data_refs_to})
"""
