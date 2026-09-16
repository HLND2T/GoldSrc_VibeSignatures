"""Self-contained IDA-side helpers for locally resolved ELF indirections."""

ELF_RESOLVER_PY = r"""
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
globals().update({'resolve_elf_plt': resolve_elf_plt, 'elf_code_refs_to': elf_code_refs_to, 'elf_data_refs_to': elf_data_refs_to})
"""
