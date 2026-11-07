"""Shared IDA-side x86 jump-chain validation for exports and vtable entries."""

from ida_elf import ELF_RESOLVER_PY

JMP_THUNK_RESOLVER_PY = (
    ELF_RESOLVER_PY
    + r"""
def resolve_jmp_thunk(ea, allow_undefined_target=False, strict=False):
    import ida_funcs, ida_ua, ida_bytes, ida_ida, ida_idaapi, idc
    current_ea = int(ea)
    resolved_ea = current_ea
    visited = set()
    for _ in range(8):
        if current_ea in visited:
            return None if strict else resolved_ea
        visited.add(current_ea)
        func = ida_funcs.get_func(current_ea)
        if func is None or int(func.start_ea) != current_ea:
            return None if strict else resolved_ea
        insn = ida_ua.insn_t()
        if ida_ua.decode_insn(insn, current_ea) <= 0:
            return None if strict else resolved_ea
        if (idc.print_insn_mnem(current_ea) or '').strip().lower() != 'jmp':
            return current_ea
        if insn.ops[0].type == ida_ua.o_near:
            target_ea = int(insn.ops[0].addr)
        elif insn.ops[0].type in (ida_ua.o_mem, ida_ua.o_displ) and not ida_ida.inf_is_64bit():
            target_ea, pointer_ea = ida_funcs.calc_thunk_func_target(func)
            if target_ea == ida_idaapi.BADADDR or pointer_ea == ida_idaapi.BADADDR:
                target_ea, pointer_ea = resolve_elf_got_thunk(current_ea)
                if target_ea == ida_idaapi.BADADDR or pointer_ea == ida_idaapi.BADADDR:
                    return None if strict else resolved_ea
            if (any(not ida_bytes.is_loaded(pointer_ea + offset) for offset in range(4))
                    or int(ida_bytes.get_dword(pointer_ea)) != int(target_ea)):
                return None if strict else resolved_ea
            target_ea = int(target_ea)
        else:
            return None if strict else resolved_ea
        if strict:
            import ida_segment
            segment = ida_segment.getseg(target_ea)
            if (segment is None or not segment.perm & ida_segment.SEGPERM_EXEC
                    or not ida_bytes.is_loaded(target_ea)):
                return None
        target_func = ida_funcs.get_func(target_ea)
        if target_func is None and allow_undefined_target and insn.ops[0].type == ida_ua.o_near:
            import ida_segment
            segment = ida_segment.getseg(target_ea)
            if (segment is not None and segment.perm & ida_segment.SEGPERM_EXEC
                    and ida_bytes.is_loaded(target_ea)):
                # The caller must recover and verify this exact function entry.
                return target_ea
            return None if strict else resolved_ea
        if target_func is None or int(target_func.start_ea) != target_ea:
            return None if strict else resolved_ea
        resolved_ea = current_ea = target_ea
    return None if strict else resolved_ea
"""
)
