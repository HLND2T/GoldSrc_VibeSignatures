"""Current x86 cdecl registration arguments, including pooled string suffixes."""

REGISTRATION_QUERY = r"""
def registered_callbacks(label):
    import ida_bytes,ida_funcs,ida_gdl,ida_segment,ida_ua,idautils,idc
    def function(value):
        segment=ida_segment.getseg(value) if isinstance(value,int) and 0<=value<=0xffffffff else None
        if segment is None or not (segment.perm & ida_segment.SEGPERM_EXEC): return False
        owner=ida_funcs.get_func(value)
        if owner is None:
            flags=ida_bytes.get_full_flags(value)
            if ida_bytes.is_code(flags) or ida_bytes.is_unknown(flags): ida_funcs.add_func(value)
            owner=ida_funcs.get_func(value)
        return owner is not None and owner.start_ea==value
    # GCC may pool "centerview" into "force_centerview". The registration
    # operand still points at the exact NUL-terminated label, not its prefix.
    strings={int(s.ea)+len(str(s).encode('utf-8'))-len(label.encode('utf-8'))
             for s in idautils.Strings() if str(s).endswith(label)}
    strings={ea for ea in strings if ida_bytes.get_bytes(ea,len(label)+1)==label.encode('ascii')+b'\0'}
    owners={ida_funcs.get_func(x).start_ea for s in strings for x in idautils.DataRefsTo(s) if ida_funcs.get_func(x)}
    callbacks=set()
    for owner in owners:
        for block in ida_gdl.FlowChart(ida_funcs.get_func(owner)):
            registers={}; stack={}; pushed=[]
            for ea in idautils.Heads(block.start_ea,block.end_ea):
                insn=idautils.DecodeInstruction(ea)
                if not insn: break
                mnemonic=idc.print_insn_mnem(ea).lower()
                dest,source=insn.ops[0],insn.ops[1]
                if mnemonic=='call':
                    if dest.type in (ida_ua.o_mem,ida_ua.o_displ,ida_ua.o_reg):
                        pairs=[(stack.get(0),stack.get(4))]
                        if len(pushed)>=2: pairs.append((pushed[-1],pushed[-2]))
                        for name,callback in pairs:
                            if name in strings and function(callback): callbacks.add(callback)
                    registers={}; stack={}; pushed=[]
                    continue
                if mnemonic=='push':
                    pushed.append(int(dest.value) if dest.type==ida_ua.o_imm else registers.get(dest.reg) if dest.type==ida_ua.o_reg else None)
                    continue
                value=None
                if mnemonic=='lea':
                    refs={int(x) for x in idautils.DataRefsFrom(ea) if x in strings or function(x)}
                    if len(refs)==1: value=refs.pop()
                elif mnemonic=='mov':
                    value=int(source.value) if source.type==ida_ua.o_imm else registers.get(source.reg) if source.type==ida_ua.o_reg else None
                if dest.type==ida_ua.o_reg and mnemonic not in ('cmp','test'):
                    registers.pop(dest.reg,None)
                    if value is not None: registers[dest.reg]=value
                elif mnemonic=='mov' and dest.type in (ida_ua.o_displ,ida_ua.o_phrase) and '[esp' in idc.print_operand(ea,0).lower():
                    offset=int(dest.addr) if dest.type==ida_ua.o_displ else 0
                    stack[offset]=value
    return callbacks
"""
