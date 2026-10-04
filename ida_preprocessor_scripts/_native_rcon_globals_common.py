"""Current x86 dataflow checks for the approved native RCON global anchors.

The selected instruction remains the runtime signature anchor. Layout scalars
are derived from current operands before LLM selection, never from a peer layout.
"""

from ida_analyze_util import (
    _INSPECT_FUNCTION_PY_EVAL,
    _find_unique_bytes,
    _load_yaml_mapping,
    _output_for_symbol,
    parse_mcp_result,
    preprocess_common_skill,
    write_gv_yaml,
)
from ida_preprocessor_scripts._native_rcon_common import verify_function
from ida_preprocessor_scripts._native_rcon_path_common import locate_path_functions
from ida_preprocessor_scripts.renderer_elf_symbols import preserve_global_identities
from llm_spec import select_llm_specs
from scalar_artifact import SCALAR_FIELDS

GV_FIELDS = [
    "gv_name",
    "gv_va",
    "gv_rva",
    "gv_sig",
    "gv_sig_va",
    "gv_inst_offset",
    "gv_inst_length",
    "gv_inst_disp",
    "gv_sig_allow_across_function_boundary:true",
]

GLOBAL_PY = r"""
def one(items, role):
    if len(items)!=1:
        raise ValueError('ambiguous current '+role+': '+repr(items))
    return next(iter(items))

def address_value(entry, operand, registers):
    op=entry['insn'].ops[operand]
    if int(op.type)==int(idaapi.o_reg):
        return registers.get(reg4(op))
    if int(op.type)==int(idaapi.o_imm):
        value=int(op.value)&0xFFFFFFFF
        return ('address' if value in entry['targets'] and not is_got(value) else 'constant',value)
    if int(op.type) in (int(idaapi.o_mem),int(idaapi.o_displ),int(idaapi.o_phrase)):
        if len(entry['targets'])==1:
            address=next(iter(entry['targets']))
            if not is_got(address):
                # A GOT load carries the object address. A later member load
                # through that register carries its contents. PIC displacements
                # do not themselves equal the GOT slot's absolute address.
                got_pointer=any(is_got(int(ref)) for ref in idautils.DataRefsFrom(entry['ea']))
                return ('address' if entry['mnem']=='lea' or got_pointer else 'load',address)
    return None

def call_arguments(start):
    # Track cdecl pushes and GCC outgoing slots. Symbols describe the current
    # loaded field or object address, not its contents. This is deliberately
    # bounded to scalar moves; unmodelled values stay unknown.
    registers={}
    stack={}
    bias=0
    frame=None
    result=[]
    for entry in scan(start) or []:
        insn,mnemonic=entry['insn'],entry['mnem']
        dst,src=insn.ops[0],insn.ops[1]
        value=address_value(entry,1,registers)
        if mnemonic=='push':
            pushed=address_value(entry,0,registers)
            bias-=4
            stack[bias]=pushed
        elif mnemonic=='pop':
            registers.pop(reg4(dst),None)
            bias+=4
        elif mnemonic in ('add','sub') and int(dst.type)==int(idaapi.o_reg) and reg4(dst)=='esp' and immediate(entry) is not None:
            bias+=(1 if mnemonic=='add' else -1)*int(src.value)
        elif mnemonic=='mov' and int(dst.type)==int(idaapi.o_reg) and reg4(dst)=='ebp' and int(src.type)==int(idaapi.o_reg) and reg4(src)=='esp':
            frame=bias
        elif mnemonic in ('mov','lea') and int(dst.type)==int(idaapi.o_reg):
            registers.pop(reg4(dst),None)
            if value is not None:
                registers[reg4(dst)]=value
        elif mnemonic=='xor' and int(dst.type)==int(idaapi.o_reg) and int(src.type)==int(idaapi.o_reg) and reg4(dst)==reg4(src):
            registers[reg4(dst)]=('constant',0)
        elif mnemonic=='mov' and int(dst.type) in (int(idaapi.o_displ),int(idaapi.o_phrase)):
            origin=bias if reg4(dst)=='esp' else frame if reg4(dst)=='ebp' else None
            if origin is not None:
                stack[origin+(signed32(dst.addr) if int(dst.type)==int(idaapi.o_displ) else 0)]=value
        else:
            # Arithmetic and other unmodelled register writes invalidate the
            # old origin instead of carrying a plausible but stale field value.
            for index,operand in enumerate(insn.ops):
                if int(operand.type)==int(idaapi.o_void):
                    break
                if int(operand.type)==int(idaapi.o_reg) and changed_operand(insn,index):
                    registers.pop(reg4(operand),None)
        if mnemonic=='call':
            target=local_call_target(entry['ea'])
            if target is not None:
                result.append((target,[stack.get(bias+4*i) for i in range(3)]))
            for reg in ('eax','ecx','edx'):
                registers.pop(reg,None)
    return result

def current_message_layout(ban,send):
    calls=call_arguments(ban)
    args=one({tuple(args) for target,args in calls if target==send},'ban native send arguments')
    if args[0]!=('constant',1) or any(arg is None or arg[0]!='load' for arg in args[1:]):
        raise ValueError('native NS_SERVER send must load length and data fields: '+repr(args))
    init=one(literal_owners('net_message'),'NET_Init literal owner')
    # The same whole object is passed to the pre/post clear and message writers.
    # A member load is not an object pointer and cannot enter this candidate set.
    object_uses={}
    for target,arguments in calls:
        arg=arguments[0]
        if target!=send and arg is not None and arg[0]=='address':
            object_uses.setdefault(arg[1],[]).append(target)
    candidates={address for address,targets in object_uses.items()
                if len(set(targets))>1 and len(targets)>len(set(targets)) and address in all_globals(init)}
    message=one(candidates,'initialized and repeatedly cleared message object')
    offsets={'sizebuf_t_data_offset':args[2][1]-message,'sizebuf_t_cursize_offset':args[1][1]-message}
    if any(offset<0 or offset>0xFFFFFFFF for offset in offsets.values()) or len(set(offsets.values()))!=2:
        raise ValueError('invalid current sizebuf field layout')
    return message,offsets

def current_server_layout(poller,clear):
    cleared={args[0][1]:args[2][1] for target,args in call_arguments(clear)
             if args[0] is not None and args[0][0]=='address' and args[1]==('constant',0)
             and args[2] is not None and args[2][0] in ('constant','address') and args[2][1]>0}
    reads=set()
    for entry in scan(poller) or []:
        if entry['mnem'] not in ('mov','cmp') or entry['written']:
            continue
        if any(int(op.type) in (int(idaapi.o_mem),int(idaapi.o_displ)) and operand_width(op)==4 for op in entry['insn'].ops):
            reads.update(entry['targets'])
    matches={(base,address) for base,size in cleared.items() for address in reads if base<=address<base+size}
    base,active=one(matches,'whole server clear and poller active guard')
    return base,{'sv_active_offset':active-base}

def check_globals(group,addresses,owners):
    if group=='message':
        message,offsets=current_message_layout(owners['SV_SendBan'],owners['NET_SendPacket'])
        if addresses['net_message']!=message or addresses['net_from'] not in all_globals(owners['NET_GetPacket']):
            raise ValueError('message/source disagrees with current native queue dataflow')
    elif group=='poller':
        server,offsets=current_server_layout(owners['SV_CheckForRcon'],owners['Host_ClearMemory'])
        if addresses['sv']!=server:
            raise ValueError('sv must be the independently cleared whole object')
        state=addresses['giActive']
        states=register_values(owners['SV_CheckForRcon'])
        close_checks=set()
        for entry in scan(owners['SV_CheckForRcon']) or []:
            if entry['mnem']=='cmp' and immediate(entry)==3:
                operand=entry['insn'].ops[0]
                if int(operand.type)==int(idaapi.o_reg):
                    value=states[entry['ea']].get(reg4(operand))
                    if value and value[0]=='global':
                        close_checks.add(value[1])
                else:
                    close_checks.update(entry['targets'])
        if state!=one(close_checks,'DLL_CLOSE guard') or state not in all_globals(owners['Host_Init']):
            raise ValueError('giActive does not match initialization/close state')
    elif group=='redirect':
        mode,output=redirect_storage(owners['SV_FlushRedirect'])
        if addresses['sv_redirected']!=mode or addresses['outputbuf']!=output:
            raise ValueError('redirect mode/output disagrees with current flush operands')
        if addresses['sv_redirectto'] not in all_globals(owners['SV_FlushRedirect']):
            raise ValueError('redirect reply address absent from native flush')
    elif group=='socket':
        if addresses['ip_sockets'] not in all_globals(owners['NET_Config']):
            raise ValueError('IP array base absent from native network configuration')
    elif group=='sven_socket':
        if owners['Sock_Config'] not in native_rcon_edges(owners['NET_Config']):
            raise ValueError('Sock_Config is not the current NET_Config transport callee')
        if addresses['ip_sockets'] not in all_globals(owners['Sock_Config']):
            raise ValueError('IP array base absent from native socket configuration')
"""


async def preprocess_globals(
    session,
    expected_outputs,
    new_binary_dir,
    platform,
    image_base,
    group,
    names,
    owner_names,
    llm_config,
    debug,
    *,
    llm_decompile_specs,
):
    owners = {}
    for name in owner_names:
        context = await verify_function(session, new_binary_dir, platform, image_base, name)
        if context is None:
            return False
        owners[name] = context["owner_ea"]
    located = await locate_path_functions(
        session,
        GLOBAL_PY
        + """
offsets={}
if values['group']=='message':
    _,offsets=current_message_layout(values['owners']['SV_SendBan'],values['owners']['NET_SendPacket'])
elif values['group']=='poller':
    _,offsets=current_server_layout(values['owners']['SV_CheckForRcon'],values['owners']['Host_ClearMemory'])
result={'scalars':offsets}
""",
        {"group": group, "owners": owners},
    )
    if located.get("error") or not isinstance(located.get("scalars"), dict):
        if debug:
            print(located)
        return False
    scalars = located["scalars"]
    found = await preprocess_common_skill(
        session=session,
        expected_outputs=expected_outputs,
        old_yaml_map=None,
        new_binary_dir=new_binary_dir,
        platform=platform,
        image_base=image_base,
        gv_names=names,
        scalar_names=list(scalars),
        llm_decompile_specs=select_llm_specs(llm_decompile_specs, expected_values=scalars),
        llm_config=llm_config,
        debug=debug,
        generate_yaml_desired_fields=[(name, GV_FIELDS) for name in names]
        + [(name, list(SCALAR_FIELDS)) for name in scalars],
    )
    if not found:
        return False
    addresses = {}
    for name in names:
        output = _output_for_symbol(expected_outputs, name)
        payload = _load_yaml_mapping(output) if output else None
        if not payload:
            return False
        addresses[name] = int(payload["gv_va"], 0)
    checked = await locate_path_functions(
        session,
        GLOBAL_PY
        + """
check_globals(values['group'],values['addresses'],values['owners'])
result={'valid':True}
""",
        {"group": group, "owners": owners, "addresses": addresses},
    )
    if checked.get("valid") is not True:
        if debug:
            print(checked)
        return False
    # The generic LLM mapper records a verified owner signature plus an access
    # offset. Part C publishes signatures beginning at the selected access itself.
    # Retain its already decoded absolute/PIC resolution fields, then independently
    # require a unique current-input match and a wildcarded four-byte operand.
    for name in names:
        output = _output_for_symbol(expected_outputs, name)
        payload = _load_yaml_mapping(output)
        instruction = int(payload["gv_sig_va"], 0) + int(payload["gv_inst_offset"], 0)
        signature = None
        across = False
        for across in (False, True):
            # Reuse the repository's operand wildcarding and bounded executable
            # segment/padding walk. The owner is an already verified real entry;
            # the access instruction is never treated as a new function.
            source = (
                _INSPECT_FUNCTION_PY_EVAL.replace("EA_PLACEHOLDER", payload["gv_sig_va"])
                .replace("IMAGE_BASE_PLACEHOLDER", str(int(image_base)))
                .replace("ALLOW_ACROSS_FUNCTION_BOUNDARY_PLACEHOLDER", str(across))
            )
            source += f"\nresult=json.dumps({{'signature': _signature({instruction}, int(func.end_ea)) if func is not None else None}})"
            generated = parse_mcp_result(await session.call_tool("py_eval", {"code": source}))
            candidate = generated.get("signature") if isinstance(generated, dict) else None
            displacement = int(payload["gv_inst_disp"], 0)
            if not candidate or candidate.split()[displacement : displacement + 4] != ["??"] * 4:
                continue
            if await _find_unique_bytes(session, candidate) == instruction:
                signature = candidate
                break
        if signature is None:
            return False
        payload.update(gv_sig=signature, gv_sig_va=hex(instruction), gv_inst_offset="0x0")
        payload.pop("gv_sig_allow_across_function_boundary", None)
        if across:
            payload["gv_sig_allow_across_function_boundary"] = True
        write_gv_yaml(output, payload)
    return await preserve_global_identities(
        session, [_output_for_symbol(expected_outputs, name) for name in names], platform
    )
