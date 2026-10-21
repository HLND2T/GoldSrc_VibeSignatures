"""IDA-side semantic collection. No build switches, old signatures or fixed RVAs."""

COLLECT = r"""
import ida_frame, ida_typeinf

def method(ea):
    if ea not in cache:cache[ea]=traced(ea)
    return cache[ea]

def labels(ea):
    return {text for text,evidence in literals.items() if ea in evidence['owners']}

def anchored(*texts):
    return unique(set.intersection(*(set(literals[t]['owners']) for t in texts)), 'owner '+str(texts))

def calls(ea):return method(ea)['calls']

def references(call,text):
    addresses={('const',a) for a in literals[text]['addresses']}
    if not any(a in addresses for a in call['stack_args']):return False
    target_name=ida_name.get_name(call['direct']).lstrip('_') if call['direct'] else ''
    index={'sprintf':1,'snprintf':2,'sprintf_chk':3,'snprintf_chk':4}.get(target_name)
    if index is not None:return call['stack_args'][index] in addresses
    owner=ida_funcs.get_func(call['ea']).start_ea
    return any(call['block']<=ref<call['ea'] and not any(ref<other['ea']<call['ea'] for other in calls(owner))
               for ref in literals[text]['sites'])

def named_call(call,text):
    target=call['direct']
    if target:
        name=ida_name.get_name(target)
        return name.lstrip('_')==text.lstrip('_')
    value=call['target']
    return bool(value and value[0]=='load' and value[1] and value[1][0]=='const'
                and ida_name.get_name(value[1][1]).lstrip('_')==text.lstrip('_'))

def copy_calls(ea,offset=None):
    found=[]
    for c in calls(ea):
        a=c['stack_args']
        if not named_call(c,'strncpy') or not a[0] or a[0][:2]!=('address',THIS):continue
        if offset is not None and a[0][2]!=offset:continue
        if not a[2] or a[2][0]!='const':raise ValueError('unknown name copy capacity')
        end=('address',THIS,a[0][2]+a[2][1]-1)
        if not any(s['address']==end and s['width']==1 and s['value']==('const',0)
                   and s['ea']>c['ea'] for s in method(ea)['stores']):
            raise ValueError('name copy lacks matching terminator')
        found.append(c)
    return found

def explicit_symbol(name):
    ea=ida_name.get_name_ea(idaapi.BADADDR,name)
    if ea==idaapi.BADADDR:raise ValueError('missing ELF public entry '+name)
    f=ida_funcs.get_func(ea)
    if not f or f.start_ea!=ea:raise ValueError('ELF symbol is not a complete entry')
    return int(ea)

def capacity(ea,destination,explicit=None):
    if not destination or destination[0]!='stack':raise ValueError('output is not a local buffer')
    f=ida_funcs.get_func(ea);frame=ida_typeinf.tinfo_t()
    if not ida_frame.get_func_frame(frame,f):raise ValueError('missing stack frame')
    start=destination[1]+f.frsize+f.frregs
    members=sorted((m.offset//8,m.size//8) for m in frame.iter_udt())
    boundary=relocated_stack_boundary(start,[offset for offset,size in members],frame_relocations.get(ea,{}))
    try:return checked_capacity(start,boundary,explicit)
    except ValueError as exc:raise ValueError(str(exc)+': '+hex(ea)+' '+repr((start,boundary,explicit)))

def primary_returns(ea):
    f=ida_funcs.get_func(ea)
    return sorted({int(idautils.DecodeInstruction(a).ops[0].value)
                   if idautils.DecodeInstruction(a).ops[0].type==idaapi.o_imm else 0
                   for a in idautils.Heads(f.start_ea,f.end_ea)
                   if idc.print_insn_mnem(a) in ('ret','retn')})

def normalize_population(ea):
    # ILocalize::ConvertANSIToUnicode has three explicit stack arguments.
    # Its output is then the ProfileButton constructor's wide label. Older
    # IDBs can count the loop's saved EBX as a fourth argument, shifting every
    # subsequent local by four bytes and fabricating a 60-byte command buffer.
    # Prove both the raw pushes and the shared output/consumer buffer before
    # correcting only this call in our trace; never edit/save the source IDB.
    if values['platform']!='windows':return
    body=method(ea)
    constructors=[c for c in body['calls'] if references(c,'ProfileButton')]
    ctor=unique(constructors,'profile button constructor')
    candidates=[]
    for c in body['calls']:
        args=c['stack_args']
        if c['direct'] or c['ea']>=ctor['ea'] or not c['this'] or c['this'][0]!='result':continue
        if not args[1] or args[1][0]!='stack' or not args[2] or args[2][0]!='const':continue
        getter=next((g for g in body['calls'] if g['ea']==c['this'][1]),None)
        if not getter or not getter['direct'] or getter['block']!=c['block']:continue
        returned={r['value'] for r in method(getter['direct'])['returns']}
        if primary_returns(getter['direct'])!=[0] or len(returned)!=1:continue
        value=next(iter(returned))
        if not value or value[0]!='load' or not value[1] or value[1][0]!='const':continue
        items=list(idautils.Heads(getter['ea']+idc.get_item_size(getter['ea']),c['ea']))
        if any(idc.print_insn_mnem(a).startswith(('call','j','ret')) for a in items):continue
        pushes=[a for a in items if idc.print_insn_mnem(a)=='push']
        if len(pushes)!=3:continue
        if any(idc.print_insn_mnem(a) in ('pop','add','sub','mov','lea')
               and idc.print_operand(a,0)=='esp' for a in items):continue
        inferred=ida_frame.get_spd(ida_funcs.get_func(ea),c['ea']+idc.get_item_size(c['ea']))-ida_frame.get_spd(ida_funcs.get_func(ea),c['ea'])
        purge=reconciled_call_cleanup(args[1],ctor['stack_args'][2],inferred,len(pushes))
        candidates.append((c,purge,inferred))
    # Other compiler layouts need no override. Their ordinary frame/capacity
    # checks still apply; an unproven correction must never be attempted.
    if not candidates:return
    conversion,purge,inferred=unique(candidates,'localized profile label producer')
    if purge==inferred:return
    call=conversion['ea']
    # Capacity/copy evidence concerns the populated loop's first iteration.
    # The empty-list path never executes this producer; exclude that path so
    # its uncorrected depth cannot merge with the corrected populated path.
    blocks=first_pass_blocks([dict(start=b,succs=s,insns=[]) for b,s in body['blocks'].items()],ea)
    excluded=edges_bypassing_block({b['start']:b['succs'] for b in blocks},conversion['block'])
    cache[ea]=traced(ea,{call:purge},excluded)
    converted=unique([c for c in calls(ea) if c['ea']==call],'corrected label conversion')
    consumed=unique([c for c in calls(ea) if c['ea']==ctor['ea']],'corrected label consumer')
    if converted['stack_args'][1]!=consumed['stack_args'][2]:
        raise ValueError('Corrected localization output is not the constructor label')
    # A stale frame can contain both the old and corrected names of one object.
    # Relocate only bases independently observed at the same decoded LEA before
    # and after correction; preserve every unrelated frame boundary.
    f=ida_funcs.get_func(ea);origin=f.frsize+f.frregs
    previous={a['ea']:a['value'] for a in body['addresses']}
    relocations={}
    for a in cache[ea]['addresses']:
        before=previous.get(a['ea']);after=a['value']
        if before and after and before[0]=='stack' and after[0]=='stack':
            relocations.setdefault(before[1]+origin,set()).add(after[1]+origin)
    frame_relocations[ea]=relocations

def add_function(stem,display,ea,purge,table=None):
    returns=primary_returns(ea)
    tail_only=(not returns and purge==0 and values['platform']=='linux'
               and any(c['tail'] and c['stack_args'][0]==THIS for c in calls(ea)))
    if returns!=[purge] and not tail_only:raise ValueError(display+': primary cleanup mismatch')
    f=ida_funcs.get_func(ea)
    record=dict(ea=ea,display=display,size=f.size(),cleanup=purge,
                status='standalone',native_name=ida_name.get_name(ea),
                calling_convention='thiscall' if values['platform']=='windows' else 'cdecl',
                this_location='ECX' if values['platform']=='windows' else 'stack[0]',
                return_type='bool in AL' if stem in ('CCareerGame_SaveProfile','CCareerGame_LoadProfile')
                            else 'native profile pointer in EAX' if stem=='CCareerGame_GetProfileForName'
                            else 'int profile count in EAX' if stem=='CCareerProfileFrame_PopulateProfiles' else 'void')
    if table:
        slots=[int(i) for i,a in table['vtable_entries'].items() if int(a,0)==ea]
        record.update(table=table['vtable_class'],index=unique(slots,'actual virtual slot'))
    functions[stem]=record

def add_site(group,owner,c,semantic,dest=None,limit=None,fmt=None):
    ea=c['ea'];insn=idautils.DecodeInstruction(ea)
    if not insn or idc.print_insn_mnem(ea)!='call':raise ValueError('not an actual CALL')
    raw=ida_bytes.get_bytes(ea,insn.size)
    strategy=branch_strategy(raw,semantic)
    if semantic in ('profile_path','config_command','selection_command'):
        fmt_index=unique([i for i,a in enumerate(c['stack_args'])
                          if a in {('const',v) for v in literals[fmt]['addresses']}],'formatter ABI position')
        abi=({1:1,3:3} if semantic=='profile_path' else {2:2,4:4}).get(fmt_index)
        if abi is None:raise ValueError('unsupported formatting ABI')
    else:
        abi={'selected_name_copy':5,'button_selection_command':6,
             'enumeration_open':7 if values['platform']=='windows' else 8,
             'enumeration_read':9,'enumeration_read_registers':10,'resume_name_set':11}[semantic]
    # The API's original-target decoder cannot resolve register-relative calls.
    # Their wrappers resolve the target from the actual public receiver/table.
    record=dict(ea=ea,owner=owner,semantic=semantic,length=insn.size,
                original_bytes=raw.hex(' '),instruction=idc.generate_disasm_line(ea,0),
                strategy=strategy,abi=abi,target=c['target'],direct=c['direct'],
                stack_args=c['stack_args'],registers=c['registers'],receiver=c['this'])
    if dest is not None:record['capacity']=capacity(owner,dest,limit)
    if fmt is not None:record['format']=fmt
    groups.setdefault(group,[]).append(record)

texts=('%s/CZProfile-%s.czp','%s/CZProfile-*.czp','%s/%s','wb','rb','CZP',
       'writecfg Save/%s\n','wait\nexec Save/%s.cfg\n','#Career_CorruptSaveTitle',
       'SelectProfileAndFocus %s','ReallyCreateProfile','SelectProfile ',
       'SelectProfileAndFocus ','ResumeProfile','name','SelectProfile %s','Ok','CreateProfile',
       'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ_-0123456789','exec config.cfg\n','ProfileButton')
literals={t:literal_evidence(t) for t in texts}
cache={};functions={};groups={};scalars={};members={};frame_relocations={}
if not literals['%s/CZProfile-*.czp']['owners']:
    if any(literals[t]['owners'] for t in texts[:2]):raise ValueError('partial Career implementation')
    result=dict(absent=True)
else:
    path=set(literals[texts[0]]['owners'])
    save=anchored(texts[0],'writecfg Save/%s\n')
    errors=set(literals['#Career_CorruptSaveTitle']['owners'])
    load=unique([ea for ea in path if ea in errors or any(c['direct'] in errors for c in calls(ea))], 'load with corrupt-save branch')
    blank_candidates=[ea for ea in path-{save,load} if any(c['direct'] in literals['CZP']['owners']
                      and len(c['args'])>=5 and c['args'][4]==('const',1) for c in calls(ea))]
    if not blank_candidates and values['platform']=='linux':
        public_blank=explicit_symbol('_ZN11CCareerGame18CreateBlankProfileEv')
        if public_blank in path:blank_candidates=[public_blank]
    create=unique(blank_candidates,'blank serializer')
    remaining=path-{save,load,create}
    query=unique([ea for ea in remaining if ea in literals['CZP']['owners'] or any(
                  c['direct'] in set(literals['CZP']['owners'])|set(literals['rb']['owners']) for c in calls(ea))], 'profile lookup')
    delete=unique(remaining-{query},'profile removal')
    build=anchored('%s/CZProfile-*.czp')
    populate=anchored('SelectProfileAndFocus %s')
    normalize_population(populate)
    double=anchored('SelectProfile %s','ResumeProfile')
    command=anchored('ReallyCreateProfile','SelectProfile ','ResumeProfile')
    send=anchored('wait\nexec Save/%s.cfg\n')
    # SelectProfile source is captured before the independent 32-byte button copy.
    candidates={c['direct'] for c in calls(populate) if c['direct']}
    setters=[ea for ea in candidates if len(copy_calls(ea))==1 and len(calls(ea))==1
             and copy_calls(ea)[0]['stack_args'][1]==('arg',1)
             and len([s for s in method(ea)['stores'] if s['width']==1 and s['address']
                      and s['address'][0] not in ('stack','const')])==1]
    button_set=unique(setters,'button raw-name setter')
    button_copy=unique(copy_calls(button_set),'button copy')
    button_offset=button_copy['stack_args'][0][2]
    name_capacity=button_copy['stack_args'][2][1]
    if values['platform']=='linux':
        selected=explicit_symbol('_ZN19CCareerProfileFrame21UpdateSelectedProfileEPKc')
    else:
        selected=unique({c['direct'] for c in calls(command) if c['direct']
                         and len(copy_calls(c['direct']))==1
                         and copy_calls(c['direct'])[0]['stack_args'][1]==('arg',1)},'selection setter')
    selected_copy=unique(copy_calls(selected),'selection copy')
    selected_offset=selected_copy['stack_args'][0][2]
    if selected_copy['stack_args'][2]!=('const',name_capacity):raise ValueError('name capacities differ')
    members['CProfileButton_m_name']=dict(struct='CProfileButton',member='m_name',offset=button_offset,size=name_capacity)
    members['CCareerProfileFrame_m_name']=dict(struct='CCareerProfileFrame',member='m_name',offset=selected_offset,size=name_capacity)
    active=[s for s in method(selected)['stores'] if s['width']==1 and s['value']!=('const',0)
            and s['address'] and s['address'][0] in ('choice','address')]
    active_offsets={v[2] for s in active for v in alternatives(s['address'])
                    if v and v[0]=='address' and v[1]!=THIS}
    active_offset=unique(active_offsets,'profile active byte')
    members['CProfileButton_m_active']=dict(struct='CProfileButton',member='m_active',offset=active_offset,size=1)
    scalars.update(CProfileButton_name_capacity=name_capacity,CCareerProfileFrame_selected_name_capacity=name_capacity)
    win=values['platform']=='windows'
    entries=[('CCareerGame_CreateBlankProfile','CCareerGame::CreateBlankProfile()',create,0),
             ('CCareerGame_SaveProfile','CCareerGame::SaveProfile(bool)',save,4 if win else 0),
             ('CCareerGame_LoadProfile','CCareerGame::LoadProfile(CareerDifficultyType)',load,4 if win else 0),
             ('CCareerGame_GetProfileForName','CCareerGame::GetProfileForName(char const*)',query,4 if win else 0),
             ('CCareerGame_DeleteProfile','CCareerGame::DeleteProfile(char const*)',delete,4 if win else 0),
             ('CCareerGame_SendMatchCommand','CCareerGame::SendMatchCommand()',send,0),
             ('CCareerProfileFrame_PopulateProfiles','CCareerProfileFrame::PopulateProfiles()',populate,0),
             ('CProfileButton_SetProfileName','CProfileButton::SetProfileName(char const*)',button_set,4 if win else 0),
             ('CCareerProfileFrame_UpdateSelectedProfile','CCareerProfileFrame::UpdateSelectedProfile(char const*)',selected,4 if win else 0)]
    for stem,display,ea,purge in entries:add_function(stem,display,ea,purge)
    add_function('CCareerProfileFrame_OnCommand','CCareerProfileFrame::OnCommand(char const*)',command,4 if win else 0,values['tables']['CCareerProfileFrame'])
    newtable=values['tables']['CCareerNewProfileBox']
    # Derive the inherited OnCommand slot from the current profile frame table.
    slot=functions['CCareerProfileFrame_OnCommand']['index']
    new_command=int(newtable['vtable_entries'][str(slot)],0)
    if new_command not in set(literals['Ok']['owners']) & set(literals['CreateProfile']['owners']):
        raise ValueError('new profile virtual slot lacks input-validation command semantics')
    if not any(references(c,'name') for c in calls(create)):raise ValueError('create lacks raw name input')
    add_function('CCareerNewProfileBox_OnCommand','CCareerNewProfileBox::OnCommand(char const*)',new_command,4 if win else 0,newtable)
    path_owners={'CreateBlankProfile':create,'SaveProfile':save,'LoadProfile':load,'GetProfileForName':query,'DeleteProfile':delete}
    all_paths=[]
    for owner_name,ea in path_owners.items():
        sites=[c for c in calls(ea) if references(c,texts[0])]
        for c in sites:
            args=c['stack_args'];idx=unique([i for i,v in enumerate(args) if v in {('const',a) for a in literals[texts[0]]['addresses']}],'path format argument')
            limit=args[2][1] if idx==3 and args[2] and args[2][0]=='const' else None
            if idx not in (1,3):raise ValueError('unknown profile format ABI')
            if not args[idx+1] or not args[idx+2]:raise ValueError('unknown path input')
            add_site('CCareerGame_'+owner_name+'_profile_path_format_callsite',ea,c,'profile_path',args[0],limit,texts[0])
            all_paths.append(c['ea'])
    if set(path)!=set(path_owners.values()) or len(all_paths)!=len(path):raise ValueError('uncovered profile path consumer')
    for owner_name,ea,fmt in [('SaveProfile',save,'writecfg Save/%s\n'),('SendMatchCommand',send,'wait\nexec Save/%s.cfg\n'),
                              ('PopulateProfiles',populate,'SelectProfileAndFocus %s')]:
        c=unique([c for c in calls(ea) if references(c,fmt)],'config/selection format')
        args=c['stack_args'];idx=unique([i for i,a in enumerate(args) if a in {('const',v) for v in literals[fmt]['addresses']}],'command format argument')
        if idx not in (2,4):raise ValueError('unknown bounded formatter ABI')
        if not args[1] or args[1][0]!='const':raise ValueError('missing explicit command capacity')
        group=('CCareerProfileFrame_PopulateProfiles_select_command_format_callsite' if ea==populate
               else 'CCareerGame_'+owner_name+'_config_command_format_callsite')
        add_site(group,ea,c,'selection_command' if ea==populate else 'config_command',args[0],args[1][1],fmt)
    # Include every inlined copy, including self-copy and focus/default selection paths.
    for ea in sorted({selected,populate,command}):
        for c in copy_calls(ea,selected_offset):
            add_site('CCareerProfileFrame_selected_name_copy_callsite',ea,c,'selected_name_copy')
    name_sets=[c for c in calls(command) if references(c,'name') and c['stack_args'][1]==('address',THIS,selected_offset)]
    add_site('CCareerProfileFrame_ResumeProfile_name_set_callsite',command,unique(name_sets,'resume name set'),'resume_name_set')
    double_format=unique([c for c in calls(double) if references(c,'SelectProfile %s')],'double click command')
    if double_format['stack_args'][:2]!=[('const',literals['SelectProfile %s']['addresses'][0]),('address',THIS,button_offset)]:
        raise ValueError('double click does not use the truncated button name')
    add_site('CProfileButton_OnMouseDoublePressed_select_command_format_callsite',double,double_format,'button_selection_command',fmt='SelectProfile %s')
    # An out-of-line ReadFile has a (path,int*) ABI. Inlined ReadFile exposes Open.
    enum_formats=[c for c in calls(build) if references(c,'%s/%s')]
    formatted=unique(enum_formats,'enumerated real filename')
    enum_path=formatted['stack_args'][0]
    reads=[]
    for c in calls(build):
        args=c['stack_args']
        if references(c,'rb'):
            if args[0]!=enum_path:raise ValueError('enumeration Open path differs')
            reads.append((c,'enumeration_open'))
        elif c['direct'] and args[0]==enum_path and args[1] and args[1][0]=='stack' and c['ea']>formatted['ea']:
            reads.append((c,'enumeration_read'))
        elif (not win and c['direct'] and c['registers']['eax']==enum_path
              and c['registers']['edx'] and c['registers']['edx'][0]=='stack'
              and ida_name.get_name(c['direct'])=='_ZL8ReadFilePKcRi'):
            reads.append((c,'enumeration_read_registers'))
    c,semantic=unique(reads,'enumeration read filter')
    add_site('CCareerGame_BuildProfileList_ReadFile_callsite',build,c,semantic)
    enum_idx=unique([i for i,a in enumerate(formatted['stack_args'])
                     if a in {('const',v) for v in literals['%s/%s']['addresses']}],'enumerated format position')
    scalars['CCareerGame_BuildProfileList_enumerated_path_capacity']=capacity(build,enum_path,formatted['stack_args'][2][1] if enum_idx==3 else None)
    # Query takes an already sanitized legacy key; inventory every caller and its actual input.
    query_callers=[]
    for ref in idautils.CodeRefsTo(query,False):
        f=ida_funcs.get_func(ref)
        if not f:raise ValueError('query has an ownerless caller')
        c=unique([c for c in calls(f.start_ea) if c['ea']==ref],'query caller flow')
        query_callers.append(dict(owner=f.start_ea,ea=int(ref),input=c['stack_args'][0 if win else 1]))
    if not query_callers:raise ValueError('lookup has no semantic callers')
    for group,sites in groups.items():
        sites.sort(key=lambda s:s['ea'])
        capacities={s['capacity'] for s in sites if 'capacity' in s}
        if len(capacities)>1:raise ValueError('group destination capacities disagree')
        if capacities:scalars[group+'_destination_capacity']=next(iter(capacities))
        scalars[group+'_count']=len(sites)
    sanitizer=unique(set(literals['abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ_-0123456789']['owners'])-path,'standalone legacy sanitizer')
    buffer_targets={c['direct'] for c in calls(create) if c['direct'] and len(c['args'])>=5
                    and c['args'][3] and c['args'][3][0]=='const' and c['args'][4]==('const',1)}
    buffers=buffer_targets & {c['direct'] for c in calls(save)} & set(literals['CZP']['owners'])
    clones=[]
    if not buffers and not win:
        prefix='_ZN11CCareerGame19CreateProfileBufferEP18CCareerProfileDataPhib'
        buffer=explicit_symbol(prefix)
        clones=sorted({c['direct'] for ea in (create,save) for c in calls(ea) if c['direct']
                       and ida_name.get_name(c['direct']).startswith(prefix+'.constprop.')})
        if not clones:raise ValueError('serializer has no validated callable or clone')
        buffer_limits={c['stack_args'][2][1] for ea in clones for c in calls(ea) if c['direct']
                       and ida_name.get_name(c['direct'])=='_ZN12BufferWriter4InitEPhi'
                       and c['stack_args'][2] and c['stack_args'][2][0]=='const'}
    else:
        buffer=unique(buffers,'profile serializer')
        buffer_limits={c['args'][3][1] for ea in (create,save) for c in calls(ea)
                       if c['direct']==buffer and c['args'][3] and c['args'][3][0]=='const'}
    scalars['CCareerGame_profile_buffer_capacity']=unique(buffer_limits,'serializer buffer capacity')
    legacy_copies=[c for c in calls(sanitizer) if named_call(c,'strncpy')]
    legacy_limits={c['stack_args'][2][1] for c in legacy_copies
                   if c['stack_args'][2] and c['stack_args'][2][0]=='const'}
    scalars['CCareerGame_legacy_key_capacity']=unique(legacy_limits,'legacy key capacity')
    legacy_capacity=scalars['CCareerGame_legacy_key_capacity']
    legacy_destinations={c['stack_args'][0] for c in legacy_copies}
    legacy_destination=unique(legacy_destinations,'legacy shared buffer')
    if not legacy_destination or legacy_destination[0]!='const':raise ValueError('legacy buffer is not static storage')
    stores=method(sanitizer)['stores']
    if not any(s['address']==('const',legacy_destination[1]+legacy_capacity-1) and s['width']==1
               and s['value']==('const',0) for s in stores):raise ValueError('legacy key lacks end-of-buffer NUL')
    if not any(s['address']==legacy_destination and s['width']==1 and s['value']==('const',ord('_')) for s in stores):
        raise ValueError('legacy key replacement rule differs')
    if not any(named_call(c,'strstr') and c['stack_args'][0] in {
                ('const',a) for a in literals['abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ_-0123456789']['addresses']}
               for c in calls(sanitizer)):raise ValueError('legacy whitelist lookup differs')
    if not any(('const',legacy_capacity-1) in c['values'] for c in method(sanitizer)['comparisons']):
        raise ValueError('legacy truncation loop bound differs')
    for caller in query_callers:
        value=caller['input']
        provenance=[c for c in calls(caller['owner']) if value==('result',c['ea']) and c['direct']==sanitizer]
        source=unique(provenance,'query legacy-key provenance')
        caller.update(input_semantic='LegacyKey',raw_input=source['stack_args'][0],sanitizer_call=source['ea'])
    scalars['CCareerGame_u8hex_storage_contract_version']=1
    if win:
        parser=unique({c['direct'] for c in calls(load) if c['direct'] and c['direct'] in literals['CZP']['owners']},'profile parser')
        stop=anchored('exec config.cfg\n')
    else:
        parser=explicit_symbol('_ZN11CCareerGame17ParseSavedProfileEPKhiP18CCareerProfileData')
        stop=explicit_symbol('_ZN11CCareerGame9StopMatchEii')
    analysis_functions={name:dict(ea=ea,size=ida_funcs.get_func(ea).size(),native_name=ida_name.get_name(ea),cleanup=primary_returns(ea))
                        for name,ea in [('CCareerGame::GetSaveGamePlayerName(char const*)',sanitizer),
                                       ('CCareerGame::BuildProfileList()',build),
                                       ('CCareerGame::CreateProfileBuffer(CCareerProfileData*, unsigned char*, int, bool)',buffer),
                                       ('CCareerGame::ParseSavedProfile(unsigned char const*, int, CCareerProfileData*)',parser),
                                       ('CCareerGame::StopMatch(int, int)',stop),
                                       ('CProfileButton::OnMouseDoublePressed(vgui2::MouseCode)',double)]}
    for ea in clones:analysis_functions[ida_name.get_name(ea)]=dict(ea=ea,size=ida_funcs.get_func(ea).size(),native_name=ida_name.get_name(ea),cleanup=primary_returns(ea),status='clone')
    result=dict(absent=False,functions=functions,groups=groups,scalars=scalars,members=members,
                query_callers=query_callers,analysis_functions=analysis_functions,literals=literals)
"""
