#!/usr/bin/env python3
"""Locate server-row owners and their locale date-formatting calls.

Discover row writers from the player-count literal, then verify strftime's
four cdecl arguments and the same buffer's LastPlayed write. ServerResponded
gets the server from a parameter; ApplyGameFilters iterates stored servers.
Some older builds do not format dates in ApplyGameFilters. Never
invent that callsite or assign the modern two-argument ABI to the old callback.
"""

from ida_analyze_util import _output_for_symbol, write_patch_yaml
from ida_preprocessor_scripts._patch_signature_common import run_signature
from ida_preprocessor_scripts._vgui_paint_common import walk, write_function

FUNCTIONS = ("CBaseGamesPage_ServerResponded", "CBaseGamesPage_ApplyGameFilters")

WALK = r"""
import ida_name

def literal(value):
    if value and value[0]=='const':
        return idc.get_strlit_contents(value[1],-1,ida_nalt.STRTYPE_C)
    return None

def literals(owner):
    return {idc.get_strlit_contents(ref,-1,ida_nalt.STRTYPE_C)
            for ea in idautils.FuncItems(owner) for ref in idautils.DataRefsFrom(ea)}

def fetched_server(value, receiver):
    if not isinstance(value,tuple): return False
    if value[0]=='result': return True
    if value[0]=='load' and value[1]==receiver and value[2]>0: return True
    if value[0]=='choice': return any(fetched_server(part,receiver) for part in value[1:])
    return False

def cleanup(flow):
    # Use reachable CFG returns: include shared tails outside the main chunk,
    # but exclude detached MSVC exception handlers.
    return {int(insn.ops[0].value) if insn.ops[0].type==idaapi.o_imm else 0
            for returned in flow['returns']
            for insn in [idautils.DecodeInstruction(returned['ea'])]}

owners=set()
strings=idautils.Strings(default_setup=False)
strings.setup(strtypes=[ida_nalt.STRTYPE_C],minlen=4)
for s in strings:
    if str(s)=='%d / %d':
        for x in idautils.XrefsTo(s.ea):
            f=ida_funcs.get_func(x.frm)
            if f: owners.add(int(f.start_ea))
rows=[]
for owner in sorted(owners):
    if not {b'GameDir',b'GameDesc',b'password',b'bots'}.issubset(literals(owner)):
        continue
    entry=None
    if values['platform']=='windows':
        entry={('stack',4*(i+1)):('arg',i+1) for i in range(MAX_ARGUMENTS)}
        entry.update(ecx=('arg',0),eax=('entry_register','eax'))
    flow=flow_at(owner,values['platform'],first_pass=True,entry_state=entry)
    calls=flow['calls']
    dates=[]
    for call_index, call in enumerate(calls):
        args=call['stack_args']
        if literal(args[2])!=b'%a %d %b %I:%M%p': continue
        tm=args[3]
        if not tm or tm[0]!='result': continue
        # GCC leaves outgoing cdecl slots live across later zero-argument
        # calls (notably __ctype_tolower_loc). Only the first call consuming
        # localtime's result is the formatter, not those stale stack slots.
        if not call_index or calls[call_index-1]['ea']!=tm[1]: continue
        if args[1]!=('const',64) or not args[0] or args[0][0]!='stack':
            raise ValueError('invalid strftime buffer/size')
        timecalls=[c for c in calls if c['ea']==tm[1]]
        if len(timecalls)!=1: raise ValueError('time producer is ambiguous')
        source=timecalls[0]['stack_args'][0]
        key_index=0 if values['platform']=='windows' else 1
        writes=[c for c in calls if literal(c['stack_args'][key_index])==b'LastPlayed'
                and c['stack_args'][key_index+1]==args[0]]
        if len(writes)!=1: raise ValueError('date buffer does not reach a unique LastPlayed write')
        dates.append(dict(ea=call['ea'],source=source))
    if len(dates)>1: raise ValueError('multiple date calls in one row owner')
    rows.append(dict(owner=owner,dates=dates,cleanup=sorted(cleanup(flow)),calls=calls))
responded=[]
for row in rows:
    if not row['dates']: continue
    source=row['dates'][0]['source']
    if source and source[0]=='address' and source[1] in (('arg',1),('arg',2)):
        row['server_arg']=source[1][1]
        responded.append(row)
if len(responded)!=1: raise ValueError('server parameter owner is ambiguous: '+repr(rows))
response=responded[0]
filter_slots=set()
for call in response['calls']:
    target=call['target']
    if (target and target[0]=='load' and target[1] and target[1][0]=='load'
        and target[1][1]==('arg',0) and call['stack_args'][0]==('arg',response['server_arg'])):
        filter_slots.add(target[2])
filter_rows=[]
for row in rows:
    if row is response: continue
    if row['dates'] and values['platform']=='linux':
        row['this_arg']=0
        filter_rows.append(row)
        continue
    # Older filter loops omit LastPlayed. Recover their filter dispatch slots
    # from ServerResponded, not a fixed vtable layout. They must pass a fetched
    # server to both filters on the same incoming page object. Some LTCG builds
    # put that object on the stack or in EAX rather than in ECX.
    groups={}
    for call in row['calls']:
        target=call['target']; receiver=call['this']; server=call['stack_args'][0]
        if (receiver in (('arg',0),('arg',1),('entry_register','eax')) and fetched_server(server,receiver)
            and target and target[0]=='load' and target[1]==('load',receiver,0)):
            groups.setdefault((receiver,server),set()).add(target[2])
    hits=[receiver for (receiver,server),slots in groups.items()
          if len(filter_slots)==2 and filter_slots.issubset(slots)]
    if len(hits)==1:
        row['this_arg']=hits[0][1]
        filter_rows.append(row)
if len(filter_rows)!=1: raise ValueError('filter owner is ambiguous')
filters=filter_rows[0]
if values['platform']=='windows':
    if not filters['cleanup']:
        # Sven tail-calls its final Panel method. Resolve the actual slot in
        # this IDB's primary table and verify its return, rather than assuming
        # that an absent RET means a no-argument method.
        tails=[c for c in filters['calls'] if c['tail']]
        table=ida_name.get_name_ea(idaapi.BADADDR,'??_7CBaseGamesPage@@6B@')
        if len(tails)==1 and table!=idaapi.BADADDR:
            tail=tails[0]; target=tail['target']
            f=ida_funcs.get_func(filters['owner'])
            receiver=('entry_register','eax') if filters['this_arg']=='eax' else ('arg',filters['this_arg'])
            if (tail['this']==receiver and target and target[0]=='load'
                and target[1]==('load',receiver,0)
                and target[2]>=0 and target[2]%4==0
                and ida_frame.get_spd(f,tail['ea'])==0):
                callee=ida_bytes.get_dword(table+target[2])
                filters['cleanup']=sorted(cleanup(flow_at(callee,'windows',first_pass=True)))
    filter_purge=4 if filters['this_arg']==1 else 0
    if response['cleanup']!=[4*response['server_arg']] or filters['cleanup']!=[filter_purge]:
        raise ValueError('unexpected owner ABI: '+repr((response['cleanup'],filters['cleanup'],filters['this_arg'])))
elif not filters['dates']:
    raise ValueError('unsupported legacy Linux row writer')
for row in (response,filters): del row['calls']
result={'response':response,'filters':filters}
"""


async def preprocess_skill(
    session, skill_name, expected_outputs, old_yaml_map, new_binary_dir, platform, image_base, debug=False
):
    located = await walk(session, WALK, {"platform": platform})
    if debug:
        print(f"{skill_name}: {located}")
    if located.get("error") or not all(key in located for key in ("response", "filters")):
        return False
    for symbol, key in zip(FUNCTIONS, ("response", "filters")):
        row = located[key]
        display = symbol.replace("CBaseGamesPage_", "CBaseGamesPage::")
        if not await write_function(session, expected_outputs, symbol, display, row["owner"], image_base):
            return False
        patch = symbol + "_to_strftime_callsite_0"
        output = _output_for_symbol(expected_outputs, patch)
        if not row["dates"]:
            if output is not None:
                return False
            continue
        if output is None:
            return False
        ea = row["dates"][0]["ea"]
        signature = await run_signature(session, ea)
        if not signature:
            return False
        write_patch_yaml(
            output,
            dict(patch_name=patch, patch_va=hex(ea), patch_rva=hex(ea - image_base), **signature),
        )
    return True
