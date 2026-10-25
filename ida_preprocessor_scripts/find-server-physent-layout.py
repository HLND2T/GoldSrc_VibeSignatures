#!/usr/bin/env python3
"""Derive private ELF rewrite layouts from the current area's x86 dataflow.

No layout is copied from a build table or from IDA types. The bounded affine
walk follows PM/client pointers and stack spills through basic blocks. Array
strides, incremented counts, capacity branches and lag-compensation reads must
agree before any scalar is published. The three fixed SDK structs need no
member signatures. Unknown instructions/merges lose provenance and fail closed.
"""

from ida_analyze_util import _load_yaml_mapping, _output_for_symbol, write_scalar_yaml
from ida_preprocessor_scripts._engine_private_globals_common import run_walk

SCALARS = [
    "playermove_t_numphysent_offset",
    "playermove_t_physents_offset",
    "playermove_t_physents_count",
    "playermove_t_nummoveent_offset",
    "playermove_t_moveents_offset",
    "playermove_t_moveents_count",
    "playermove_t_numvisent_offset",
    "playermove_t_visents_offset",
    "client_t_active_offset",
    "client_t_lw_offset",
    "client_t_lc_offset",
    "truepositions_element_size",
    "truepositions_active_offset",
    "truepositions_needrelink_offset",
    "truepositions_oldorg_offset",
    "truepositions_oldabsmin_offset",
    "truepositions_oldabsmax_offset",
]

WALK = r"""
import ida_gdl, math

REGS = ('eax','ecx','edx','ebx','esp','ebp','esi','edi')
def expr(c=0, terms=()):
    return (c, tuple(sorted((k,v) for k,v in dict(terms).items() if v)))
def unknown(k):
    return expr(0, ((str(k),1),))
def add(a,b,scale=1):
    terms=dict(a[1])
    for k,v in b[1]: terms[k]=terms.get(k,0)+scale*v
    return expr(a[0]+scale*b[0], terms.items())
def mul(a,n): return expr(a[0]*n, ((k,v*n) for k,v in a[1]))
def address(op, state):
    if int(op.type)==int(idaapi.o_mem) and not int(op.specflag1): return expr(int(op.addr))
    if int(op.type) not in (int(idaapi.o_mem),int(idaapi.o_displ),int(idaapi.o_phrase)): return None
    base=expr(signed32(op.addr) if int(op.type) in (int(idaapi.o_mem),int(idaapi.o_displ)) else 0)
    if int(op.specflag1):
        sib=int(op.specflag2)
        # IDA represents a SIB with no base (e.g. [edi*8]) as o_mem.
        if int(op.type)!=int(idaapi.o_mem): base=add(base,state[REGS[sib&7]])
        if (sib>>3)&7 != 4: base=add(base,mul(state[REGS[(sib>>3)&7]],1<<(sib>>6)))
        return base
    return add(base,state[reg4(op)])
def stack_key(a):
    return 'stack:'+repr(a) if a is not None and any(k=='entry:esp' for k,v in a[1]) else None

start=values['owner']
pm,client,positions=(values[n] for n in ('pmove','host_client','truepositions'))
entries=scan(start)
blocks=list(ida_gdl.FlowChart(ida_funcs.get_func(start)))
by_block={int(b.start_ea):[e for e in entries if int(b.start_ea)<=e['ea']<int(b.end_ea)] for b in blocks}
got,gotreg=got_anchor(start)
initial={r:unknown('entry:'+r) for r in REGS}
if got is not None: initial[gotreg]=expr(got)

def execute(block,state,collect=False):
    state=dict(state)
    for entry in by_block[block]:
        ea,insn,m=entry['ea'],entry['insn'],entry['mnem']
        dst,src=insn.ops[0],insn.ops[1]
        addresses={i:address(op,state) for i,op in enumerate(insn.ops) if int(op.type) in (int(idaapi.o_mem),int(idaapi.o_displ),int(idaapi.o_phrase))}
        if collect:
            for i,a in addresses.items():
                if a is not None: accesses.append((ea,m,i,a,changed_operand(insn,i)))
            if m=='cmp' and int(dst.type)==int(idaapi.o_reg) and int(src.type)==int(idaapi.o_imm):
                comparisons.append((ea,state[reg4(dst)],int(src.value)))
        def value(op,index):
            if int(op.type)==int(idaapi.o_reg): return state.get(reg4(op),unknown('reg:'+str(op.reg)))
            if int(op.type)==int(idaapi.o_imm): return expr(signed32(op.value))
            a=addresses.get(index)
            key=stack_key(a)
            if key is not None: return state.get(key,unknown(key))
            if a is not None:
                if not a[1]:
                    if a[0]==pm: return unknown('PM')
                    if a[0]==client: return unknown('CLIENT')
                    if is_got(a[0]): return expr(int(ida_bytes.get_dword(a[0])))
                terms=dict(a[1])
                if terms=={'PM':1}: return unknown('PMFIELD:'+str(a[0]))
            return unknown('load:'+hex(ea))
        incoming=None
        if m in ('mov','movss','movsd','movzx','movsx'): incoming=value(src,1)
        elif m=='lea': incoming=addresses.get(1)
        elif m=='xor' and int(dst.type)==int(idaapi.o_reg) and int(src.type)==int(idaapi.o_reg) and reg4(dst)==reg4(src): incoming=expr()
        elif m in ('add','sub') and int(dst.type)==int(idaapi.o_reg): incoming=add(state[reg4(dst)],value(src,1),1 if m=='add' else -1)
        elif m in ('inc','dec') and int(dst.type)==int(idaapi.o_reg): incoming=add(state[reg4(dst)],expr(1 if m=='inc' else -1))
        elif m in ('shl','sal') and int(dst.type)==int(idaapi.o_reg) and int(src.type)==int(idaapi.o_imm): incoming=mul(state[reg4(dst)],1<<int(src.value))
        elif m=='imul' and int(dst.type)==int(idaapi.o_reg):
            if int(insn.ops[2].type)==int(idaapi.o_imm): incoming=mul(value(src,1),signed32(insn.ops[2].value))
            elif int(src.type)==int(idaapi.o_imm): incoming=mul(state[reg4(dst)],signed32(src.value))
        if collect and m in ('add','sub') and incoming is not None:
            accesses.append((ea,'address',1,incoming,False))
        if m=='push':
            pushed=value(dst,0)
            state['esp']=add(state['esp'],expr(-4))
            key=stack_key(state['esp'])
            if key: state[key]=pushed
        elif m=='pop':
            key=stack_key(state['esp'])
            incoming=state.get(key,unknown('pop:'+hex(ea)))
            state['esp']=add(state['esp'],expr(4))
        if m=='call':
            for r in ('eax','ecx','edx'): state[r]=unknown('call:'+hex(ea)+r)
        for i,op in enumerate(insn.ops):
            if int(op.type)==int(idaapi.o_reg) and changed_operand(insn,i):
                r=reg4(op)
                if r in REGS and r!=gotreg:
                    state[r]=incoming if i==0 and incoming is not None else unknown('write:'+hex(ea)+r)
        key=stack_key(addresses.get(0))
        if key and changed_operand(insn,0): state[key]=incoming if incoming is not None else unknown('store:'+hex(ea))
    return state

states={}
for iteration in range(64):
    changed=False
    for b in blocks:
        begin=int(b.start_ea)
        predecessors=[states[int(p.start_ea)] for p in b.preds() if int(p.start_ea) in states]
        if begin==start: predecessors.append(initial)
        if not predecessors: continue
        merged={}
        for key in set().union(*(set(s) for s in predecessors)):
            vals=[s.get(key) for s in predecessors]
            merged[key]=vals[0] if vals[0] is not None and all(v==vals[0] for v in vals) else unknown('phi:'+str(begin)+key)
        new=execute(begin,merged)
        if states.get(begin)!=new: states[begin]=new; changed=True
    if not changed: break
else: raise ValueError('affine flow did not converge')
accesses,comparisons=[],[]
for b in blocks:
    begin=int(b.start_ea)
    predecessors=[states[int(p.start_ea)] for p in b.preds() if int(p.start_ea) in states]
    if begin==start: predecessors.append(initial)
    if not predecessors: continue
    merged={}
    for key in set().union(*(set(s) for s in predecessors)):
        vals=[s.get(key) for s in predecessors]
        merged[key]=vals[0] if vals[0] is not None and all(v==vals[0] for v in vals) else unknown('phi:'+str(begin)+key)
    execute(begin,merged,True)

counts=sorted({a[0] for ea,m,i,a,w in accesses if m=='mov' and i==1 and dict(a[1])=={'PM':1}})
if len(counts)!=3: raise ValueError('expected three PM count reads: '+repr(counts))
strides={abs(v) for ea,m,i,a,w in accesses for k,v in a[1] if k.startswith('PMFIELD:') and dict(a[1]).get('PM')==1 and v}
if len(strides)!=1: raise ValueError('PM array stride ambiguous: '+repr(strides))
stride=strides.pop()
# Fixed SDK physent_t is 224 bytes. This is validation, never a locator.
if stride!=224: raise ValueError('fixed physent_t size disagrees with current indexing: '+repr((stride,[(hex(ea),m,a) for ea,m,i,a,w in accesses if any(k.startswith('PMFIELD:') for k,v in a[1])][:12])))
metadata={}
for name,offset in zip(('physent','moveent','visent'),counts):
    array=name+'s'
    if not any(dict(a[1]).get('PM')==1 and dict(a[1]).get('PMFIELD:'+str(offset))==stride and a[0]==offset+4 for ea,m,i,a,w in accesses):
        raise ValueError('PM count lacks corresponding array: '+name)
    metadata['playermove_t_num'+name+'_offset']=offset
    metadata['playermove_t_'+array+'_offset']=offset+4
for j,name in enumerate(('physents','moveents')):
    numerator=counts[j+1]-counts[j]-4
    if numerator<=0 or numerator%stride: raise ValueError('invalid contiguous PM array')
    capacity=numerator//stride
    guards=[]
    for ea,a,limit in comparisons:
        if a!=(0,(('PMFIELD:'+str(counts[j]),1),)): continue
        branch=(idc.print_insn_mnem(idc.next_head(ea)) or '').lower()
        if branch in ('jg','ja','jle','jbe'): guards.append(limit+1)
        elif branch in ('jge','jae','jl','jb'): guards.append(limit)
    if not guards or set(guards)!={capacity}: raise ValueError('capacity guard disagrees with array extent: '+repr((name,capacity,guards)))
    metadata['playermove_t_'+name+'_count']=capacity
client_fields=sorted({a[0] for ea,m,i,a,w in accesses if m=='mov' and i==1 and dict(a[1])=={'CLIENT':1}})
if len(client_fields)!=3 or client_fields[0]!=0 or client_fields[2]-client_fields[1]!=4:
    raise ValueError('lag-compensation client field reads ambiguous: '+repr(client_fields))
for name,offset in zip(('active','lw','lc'),client_fields): metadata['client_t_'+name+'_offset']=offset
position_accesses=[(m,a) for ea,m,i,a,w in accesses if abs(a[0]-positions)<65536 and a[1] and not any(k in ('PM','CLIENT') or k.startswith('entry:') for k,v in a[1])]
coefficients=[abs(v) for m,a in position_accesses for k,v in a[1] if v]
step=math.gcd(*coefficients) if coefficients else 0
if step<=4: raise ValueError('truepositions index stride unresolved: '+repr(coefficients))
reads={((a[0]-positions)%step) for m,a in position_accesses if m in ('mov','movss')}
addresses={((a[0]-positions)%step) for m,a in position_accesses if m in ('lea','address')}
vectors=sorted(x for x in reads if x>4)
absolutes=sorted(addresses-{0})
if reads & {0,4}!={0,4} or len(vectors)!=3 or vectors!=list(range(vectors[0],vectors[0]+12,4)) or len(absolutes)!=2 or absolutes[1]-absolutes[0]!=12:
    raise ValueError('truepositions origin/bounds reads disagree: '+repr((step,reads,addresses)))
metadata.update(truepositions_element_size=step,truepositions_active_offset=0,truepositions_needrelink_offset=4,truepositions_oldorg_offset=vectors[0],truepositions_oldabsmin_offset=absolutes[0],truepositions_oldabsmax_offset=absolutes[1])
result={'scalars':metadata}
"""


async def preprocess_skill(
    session, skill_name, expected_outputs, old_yaml_map, new_binary_dir, platform, image_base, debug=False
):
    _ = old_yaml_map, image_base
    values = {}
    for name, category in [
        ("SV_AddLinksToPM_", "func"),
        ("pmove", "gv"),
        ("host_client", "gv"),
        ("truepositions", "gv"),
    ]:
        data = _load_yaml_mapping(f"{new_binary_dir}/{name}.{platform}.yaml")
        if not data or f"{category}_va" not in data:
            return False
        values["owner" if category == "func" else name] = int(data[f"{category}_va"], 0)
    located = await run_walk(session, WALK, values)
    if debug:
        print(f"{skill_name}: {located}")
    if located.get("error") or set(located.get("scalars", {})) != set(SCALARS):
        return False
    for name, value in located["scalars"].items():
        output = _output_for_symbol(expected_outputs, name)
        if output is None:
            return False
        write_scalar_yaml(output, {"scalar_name": name, "scalar_value": value})
    return True
