"""Current-binary evidence for the engine's UDP download command.

The direct-global exception is deliberate: command-source stores and client
context stores are matched by argument dataflow, then corroborated in the
registered download callback. No client/netchan offsets, VAs or ELF spellings
are discovery inputs. See memory/locators/UDP download monitoring symbols.md
for the input matrix and the independent semantic audit.
"""

from ida_preprocessor_scripts._native_rcon_path_common import PATH_PY


DATAFLOW_PY = r"""
import ida_hexrays

def uncast(e):
    while e.op == ida_hexrays.cot_cast:
        e = e.x
    return e

def c_string(e):
    e = uncast(e)
    if e.op == ida_hexrays.cot_str:
        return e.string
    def address(item):
        item = uncast(item)
        if item.op == ida_hexrays.cot_obj:
            return int(item.obj_ea)
        if item.op == ida_hexrays.cot_ref:
            return address(item.x)
        if item.op == ida_hexrays.cot_idx:
            base, index = address(item.x), uncast(item.y)
            if base is not None and index.op == ida_hexrays.cot_num:
                return base + int(index.numval()) * int(item.type.get_size())
        return None
    value = address(e)
    if value is not None:
        data = ida_bytes.get_strlit_contents(value, -1, ida_nalt.STRTYPE_C)
        return data.decode('ascii', errors='replace') if data else None
    return None

class Tree(ida_hexrays.ctree_visitor_t):
    def __init__(self, start):
        super().__init__(ida_hexrays.CV_FAST)
        self.cf = ida_hexrays.decompile(start)
        if self.cf is None:
            raise ValueError('cannot verify current function dataflow: %x' % start)
        variables = self.cf.get_lvars()
        # Hex-Rays may infer live incoming registers as pseudo-parameters.
        # These source entrypoints use cdecl; only actual stack arguments count.
        self.args = sorted((i for i in self.cf.argidx if variables[i].location.is_stkoff()),
                           key=lambda i: variables[i].location.stkoff())
        self.assignments, self.calls, self.comparisons = [], [], []
        self.defs = {}
        self.apply_to(self.cf.body, None)

    def visit_expr(self, e):
        if e.op == ida_hexrays.cot_asg:
            self.assignments.append(e)
            lhs = uncast(e.x)
            if lhs.op == ida_hexrays.cot_var:
                self.defs.setdefault(int(lhs.v.idx), []).append(e.y)
        elif e.op == ida_hexrays.cot_call:
            self.calls.append(e)
        elif e.op in (ida_hexrays.cot_eq, ida_hexrays.cot_ne):
            self.comparisons.append(e)
        return 0

    def value(self, e, seen=()):
        e = uncast(e)
        if e.op == ida_hexrays.cot_num:
            return ('num', int(e.numval()) & 0xffffffff)
        if e.op == ida_hexrays.cot_obj:
            return ('global', int(e.obj_ea))
        if e.op == ida_hexrays.cot_var:
            index = int(e.v.idx)
            if index in self.args:
                return ('arg', self.args.index(index))
            definitions = self.defs.get(index, [])
            if definitions and index not in seen:
                results = {self.value(value, (*seen, index)) for value in definitions}
                if len(results) == 1:
                    return results.pop()
            return ('local', index)
        if e.op == ida_hexrays.cot_ref:
            operand = uncast(e.x)
            if operand.op == ida_hexrays.cot_obj:
                return ('num', int(operand.obj_ea))
            value = self.value(operand, seen)
            return value[1] if value[0] == 'load' else ('address', value)
        if e.op == ida_hexrays.cot_ptr:
            return ('load', self.value(e.x, seen), int(e.type.get_size()))
        if e.op == ida_hexrays.cot_memptr:
            return ('load', ('add', self.value(e.x, seen), ('num', int(e.m))), int(e.type.get_size()))
        if e.op == ida_hexrays.cot_add:
            left, right = self.value(e.x, seen), self.value(e.y, seen)
            if e.x.type.is_ptr() and right[0] == 'num':
                size = int(e.x.type.get_pointed_object().get_size())
                if size <= 0 or size > 0x100000:
                    return ('unknown', int(e.op))
                right = ('num', (right[1] * size) & 0xffffffff)
            return ('add', left, right)
        if e.op == ida_hexrays.cot_idx:
            index = self.value(e.y, seen)
            size = int(e.type.get_size())
            if index[0] != 'num' or size <= 0 or size > 0x100000:
                return ('unknown', int(e.op))
            return ('load', ('add', self.value(e.x, seen), ('num', index[1] * size)), size)
        return ('unknown', int(e.op))

    def stores(self):
        result = []
        for e in self.assignments:
            lhs = uncast(e.x)
            if lhs.op == ida_hexrays.cot_obj and int(lhs.type.get_size()) == 4:
                address = int(lhs.obj_ea)
                if address % 4 == 0 and is_writable_data(address):
                    result.append((address, self.value(e.y), int(e.ea)))
        return result

def unique(items, label):
    items = set(items)
    if len(items) != 1:
        raise ValueError('%s: expected one candidate, got %r' % (label, sorted(items)))
    return items.pop()

def relative_to(value, root):
    if value == root:
        return 0
    if value[0] == 'add':
        for base, offset in ((value[1], value[2]), (value[2], value[1])):
            if offset[0] == 'num':
                preceding = relative_to(base, root)
                if preceding is not None:
                    return (preceding + offset[1]) & 0xffffffff
    return None

"""


WALK = (
    PATH_PY
    + DATAFLOW_PY
    + r"""

def command_callback():
    registrations = set()
    # MSVC's long initializer may not decompile (unrelated inferred noreturn
    # calls truncate Hex-Rays). Its adjacent cdecl argument materialization is
    # nevertheless complete, current-binary evidence, including BLOB inputs.
    for literal in literal_addresses('dlfile'):
        for site in elf_data_refs_to(literal):
            previous = idc.prev_head(site)
            following = idc.next_head(site)
            before = idautils.DecodeInstruction(previous)
            current = idautils.DecodeInstruction(site)
            after = idautils.DecodeInstruction(following)
            if not before or not current or not after:
                continue
            if (idc.print_insn_mnem(previous) != 'push' or idc.print_insn_mnem(site) != 'push'
                    or int(before.ops[0].type) != int(idaapi.o_imm)
                    or int(current.ops[0].type) != int(idaapi.o_imm)
                    or int(current.ops[0].value) != literal or ida_bytes.get_byte(following) != 0xe8
                    or previous + before.size != site or site + current.size != following):
                continue
            callback = int(before.ops[0].value)
            function = ida_funcs.get_func(callback)
            owner = ida_funcs.get_func(site)
            if (function is not None and int(function.start_ea) == callback
                    and owner is not None and ida_funcs.get_func(previous) == owner
                    and ida_funcs.get_func(following) == owner):
                registrations.add((int(following), callback))
    for start in literal_owners('dlfile'):
        # Some command-comparison siblings are not decompilable. They cannot
        # provide a verified callback and never become fallback candidates.
        if ida_hexrays.decompile(start) is None:
            continue
        for call in Tree(start).calls:
            if len(call.a) != 2 or c_string(call.a[0]) != 'dlfile':
                continue
            callback = uncast(call.a[1])
            if callback.op != ida_hexrays.cot_obj:
                continue
            address = int(callback.obj_ea)
            function = ida_funcs.get_func(address)
            if function is not None and int(function.start_ea) == address and is_code_address(address):
                registrations.add((int(call.ea), address))
    registration, address = unique(registrations, 'dlfile registration/callback')
    if address not in literal_owners('!MD5') & literal_owners('custom.hpk'):
        raise ValueError('registered callback lacks the custom decal branch')
    return registration, address

def addressable(start, address):
    entries = [e for e in scan(start) or [] if address in e['targets']
               and e['disp'] > 0 and e['disp'] + 4 <= e['len']]
    if not entries:
        raise ValueError('no decodable storage operand for %x in %x' % (address, start))
    entry = min(entries, key=lambda e: e['ea'])
    return {'gv_ea': address, 'insn_ea': entry['ea'], 'insn_len': entry['len'],
            'insn_disp': entry['disp'], 'disasm': entry['disasm']}

registration, download = command_callback()
drop = unique(literal_owners('Dropped %s from server\nReason: %s\n')
              | literal_owners('Dropped %s from server\nReason:  %s\n'), 'SV_DropClient')
message = unique(literal_owners('Bad command character in client command'), 'client message context')
dl, msg = Tree(download), Tree(message)
download_globals = set().union(*(e['targets'] for e in scan(download)))
host = unique((address for address, value, _ in msg.stores()
               if address in download_globals and value == ('arg', 0)), 'host_client')
player = unique((address for address, value, _ in msg.stores()
                if address != host and value[0] == 'load' and value[2] == 4
                and any(relative_to(value[1], root) is not None for root in (('arg', 0), ('global', host)))),
                'sv_player = cl->edict')
player_offsets = set()
for address, value, _ in msg.stores():
    if address == player:
        for root in (('arg', 0), ('global', host)):
            offset = relative_to(value[1], root)
            if offset is not None:
                player_offsets.add(offset)
edict_offset = unique(player_offsets, 'client edict byte offset')
disconnect_calls = set()
drop_tree = Tree(drop)
for call in drop_tree.calls:
    if len(call.a) != 1:
        continue
    target = uncast(call.x)
    if target.op == ida_hexrays.cot_obj and is_code_address(int(target.obj_ea)):
        continue
    argument = drop_tree.value(call.a[0])
    if (argument[0] == 'load' and argument[2] == 4
            and relative_to(argument[1], ('arg', 0)) == edict_offset):
        disconnect_calls.add(int(call.ea))
unique(disconnect_calls, 'ClientDisconnect receives the same edict field')
sources = set()
for comparison in dl.comparisons:
    left, right = dl.value(comparison.x), dl.value(comparison.y)
    for gv, scalar in ((left, right), (right, left)):
        if gv[0] == 'global' and scalar == ('num', 1) and is_writable_data(gv[1]):
            sources.add(gv[1])
source = unique(sources, 'cmd_source == src_command')
command = int(values['command'])
command_stores = Tree(command).stores()
matching = [(address, value) for address, value, _ in command_stores if address == source]
if matching != [(source, ('arg', 1))]:
    # HL25 Windows retains a privilege wrapper around the command executor.
    # Require the same source argument to flow into the unique direct callee.
    command_tree = Tree(command)
    cores = set()
    for call in command_tree.calls:
        target = uncast(call.x)
        if target.op != ida_hexrays.cot_obj or len(call.a) not in (2, 3):
            continue
        if [command_tree.value(arg) for arg in list(call.a)[:2]] != [('arg', 0), ('arg', 1)]:
            continue
        if len(call.a) == 3 and command_tree.value(call.a[2]) != ('num', 1):
            continue
        target = resolve_elf_plt(int(target.obj_ea))
        if any(address == source and value == ('arg', 1) for address, value, _ in Tree(target).stores()):
            cores.add(target)
    unique(cores, 'Cmd_ExecuteString source-writing core')
fragments = {3: set(), 5: set()}
for call in dl.calls:
    if len(call.a) not in fragments or dl.value(call.a[0]) != ('num', 1):
        continue
    offset = relative_to(dl.value(call.a[1]), ('global', host))
    target = uncast(call.x)
    if offset and target.op == ida_hexrays.cot_obj:
        fragments[len(call.a)].add((resolve_elf_plt(int(target.obj_ea)), offset))
normal = unique(fragments[3], 'ordinary file fragment call')
decal = unique(fragments[5], 'custom decal buffer fragment call')
if normal[0] == decal[0] or normal[1] != decal[1]:
    raise ValueError('ordinary/decal calls disagree on the client netchan')
if len({host, source, player}) != 3:
    raise ValueError('client context storage aliases')
result = {'functions': {'SV_BeginFileDownload_f': download, 'SV_DropClient': drop},
          'owners': {'host_client': download, 'cmd_source': download, 'sv_player': message},
          'globals': {'host_client': addressable(download, host),
                      'cmd_source': addressable(download, source),
                      'sv_player': addressable(message, player)},
          'registration': registration, 'message': message,
          'edict_offset': edict_offset,
          'fragments': {'file': normal[0], 'buffer': decal[0]}}
"""
)
