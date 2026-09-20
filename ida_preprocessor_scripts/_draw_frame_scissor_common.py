"""Shared Draw_Frame scissor-block detector for the engine GL draw paths.

``engine/gl_draw.c`` keeps the software-sprite clip rectangle in file-scope
statics and ``Draw_Frame`` is their only reader:

    static int scissor_x, scissor_y;
    static int scissor_width, scissor_height;
    static qboolean giScissorTest = false;

    if ( giScissorTest )
    {
        qglScissor( scissor_x, scissor_y, scissor_width, scissor_height );
        qglEnable( GL_SCISSOR_TEST );
    }

``Draw_Frame`` is therefore the only function in the engine that reads four
distinct writable dwords as the arguments of a single call and then stores
``GL_SCISSOR_TEST`` (0xC11) into that call's result/capability slot. The block is
recognised from that shape, never from a byte pattern or an address:

* four argument values, each resolving to a distinct writable global — a direct
  ``push ds:gv``/``push reg`` after ``mov reg, ds:gv`` (MSVC), or
  ``mov [esp+disp], reg`` after ``mov reg, ds:gv`` (gcc, which fills the
  pre-allocated outgoing-argument area instead of pushing),
* followed by a direct or indirect ``call`` (the ``qglScissor`` pointer on
  GoldSrc/HL25, the ``_glScissor`` import thunk on SvEngine),
* followed by a store of ``GL_SCISSOR_TEST`` for ``qglEnable``/``_glEnable``,
* guarded by the conditional branch that controls the block — a fall-through
  ``jcc`` on MSVC, a jump into an outlined cold block on gcc. The writable
  global its condition reads is ``giScissorTest``.

Argument identity follows the source's argument order, which both ABIs lay out
right-to-left, so the *reverse* instruction order is ``qglScissor(scissor_x,
scissor_y, scissor_width, scissor_height)``. Address order is deliberately not
used: gcc emits the four statics in ``EnableScissorTest``'s store order or in
reverse declaration order, neither of which matches MSVC.

Both 32-bit ABIs and both address models are covered by the injected decoder:
MSVC/GoldSrc absolute operands, gcc non-PIC absolutes, and gcc PIC
``gv@GOTOFF(%ebx)`` accesses all resolve to the same global through
``entry['targets']``.
"""

# Code injected into the owned worker. Requires the decoder from
# ``_engine_private_globals_common`` (``scan``, ``access``, ``reg4``,
# ``signed32``, ``changed_operand``, ``is_writable_data``).
DETECTOR = r"""
import ida_gdl

ARGUMENT_WINDOW = 12
GUARD_WINDOW = 12
ENABLE_WINDOW = 4
GL_SCISSOR_TEST = 0xC11
TARGET_GLOBAL_NAMES = ('giScissorTest', 'scissor_x', 'scissor_y', 'scissor_width', 'scissor_height')
ARGUMENT_GLOBAL_NAMES = ('scissor_x', 'scissor_y', 'scissor_width', 'scissor_height')
CONDITIONAL = ('ja', 'jae', 'jb', 'jbe', 'jc', 'je', 'jg', 'jge', 'jl', 'jle',
               'jna', 'jnae', 'jnb', 'jnbe', 'jnc', 'jne', 'jng', 'jnge',
               'jnl', 'jnle', 'jno', 'jnp', 'jns', 'jnz', 'jo', 'jp', 'jpe',
               'jpo', 'js', 'jz', 'jcxz', 'jecxz')
# Instructions that end the argument-setup run of a call.
BARRIER = ('call', 'jmp', 'ret', 'retn', 'pop', 'popa', 'popad', 'leave', 'enter')
CALLEE_SAVED = ('ebx', 'esi', 'edi', 'ebp')
MEMORY_OPERANDS = (int(idaapi.o_mem), int(idaapi.o_displ), int(idaapi.o_phrase))


def single_target(entry):
    targets = entry['targets']
    return next(iter(targets)) if len(targets) == 1 else None


def scissor_block(entries, owner_ea):
    '''Locate the qglScissor block of one decoded function.

    Returns ``{'call': ea, 'giScissorTest': ea, 'guard_insn': index,
    'arguments': [ea, ea, ea, ea], 'argument_insns': [index, index, index, index]}``
    with the arguments in source order (x, y, width, height) and each ``*_insn``
    naming the instruction that carries the global's four-byte displacement, or
    ``None``.
    '''
    owner = ida_funcs.get_func(int(owner_ea))
    if owner is None:
        return None
    blocks = list(ida_gdl.FlowChart(owner))

    def block_of(ea):
        return next((int(block.start_ea) for block in blocks
                     if block.start_ea <= ea < block.end_ea), None)

    def writes_memory(entry):
        for index, operand in enumerate(entry['insn'].ops):
            if int(operand.type) in MEMORY_OPERANDS and changed_operand(entry['insn'], index):
                return True
        return False

    def register_global(index, register):
        # (load index, global) for the writable global the register was last
        # loaded from in this block. The load carries the four-byte displacement
        # the runtime resolver needs; a ``push reg`` does not.
        block = block_of(entries[index]['ea'])
        if register is None or block is None:
            return None
        for previous in range(index - 1, -1, -1):
            entry = entries[previous]
            if block_of(entry['ea']) != block:
                return None
            insn = entry['insn']
            if entry['mnem'] == 'mov' and int(insn.ops[0].type) == int(idaapi.o_reg) \
                    and reg4(insn.ops[0]) == register:
                if int(insn.ops[1].type) not in MEMORY_OPERANDS:
                    return None
                address = single_target(entry)
                return None if address is None else (previous, address)
            if entry['mnem'] == 'call':
                return None
            for position, operand in enumerate(insn.ops):
                if int(operand.type) == int(idaapi.o_reg) and reg4(operand) == register \
                        and changed_operand(insn, position):
                    return None
        return None

    def push_argument(index):
        # (referencing index, global) supplied by this push.
        operand = entries[index]['insn'].ops[0]
        if int(operand.type) in MEMORY_OPERANDS:
            address = single_target(entries[index])
            return None if address is None else (index, address)
        if int(operand.type) != int(idaapi.o_reg):
            return None
        return register_global(index, reg4(operand))

    def stack_slot(index):
        # (displacement, register) when the instruction stores a register into an
        # outgoing-argument slot, else None. gcc pre-allocates that area, so it
        # writes [esp+disp] instead of pushing; a zero displacement is encoded as
        # a register-only operand.
        entry = entries[index]
        insn = entry['insn']
        if entry['mnem'] != 'mov':
            return None
        destination, source = insn.ops[0], insn.ops[1]
        kind = int(destination.type)
        if kind not in (int(idaapi.o_displ), int(idaapi.o_phrase)):
            return None
        if reg4(destination) != 'esp' or int(source.type) != int(idaapi.o_reg):
            return None
        displacement = signed32(destination.addr) if kind == int(idaapi.o_displ) else 0
        return (displacement, reg4(source))

    def zero_register(index, register):
        # True when a callee-saved register holds a proven zero at ``index``.
        if register not in CALLEE_SAVED:
            return False
        for previous in range(index - 1, -1, -1):
            entry = entries[previous]
            insn = entry['insn']
            if entry['mnem'] in ('ret', 'retn', 'jmp', 'int3'):
                return False
            if entry['mnem'] in ('xor', 'sub') and int(insn.ops[0].type) == int(idaapi.o_reg) \
                    and int(insn.ops[1].type) == int(idaapi.o_reg) \
                    and int(insn.ops[0].reg) == int(insn.ops[1].reg):
                return reg4(insn.ops[0]) == register
            for position, operand in enumerate(insn.ops):
                if int(operand.type) == int(idaapi.o_reg) and reg4(operand) == register \
                        and changed_operand(insn, position):
                    return False
        return False

    def outgoing_arguments(call_index):
        # [(referencing index, global)] in argument order; the referencing
        # instruction is the push, or the load that fed a ``push reg``/slot
        # store. Both ABIs lay arguments out right-to-left, so the reverse
        # instruction order is the argument order.
        block = block_of(entries[call_index]['ea'])
        if block is None:
            return None
        arguments = []
        kinds = set()
        displacements = []
        for position in range(call_index - 1, max(-1, call_index - 1 - ARGUMENT_WINDOW), -1):
            entry = entries[position]
            if block_of(entry['ea']) != block:
                return None
            if entry['mnem'] == 'push':
                argument = push_argument(position)
                if argument is None:
                    return None
                kinds.add('push')
                arguments.append(argument)
            else:
                slot = stack_slot(position)
                if slot is not None:
                    argument = register_global(position, slot[1])
                    if argument is None:
                        return None
                    kinds.add('slot')
                    displacements.append(slot[0])
                    arguments.append(argument)
                elif entry['mnem'] in BARRIER or writes_memory(entry):
                    return None
            if len(arguments) != 4:
                continue
            if len(kinds) != 1:
                return None
            if displacements and displacements != sorted(set(displacements)):
                return None
            return arguments
        return None

    def enables_scissor(call_index):
        for offset in range(1, ENABLE_WINDOW + 1):
            position = call_index + offset
            if position >= len(entries):
                return False
            entry = entries[position]
            operands = [operand for operand in entry['insn'].ops
                        if int(operand.type) != int(idaapi.o_void)]
            if entry['mnem'] == 'push':
                if len(operands) == 1 and int(operands[0].type) == int(idaapi.o_imm) \
                        and int(operands[0].value) == GL_SCISSOR_TEST:
                    return True
            elif entry['mnem'] == 'mov':
                if len(operands) == 2 and int(operands[1].type) == int(idaapi.o_imm) \
                        and int(operands[1].value) == GL_SCISSOR_TEST \
                        and int(operands[0].type) in MEMORY_OPERANDS \
                        and reg4(operands[0]) == 'esp':
                    return True
        return False

    def guard_global(scissor_start):
        # The conditional branch that controls the scissor block: it either falls
        # through into it (MSVC jumps over the block) or jumps straight to the
        # block start (gcc outlines the block). Its tested writable global is
        # giScissorTest; the returned index is the referencing instruction.
        candidates = []
        for index, entry in enumerate(entries):
            if entry['mnem'] not in CONDITIONAL:
                continue
            operand = entry['insn'].ops[0]
            if int(operand.type) != int(idaapi.o_near):
                continue
            target = int(operand.addr)
            if target == scissor_start or int(entry['ea']) + int(entry['len']) == scissor_start \
                    or block_of(target) == scissor_start:
                candidates.append(index)
        if len(candidates) != 1:
            return None
        index = candidates[0]
        for probe in range(index - 1, max(-1, index - 4), -1):
            entry = entries[probe]
            insn = entry['insn']
            if entry['mnem'] == 'cmp' and int(insn.ops[0].type) in MEMORY_OPERANDS:
                address = single_target(entry)
                if address is None:
                    return None
                tested = insn.ops[1]
                if int(tested.type) == int(idaapi.o_imm) and int(tested.value) == 0:
                    return (probe, address)
                if int(tested.type) == int(idaapi.o_reg) and zero_register(probe, reg4(tested)):
                    return (probe, address)
                return None
            if entry['mnem'] == 'test' and int(insn.ops[0].type) == int(idaapi.o_reg) \
                    and int(insn.ops[0].reg) == int(insn.ops[1].reg):
                register = reg4(insn.ops[0])
                load = entries[probe - 1] if probe > 0 else None
                if load is None or load['mnem'] != 'mov':
                    return None
                if int(load['insn'].ops[0].type) != int(idaapi.o_reg) \
                        or reg4(load['insn'].ops[0]) != register:
                    return None
                if int(load['insn'].ops[1].type) not in MEMORY_OPERANDS:
                    return None
                address = single_target(load)
                return None if address is None else (probe - 1, address)
        return None

    for index, entry in enumerate(entries):
        if entry['mnem'] != 'call':
            continue
        operand = entry['insn'].ops[0]
        if int(operand.type) not in (int(idaapi.o_mem), int(idaapi.o_near)):
            continue
        arguments = outgoing_arguments(index)
        if arguments is None or len({address for _, address in arguments}) != 4:
            continue
        if not enables_scissor(index):
            continue
        scissor_start = block_of(entries[arguments[3][0]]['ea'])
        if scissor_start is None:
            continue
        guard = guard_global(scissor_start)
        if guard is None or guard[1] in {address for _, address in arguments}:
            continue
        return {'call': int(entry['ea']), 'giScissorTest': guard[1], 'guard_insn': entries[guard[0]]['ea'],
                'arguments': [address for _, address in arguments],
                'argument_insns': [entries[position]['ea'] for position, _ in arguments]}
    return None


def locate_draw_frame():
    '''Every function in the image whose body carries the scissor block.

    The 0xC11 immediate of the qglEnable store is a cheap prefilter; the block
    shape decides. Returns ``[(owner_ea, evidence)]``.
    '''
    needle = b'\x11\x0C\x00\x00'
    found = []
    for start in idautils.Functions():
        owner = ida_funcs.get_func(int(start))
        if owner is None:
            continue
        body = ida_bytes.get_bytes(int(start), int(owner.end_ea) - int(start)) or b''
        if needle not in body:
            continue
        entries = scan(int(start))
        if entries is None:
            continue
        evidence = scissor_block(entries, int(start))
        if evidence is not None:
            found.append((int(start), evidence))
    return found


def scissor_globals(owner_ea):
    '''{name: operand record} for the five scissor globals of one Draw_Frame.'''
    entries = scan(int(owner_ea))
    if entries is None:
        return {'error': 'owner is not a function start'}
    evidence = scissor_block(entries, int(owner_ea))
    if evidence is None:
        return {'error': 'no qglScissor block in the owner'}
    by_ea = {int(entry['ea']): entry for entry in entries}
    located = {}
    for position, name in enumerate(ARGUMENT_GLOBAL_NAMES):
        located[name] = access(by_ea[evidence['argument_insns'][position]], evidence['arguments'][position])
    located['giScissorTest'] = access(by_ea[evidence['guard_insn']], evidence['giScissorTest'])
    for name in TARGET_GLOBAL_NAMES:
        if located[name]['insn_disp'] == '0x0':
            return {'error': '%s has no addressable reference' % name}
    located['pointer_size'] = 4
    located['owner'] = int(owner_ea)
    located['call'] = evidence['call']
    return located
"""

# Python-side decoder inputs for the walks above.
ARGUMENT_WINDOW = 12
GUARD_WINDOW = 12
ENABLE_WINDOW = 4
GL_SCISSOR_TEST = 0xC11

# Entry points for ``run_walk``: one locates Draw_Frame across the image, the
# other extracts the five globals of a known Draw_Frame.
LOCATE_WALK = (
    DETECTOR
    + r"""
result = {'frames': [
    {'ea': hex(ea), 'call': hex(evidence['call']),
     'giScissorTest': hex(evidence['giScissorTest']),
     'arguments': [hex(address) for address in evidence['arguments']]}
    for ea, evidence in locate_draw_frame()
]}
"""
)

GLOBALS_WALK = (
    DETECTOR
    + r"""
result = scissor_globals(int(values['owner'], 0))
"""
)


def walk_values(owner_ea=None):
    """Decoder inputs shared by the consuming finders and the probe."""
    values = {}
    if owner_ea is not None:
        values["owner"] = hex(int(owner_ea))
    return values
