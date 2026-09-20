"""Shared ``cl_enginefuncs.pTriAPI`` anchor for the engine fog symbols.

``engine/r_triangle.c`` publishes a global ``triangleapi_t tri`` through the
engine function table the client receives:

    triangleapi_t tri = { TRI_API_VERSION, ..., R_RenderFog, ..., R_FogParams };

``common/triangleapi.h`` fixes that field order, so ``tri`` slot 13 is
``R_RenderFog`` (``Fog``) and slot 19 is ``R_FogParams`` (``FogParams``). The
table itself is reached from ``cl_enginefunc_t cl_enginefuncs``
(``engine/cdll_int.c``), whose ``pTriAPI`` field is the 83rd initializer entry,
i.e. byte offset ``0x148``; ``pEfxAPI``/``pEventAPI`` follow at ``0x14C`` and
``0x150``. ``tri`` is located from that pointer and the table shape, never from
a byte signature or an address.

Each of the six fog globals is then identified by the source's own
argument-to-global assignment, not by address order or a layout guess:

* ``R_RenderFog(float *flFogColor, float flStart, float flEnd, BOOL bOn)``
  writes ``flFogColor[0..2]/255.0`` into ``flFinalFogColor`` (reached through
  the first argument pointer), ``flStart``/``flEnd`` into ``flFogStart``/
  ``flFogEnd`` (arguments 1 and 2), and ``bOn`` into ``g_bUserFogOn`` (a 0/1
  constant, or a stack temporary, never an argument slot);
* ``R_FogParams(float flDensity, int iFogSkybox)`` writes its arguments into
  ``flFogDensity`` and ``g_bFogSkybox``.

Argument identity comes from the caller frame: cdecl lays arguments out from
``[entry_esp+4]`` upwards, so a ``[esp/ebp+disp]`` load resolves to argument
``(disp - frame_delta - 4) / 4`` once the function's own stack movement is
tracked. MSVC absolute, gcc non-PIC absolute and gcc PIC ``gv@GOTOFF(%ebx)``
global accesses are all decoded through ``scan``/``operand_globals``.

SvEngine stores thin adapters (``tri_R_RenderFog_I``/``tri_R_FogParams_I``)
that only normalise the ``BOOL`` argument and tail into the real
implementations, so a slot whose body owns no global write is followed to the
single callee that does.
"""

# Code injected into the owned worker. Requires the decoder from
# ``_engine_private_globals_common`` (``scan``, ``access``, ``reg4``,
# ``signed32``, ``changed_operand``, ``is_writable_data``, ``is_code_address``,
# ``direct_calls``).
DETECTOR = r"""
PTRIAPI_OFFSET = 0x148
TRI_API_VERSION = 1
TRI_SLOTS = 19
FOG_SLOT = 13
FOG_PARAMS_SLOT = 19
COLOUR_COMPONENTS = 4

COLOUR_GLOBAL = 'flFinalFogColor'
FOG_START_GLOBAL = 'flFogStart'
FOG_END_GLOBAL = 'flFogEnd'
FOG_DENSITY_GLOBAL = 'flFogDensity'
FOG_SKYBOX_GLOBAL = 'g_bFogSkybox'
USER_FOG_GLOBAL = 'g_bUserFogOn'

# x87 instructions that leave a value in st(0); the rest of the opcode space
# (fcomp/fucomi/fnstsw/fxch) only consumes or rearranges it.
X87_VALUES = ('fld', 'fld1', 'fldz', 'fild', 'fdiv', 'fdivr', 'fmul', 'fadd',
              'fsub', 'fsubr', 'fabs', 'fchs', 'fsqrt')
X87_STORES = ('fst', 'fstp')
STACK_PUSH = 4


def function_start(ea):
    function = ida_funcs.get_func(int(ea))
    if function is None or int(function.start_ea) != int(ea):
        return None
    return int(ea)


def tri_table(enginefuncs):
    '''(tri address, [slot 1 .. slot 19]) when pTriAPI points at triangleapi_t.'''
    tri = ida_bytes.get_dword(int(enginefuncs) + PTRIAPI_OFFSET)
    if not is_writable_data(tri) or ida_bytes.get_dword(tri) != TRI_API_VERSION:
        return None
    pointers = []
    for index in range(TRI_SLOTS):
        pointer = ida_bytes.get_dword(tri + 4 * (index + 1))
        if function_start(pointer) is None:
            return None
        pointers.append(int(pointer))
    return (int(tri), pointers)


def writes_globals(entries):
    return any(entry['written'] for entry in entries)


def implementation(slot_ea):
    '''The function that actually owns a triangleapi slot's global writes.

    SvEngine publishes adapters that only convert the BOOL argument, so a slot
    with no global write is followed to the unique callee that has one. The PIC
    ``__x86_get_pc_thunk_*`` helper is rejected by that same test.
    '''
    entries = scan(int(slot_ea))
    if entries is None:
        return None
    if writes_globals(entries):
        return int(slot_ea)
    candidates = []
    for callee in direct_calls(int(slot_ea)):
        body = scan(int(callee))
        if body is not None and writes_globals(body):
            candidates.append(int(callee))
    return candidates[0] if len(candidates) == 1 else None


def frame_states(entries):
    '''[(esp_delta, ebp_delta)] per instruction, both in bytes below entry esp.'''
    esp_delta = 0
    ebp_delta = None
    states = []
    for entry in entries:
        states.append((esp_delta, ebp_delta))
        mnemonic = entry['mnem']
        insn = entry['insn']
        if mnemonic == 'push':
            esp_delta += STACK_PUSH
        elif mnemonic == 'pop':
            esp_delta -= STACK_PUSH
        elif mnemonic in ('sub', 'add') and reg4(insn.ops[0]) == 'esp' \
                and int(insn.ops[1].type) == int(idaapi.o_imm):
            amount = int(insn.ops[1].value) & 0xFFFFFFFF
            esp_delta += amount if mnemonic == 'sub' else -amount
        elif mnemonic == 'mov' and reg4(insn.ops[0]) == 'ebp' and reg4(insn.ops[1]) == 'esp':
            ebp_delta = esp_delta
    return states


def writes_register(entry, register):
    if register is None:
        return False
    for position, operand in enumerate(entry['insn'].ops):
        if int(operand.type) == int(idaapi.o_void):
            break
        if int(operand.type) == int(idaapi.o_reg) and reg4(operand) == register \
                and changed_operand(entry['insn'], position):
            return True
    return False


def frame_slot(states, index, operand):
    '''('arg', n) or ('local', offset) for a frame-relative operand.'''
    base = reg4(operand)
    if base not in ('esp', 'ebp'):
        return None
    esp_delta, ebp_delta = states[index]
    if base == 'esp':
        offset = signed32(operand.addr) - esp_delta
    else:
        if ebp_delta is None:
            return None
        offset = signed32(operand.addr) - ebp_delta
    if offset >= 4 and (offset - 4) % 4 == 0:
        return ('arg', (offset - 4) // 4)
    return ('local', offset)


def operand_provenance(entries, states, index, operand, depth=0):
    '''Where one operand's value comes from: argument, dereferenced pointer
    argument, constant, or local frame slot.'''
    kind = int(operand.type)
    if kind == int(idaapi.o_imm):
        return ('constant', int(operand.value) & 0xFFFFFFFF)
    if kind == int(idaapi.o_reg):
        return register_provenance(entries, states, index, reg4(operand), depth + 1)
    if kind not in (int(idaapi.o_mem), int(idaapi.o_displ), int(idaapi.o_phrase)):
        return None
    slot = frame_slot(states, index, operand)
    if slot is not None:
        return slot
    if kind == int(idaapi.o_mem):
        return None
    base = register_provenance(entries, states, index, reg4(operand), depth + 1)
    if base is not None and base[0] == 'arg':
        return ('element', base[1], signed32(operand.addr))
    return None


def register_provenance(entries, states, index, register, depth=0):
    if register is None or depth > 4:
        return None
    for previous in range(index - 1, -1, -1):
        entry = entries[previous]
        if entry['mnem'] == 'call':
            return None
        if not writes_register(entry, register):
            continue
        insn = entry['insn']
        if entry['mnem'] in ('xor', 'sub') and reg4(insn.ops[0]) == register \
                and int(insn.ops[1].type) == int(idaapi.o_reg) \
                and reg4(insn.ops[1]) == register:
            return ('constant', 0)
        source = insn.ops[1] if len(insn.ops) > 1 else None
        if source is None or int(source.type) == int(idaapi.o_void):
            return None
        return operand_provenance(entries, states, previous, source, depth)
    return None


def x87_provenance(entries, states, index):
    for previous in range(index - 1, -1, -1):
        entry = entries[previous]
        mnemonic = entry['mnem']
        if mnemonic in ('call', 'ret', 'retn'):
            return None
        if mnemonic == 'fld1':
            return ('constant', 0x3F800000)
        if mnemonic == 'fldz':
            return ('constant', 0)
        if mnemonic not in X87_VALUES:
            continue
        for operand in entry['insn'].ops:
            if int(operand.type) == int(idaapi.o_void):
                break
            if int(operand.type) in (int(idaapi.o_mem), int(idaapi.o_displ), int(idaapi.o_phrase)):
                return operand_provenance(entries, states, previous, operand)
        if mnemonic in ('fdiv', 'fdivr', 'fmul', 'fadd', 'fsub', 'fsubr'):
            continue
        return None
    return None


def store_provenance(entries, states, index):
    '''Where the value one global-writing instruction stores comes from.'''
    entry = entries[index]
    if entry['mnem'] in X87_STORES:
        return x87_provenance(entries, states, index)
    source = entry['insn'].ops[1] if len(entry['insn'].ops) > 1 else None
    if source is None or int(source.type) == int(idaapi.o_void):
        return None
    return operand_provenance(entries, states, index, source)


def write_provenances(entries):
    '''{global address: [(instruction index, provenance)]}.'''
    states = frame_states(entries)
    found = {}
    for index, entry in enumerate(entries):
        for address in entry['written']:
            found.setdefault(int(address), []).append((index, store_provenance(entries, states, index)))
    return found


def render_fog_layout(entries):
    '''{name: (instruction index, global address)} for R_RenderFog's globals.

    ``flFinalFogColor`` is the four-element colour run whose last element is the
    alpha literal ``1`` (``flFinalFogColor[3] = 1``), so its base is that
    write's address minus three components. The remaining three globals are
    ``flStart``/``flEnd`` (arguments 1 and 2) and the boolean flag, which is a
    0/1 constant or a stack temporary and never an argument slot.
    '''
    provenances = write_provenances(entries)
    ones = sorted(address for address, items in provenances.items()
                  if any(provenance == ('constant', 0x3F800000) for _, provenance in items))
    if len(ones) != 1:
        return {'error': 'flFinalFogColor alpha write is not unique'}
    base = ones[0] - 4 * (COLOUR_COMPONENTS - 1)
    members = {base + 4 * component for component in range(COLOUR_COMPONENTS)}
    if not members <= set(provenances):
        return {'error': 'flFinalFogColor is not a written four-element run'}
    named = {COLOUR_GLOBAL: (provenances[base][0][0], base)}
    other = {address: items for address, items in provenances.items() if address not in members}
    if len(other) != 3:
        return {'error': 'R_RenderFog writes %d non-colour globals' % len(other)}
    for address, items in other.items():
        kinds = {provenance for _, provenance in items}
        index = min(position for position, _ in items)
        if kinds == {('arg', 1)}:
            named[FOG_START_GLOBAL] = (index, address)
        elif kinds == {('arg', 2)}:
            named[FOG_END_GLOBAL] = (index, address)
        elif all(kind and kind[0] in ('constant', 'local') for kind in kinds):
            named[USER_FOG_GLOBAL] = (index, address)
        else:
            return {'error': 'unexpected R_RenderFog write provenance %s' % sorted(map(str, kinds))}
    if set(named) != {COLOUR_GLOBAL, FOG_START_GLOBAL, FOG_END_GLOBAL, USER_FOG_GLOBAL}:
        return {'error': 'R_RenderFog globals are not identifiable'}
    return named


def fog_params_layout(entries):
    '''{name: (instruction index, global address)} for R_FogParams' globals.'''
    provenances = write_provenances(entries)
    if len(provenances) != 2:
        return {'error': 'R_FogParams writes %d globals' % len(provenances)}
    named = {}
    for address, items in provenances.items():
        kinds = {provenance for _, provenance in items}
        index = min(position for position, _ in items)
        if kinds == {('arg', 0)}:
            named[FOG_DENSITY_GLOBAL] = (index, address)
        elif kinds == {('arg', 1)}:
            named[FOG_SKYBOX_GLOBAL] = (index, address)
        else:
            return {'error': 'unexpected R_FogParams write provenance %s' % sorted(map(str, kinds))}
    if set(named) != {FOG_DENSITY_GLOBAL, FOG_SKYBOX_GLOBAL}:
        return {'error': 'R_FogParams globals are not identifiable'}
    return named


def locate_fog(enginefuncs):
    '''{func name: address} for the two fog implementations behind pTriAPI.'''
    table = tri_table(enginefuncs)
    if table is None:
        return {'error': 'pTriAPI does not point at a triangleapi_t table'}
    tri_ea, pointers = table
    fog = implementation(pointers[FOG_SLOT - 1])
    fog_params = implementation(pointers[FOG_PARAMS_SLOT - 1])
    if fog is None or fog_params is None:
        return {'error': 'a fog slot has no single implementation'}
    return {'tri': tri_ea, 'R_RenderFog': fog, 'R_FogParams': fog_params}


def located_globals(render_fog_ea, fog_params_ea):
    '''{owner name: {global name: access record}} for both fog implementations.'''
    result = {}
    for name, owner_ea, layout in (
            ('R_RenderFog', int(render_fog_ea), render_fog_layout),
            ('R_FogParams', int(fog_params_ea), fog_params_layout)):
        entries = scan(owner_ea)
        if entries is None:
            return {'error': '%s is not a function start' % name}
        found = layout(entries)
        if 'error' in found:
            return {'error': '%s: %s' % (name, found['error'])}
        result[name] = {
            global_name: access(entries[index], address)
            for global_name, (index, address) in found.items()
        }
        for global_name, record in result[name].items():
            if record['insn_disp'] == '0x0':
                return {'error': '%s.%s has no addressable reference' % (name, global_name)}
    return result
"""

# Python-side decoder inputs for the walks above.
PTRIAPI_OFFSET = 0x148

# ``values`` keys consumed by each walk.
ENGINE_FUNCS_GLOBAL = "cl_enginefuncs"
RENDER_FOG_FUNC = "R_RenderFog"
FOG_PARAMS_FUNC = "R_FogParams"
RENDER_FOG_GLOBALS = ("flFinalFogColor", "flFogStart", "flFogEnd", "g_bUserFogOn")
FOG_PARAMS_GLOBALS = ("flFogDensity", "g_bFogSkybox")
TARGET_GLOBAL_NAMES = RENDER_FOG_GLOBALS + FOG_PARAMS_GLOBALS

# Entry points for ``run_walk``: one locates both implementations across the
# image, the other extracts their globals.
LOCATE_WALK = (
    DETECTOR
    + r"""
result = locate_fog(int(values['enginefuncs'], 0))
"""
)

GLOBALS_WALK = (
    DETECTOR
    + r"""
result = located_globals(int(values['render_fog'], 0), int(values['fog_params'], 0))
"""
)


def walk_values(enginefuncs=None, render_fog=None, fog_params=None):
    """Decoder inputs shared by the consuming finders and the probe."""
    values = {}
    if enginefuncs is not None:
        values["enginefuncs"] = hex(int(enginefuncs))
    if render_fog is not None:
        values["render_fog"] = hex(int(render_fog))
    if fog_params is not None:
        values["fog_params"] = hex(int(fog_params))
    return values
