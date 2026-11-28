#!/usr/bin/env python3
"""Recover Sven server entity dispatch slots from native AngelScript bindings.

RegisterSCScriptBaseEntity<CBaseEntity> binds the six member pointers. MSVC
materializes dispatch thunks, while GCC stores an Itanium member pointer
with ptr = byte offset + 1 and zero this adjustment. TraceAttack is instead
bound through Entity_TraceAttack, which forwards the vector by value and
dispatches on its last argument. Only the resulting slots are published.
"""

from ida_analyze_util import _output_for_symbol, preprocess_vtable_via_mcp, write_func_yaml
from ida_preprocessor_scripts._vgui_paint_common import walk

CLASS = "CBaseEntity"
SLOT_WIDTH = 4
DECLARATIONS = {
    "Precache": "void Precache()",
    "TakeDamage": "int TakeDamage(entvars_t@ pevInflictor, entvars_t@ pevAttacker, float flDamage, int bitsDamageType)",
    "TakeHealth": "bool TakeHealth(float flHealth, int bitsDamageType, int health_cap = 0)",
    "TakeArmor": "bool TakeArmor(float flArmor, int bitsDamageType, int armor_cap = 0)",
    "IsPlayer": "bool IsPlayer()",
    "BeginRevive": "void BeginRevive(float flTimeUntilRevive)",
    "TraceAttack": "void TraceAttack(entvars_t@ pevAttacker, float flDamage, const Vector& in vecDir, "
    "TraceResult& in traceResult, int bitsDamageType)",
}

LOCATE = r"""
import ida_hexrays as hx, ida_name

AS_CALL_THISCALL = 3
AS_CALL_CDECL_OBJLAST = 4
AS_MEMBER_POINTER = 3
AS_GLOBAL_POINTER = 2
# The ELF i386 asSFuncPtr union rounds the 25-byte storage up to 28 bytes.
ELF_AS_POINTER_TAG_OFFSET = 28
POINTER_WIDTH = 4
DECLS = values['declarations']
PLATFORM = values['platform']


def unique(candidates, role):
    if len(candidates) != 1:
        raise ValueError('%s: expected one match, found %d' % (role, len(candidates)))
    return next(iter(candidates))


def owners(addresses):
    result = set()
    for address in addresses:
        for ref in idautils.XrefsTo(address):
            function = ida_funcs.get_func(ref.frm)
            if function:
                result.add(int(function.start_ea))
    return result


def called_with_base_name(entry):
    # The common template is instantiated for many entities. Its base
    # registration caller passes the literal CBaseEntity as the script type.
    for ref in idautils.XrefsTo(entry):
        if not ref.iscode or idc.print_insn_mnem(ref.frm) != 'call':
            continue
        function = ida_funcs.get_func(ref.frm)
        if not function:
            continue
        cursor = ref.frm
        for _ in range(7):
            cursor = idc.prev_head(cursor, function.start_ea)
            if cursor == idaapi.BADADDR or idc.print_insn_mnem(cursor) == 'call':
                break
            if any(idc.get_strlit_contents(ea) == b'CBaseEntity' for ea in idautils.DataRefsFrom(cursor)):
                return True
    return False


def unwrap(expr):
    while expr.op in (hx.cot_cast, hx.cot_ref):
        expr = expr.x
    return expr


def value(expr, op):
    expr = unwrap(expr)
    if expr.op != op:
        return None
    if op == hx.cot_obj:
        return int(expr.obj_ea)
    if op == hx.cot_var:
        return int(expr.v.idx)
    return int(expr.numval())


class Expressions(hx.ctree_visitor_t):
    def __init__(self):
        super().__init__(hx.CV_FAST)
        self.events = []

    def visit_expr(self, expr):
        if expr.op in (hx.cot_asg, hx.cot_call):
            self.events.append(expr)
        return 0


def binding(cfunc, events, index, method):
    call = events[index]
    args = list(call.a)
    is_trace = method == 'TraceAttack'
    convention = AS_CALL_CDECL_OBJLAST if is_trace else AS_CALL_THISCALL
    descriptor = value(args[-2], hx.cot_var)
    if descriptor is None or value(args[-1], hx.cot_num) != convention:
        raise ValueError('unsupported registration ABI: ' + method)

    # The descriptor is initialized in the same registration statement group.
    # Stop at the preceding call to the same registration method.
    register_method = value(call.x, hx.cot_obj)
    assignments = []
    for expr in reversed(events[:index]):
        if expr.op == hx.cot_call and value(expr.x, hx.cot_obj) == register_method:
            break
        if expr.op == hx.cot_asg and value(expr.x, hx.cot_var) is not None:
            assignments.append(expr)
    initializer = next((expr.y for expr in assignments if value(expr.x, hx.cot_var) == descriptor), None)
    if initializer is None:
        raise ValueError('missing descriptor initializer: ' + method)

    if PLATFORM == 'windows':
        conversion = unwrap(initializer)
        if conversion.op != hx.cot_call or len(conversion.a) != 2:
            raise ValueError('missing asSFuncPtr conversion: ' + method)
        return register_method, value(conversion.a[1], hx.cot_obj)

    locals_ = cfunc.get_lvars()
    descriptor_stack = locals_[descriptor].get_stkoff()
    fields = {}
    for expr in assignments:
        local = locals_[value(expr.x, hx.cot_var)]
        if local.is_stk_var():
            fields.setdefault(local.get_stkoff() - descriptor_stack, value(expr.y, hx.cot_num))
    expected_tag = AS_GLOBAL_POINTER if is_trace else AS_MEMBER_POINTER
    if fields.get(ELF_AS_POINTER_TAG_OFFSET) != expected_tag:
        raise ValueError('unexpected asSFuncPtr tag: %s (%r)' % (method, fields))
    if is_trace:
        return register_method, value(initializer, hx.cot_obj)
    encoded = value(initializer, hx.cot_num)
    if fields.get(POINTER_WIDTH) != 0 or encoded is None or encoded % POINTER_WIDTH != 1:
        raise ValueError('invalid Itanium member pointer: ' + method)
    return register_method, encoded - 1


def bindings(entry, addresses):
    cfunc = hx.decompile(entry)
    visitor = Expressions()
    visitor.apply_to(cfunc.body, None)
    result = {method: [] for method in addresses.values()}
    for index, expr in enumerate(visitor.events):
        if expr.op != hx.cot_call or len(expr.a) < 5:
            continue
        method = addresses.get(value(expr.a[len(expr.a) - 3], hx.cot_obj))
        if method:
            result[method].append(binding(cfunc, visitor.events, index, method))
    return {method: unique(entries, method + ' binding') for method, entries in result.items()}


def dispatch_offset(entry, receiver, tail):
    calls = flow_at(entry, PLATFORM)['calls']
    targets = [
        offset for call in calls if call['tail'] == tail
        for obj, offset in virtual_targets(call['target']) if obj == ('arg', receiver)
    ]
    return unique(targets, 'dispatch to receiver at %#x' % entry)


def locate():
    strings = {method: set() for method in DECLS}
    methods = {decl: method for method, decl in DECLS.items()}
    for item in idautils.Strings():
        method = methods.get(str(item))
        if method:
            strings[method].add(int(item.ea))

    trace = 'TraceAttack'
    trace_entry = unique(owners(strings[trace]), 'TraceAttack registration owner')
    member_addresses = {
        addr: method for method, addresses in strings.items() if method != trace for addr in addresses
    }
    candidates = set.intersection(*(owners(addresses) for method, addresses in strings.items() if method != trace))
    retained_name = '_Z26RegisterSCScriptBaseEntityI11CBaseEntityEvP16CASDocumentationPKcb'
    base_candidates = {entry for entry in candidates if called_with_base_name(entry)}
    named = ida_name.get_name_ea(idaapi.BADADDR, retained_name)
    if named in candidates:
        base_candidates.add(named)
    base_entry = unique(base_candidates, 'CBaseEntity registration owner')

    registered = bindings(base_entry, member_addresses)
    registered.update(bindings(trace_entry, {addr: trace for addr in strings[trace]}))
    unique({register for register, _ in registered.values()}, 'RegisterObjectMethod callee')

    result = {}
    for method, (_, target) in registered.items():
        if target is None:
            raise ValueError('missing native binding: ' + method)
        if method == trace:
            # Entity_TraceAttack is cdecl object-last. The flow model gives
            # Windows stack arguments numbers starting at 1 (ECX is argument 0).
            result[method] = dispatch_offset(target, 6 if PLATFORM == 'windows' else 5, False)
        elif PLATFORM == 'windows':
            result[method] = dispatch_offset(target, 0, True)
        else:
            result[method] = target
    return result


result = {'slots': locate()}
"""


async def preprocess_skill(
    session, skill_name, expected_outputs, old_yaml_map, new_binary_dir, platform, image_base, debug=False
):
    _ = old_yaml_map, new_binary_dir
    outputs = {method: _output_for_symbol(expected_outputs, f"{CLASS}_{method}") for method in DECLARATIONS}
    if platform not in {"windows", "linux"} or not all(outputs.values()):
        return False

    evidence = await walk(session, LOCATE, {"platform": platform, "declarations": DECLARATIONS})
    slots = evidence.get("slots", {})
    table = await preprocess_vtable_via_mcp(session, CLASS, image_base, platform) if slots else None
    entries = {int(index) for index in table["vtable_entries"]} if table else set()
    if (
        slots.keys() != DECLARATIONS.keys()
        or len(set(slots.values())) != len(DECLARATIONS)
        or any(offset < 0 or offset % SLOT_WIDTH or offset // SLOT_WIDTH not in entries for offset in slots.values())
    ):
        if debug:
            print(f"{skill_name}: invalid or ambiguous slots: {evidence}")
        return False

    for method, offset in slots.items():
        write_func_yaml(
            outputs[method],
            {
                "func_name": f"{CLASS}_{method}",
                "vtable_name": CLASS,
                "vfunc_offset": hex(offset),
                "vfunc_index": offset // SLOT_WIDTH,
            },
        )
    if debug:
        print(f"{skill_name}: {slots}")
    return True
