"""Validate SingleClip ABI and recover a retained trace-returning wrapper.

HL25 ELF calls a compiler-created .part.0 body with eax/edx/ecx arguments.
That body is not the public six-stack-argument entry fallguys can call. Recover
the unique six-argument cdecl guard that forwards every argument unchanged.
Wrapper discovery then includes callers of that implementation as well as the
public entry, because GCC can bypass the public null guards.
"""

from ida_analyze_util import _load_yaml_mapping, _output_for_symbol, write_func_yaml
from ida_preprocessor_scripts._engine_private_globals_common import inspect_func, run_walk

CLIPPING_DECODER = r"""
import ida_hexrays, ida_typeinf


def uncast(expr):
    while expr.op == ida_hexrays.cot_cast:
        expr = expr.x
    return expr


class CallsAndReturns(ida_hexrays.ctree_visitor_t):
    def __init__(self):
        super().__init__(ida_hexrays.CV_FAST)
        self.calls = []
        self.returns = []

    def visit_expr(self, expr):
        if expr.op == ida_hexrays.cot_call and expr.x.op == ida_hexrays.cot_obj:
            self.calls.append((resolve_elf_plt(int(expr.x.obj_ea)), expr))
        return 0

    def visit_insn(self, insn):
        if insn.op == ida_hexrays.cit_return:
            self.returns.append(insn.creturn.expr)
        return 0


def function_info(start):
    function = ida_hexrays.decompile(int(start))
    details = ida_typeinf.func_type_data_t()
    if function is None or not function.type.get_func_details(details):
        raise RuntimeError('cannot establish clipping function ABI')
    visitor = CallsAndReturns()
    visitor.apply_to(function.body, None)
    return function, details, visitor


def argument_indexes(function):
    return [int(index) for index in function.argidx]


def forwards(expr, indexes):
    if expr.a.size() != len(indexes):
        return False
    return all(uncast(expr.a[index]).op == ida_hexrays.cot_var
               and int(uncast(expr.a[index]).v.idx) == value
               for index, value in enumerate(indexes))


def conventional(details):
    return int(details.get_cc()) & int(ida_typeinf.CM_CC_MASK) == int(ida_typeinf.CM_CC_CDECL)


def forwards_tail(expr, index):
    expr = uncast(expr)
    return expr.op == ida_hexrays.cot_var and int(expr.v.idx) == index


def single_entry(selected, argc):
    function, details, visitor = function_info(selected)
    if details.size() != argc:
        raise RuntimeError('SingleClip argument count disagrees with selected ABI')
    if conventional(function.type):
        return selected
    # Only accept the compiler split after proving its public forwarding guard.
    candidates = []
    for caller, site in callers(selected):
        parent, parent_details, parent_visitor = function_info(caller)
        indexes = argument_indexes(parent)
        if not conventional(parent.type) or parent_details.size() != argc or not parent_details.rettype.is_void():
            continue
        if len(parent_visitor.calls) != 1:
            continue
        target, expr = parent_visitor.calls[0]
        if target == selected and forwards(expr, indexes):
            candidates.append(caller)
    candidates = sorted(set(candidates))
    if len(candidates) != 1:
        raise RuntimeError('compiler clipping body has no unique public cdecl forwarding entry')
    return candidates[0]


def implementation_targets(entry):
    function, details, visitor = function_info(entry)
    indexes = argument_indexes(function)
    targets = {entry}
    if len(visitor.calls) == 1:
        target, expr = visitor.calls[0]
        if forwards(expr, indexes):
            targets.add(target)
    return targets


def retained_wrapper(entry):
    targets = implementation_targets(entry)
    found = []
    for target in sorted(targets):
        for caller, site in callers(target):
            if caller in targets:
                continue
            function, details, visitor = function_info(caller)
            indexes = argument_indexes(function)
            # Hidden output pointer, five source args, and optional passedict.
            if len(indexes) not in (6, 7):
                continue
            relevant = [(callee, expr) for callee, expr in visitor.calls if callee in targets]
            if len(relevant) != 1:
                continue
            callee, expr = relevant[0]
            if expr.a.size() != len(indexes):
                continue
            forwarding = True
            for index in range(5):
                argument = uncast(expr.a[index])
                if argument.op != ida_hexrays.cot_var or int(argument.v.idx) != indexes[index + 1]:
                    forwarding = False
            if expr.a.size() == 7 and not forwards_tail(expr.a[6], indexes[6]):
                forwarding = False
            returned = any(uncast(expr).op == ida_hexrays.cot_var and int(uncast(expr).v.idx) == indexes[0]
                           for expr in visitor.returns)
            # Independently require the trace copy width, rather than a size cap.
            trace_argument = uncast(expr.a[5])
            trace_copy = (trace_argument.op == ida_hexrays.cot_var
                          and int(trace_argument.v.idx) == indexes[0])
            for ea in idautils.FuncItems(caller):
                insn = idautils.DecodeInstruction(ea)
                if insn is None:
                    continue
                for op in insn.ops:
                    if int(op.type) == int(idaapi.o_imm) and int(op.value) == 56:
                        trace_copy = True
            if forwarding and returned and trace_copy:
                found.append(caller)
    found = sorted(set(found))
    if len(found) != 1:
        raise RuntimeError('retained trace-returning wrapper missing or ambiguous: ' + repr(found))
    return found[0]
"""


async def normalize_singleclip(session, expected_outputs, image_base, name, argc, debug=False):
    output = _output_for_symbol(expected_outputs, name)
    payload = _load_yaml_mapping(output)
    if not payload:
        return False
    selected = int(payload["func_va"], 0)
    located = await run_walk(
        session,
        CLIPPING_DECODER + "\nresult = {'entry': hex(single_entry(int(values['selected'], 0), values['argc']))}",
        {"selected": hex(selected), "argc": argc},
    )
    if debug:
        print(f"{name}: ABI/entry validation: {located}")
    if located.get("error"):
        return False
    entry = int(located["entry"], 0)
    function = await inspect_func(session, entry, image_base, "SV_SingleClipMoveToEntity")
    if function is None:
        return False
    write_func_yaml(output, function)
    return True
