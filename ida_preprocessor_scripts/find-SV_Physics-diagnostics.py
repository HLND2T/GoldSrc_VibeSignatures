#!/usr/bin/env python3
"""Locate SV_PushRotate and SV_ClipToLinks by their own fatal diagnostics.

Direct string xrefs are preferred. SvEngine's PIC register copies can hide IDA
data xrefs: a current-function thunk/add base plus a literal displacement only
narrows candidates. Hex-Rays must independently fold the first argument of the
verified Sys_Error call to the exact string address. A displacement match alone
never establishes ownership. The current binary supplies every PIC base.
"""

from pathlib import Path

from ida_analyze_util import _load_yaml_mapping, _output_for_symbol, write_func_yaml
from ida_preprocessor_scripts._engine_private_globals_common import inspect_func, run_walk

DIAGNOSTICS = {
    "SV_PushRotate": "Out of edicts in simulator!\n",
    "SV_ClipToLinks": "Trigger in clipping list",
}

WALK = r"""
import ida_hexrays


def constant(expr):
    op = expr.op
    if op == ida_hexrays.cot_num:
        return int(expr.numval()) & 0xFFFFFFFF
    if op == ida_hexrays.cot_obj:
        return int(expr.obj_ea)
    if op == ida_hexrays.cot_ref and expr.x.op == ida_hexrays.cot_obj:
        return int(expr.x.obj_ea)
    if op == ida_hexrays.cot_cast:
        return constant(expr.x)
    if op in (ida_hexrays.cot_add, ida_hexrays.cot_sub):
        left, right = constant(expr.x), constant(expr.y)
        if left is None or right is None:
            return None
        scale = int(expr.x.type.get_ptrarr_objsize()) if expr.x.type.is_ptr() else 1
        if scale <= 0:
            return None
        return (left + right * scale if op == ida_hexrays.cot_add else left - right * scale) & 0xFFFFFFFF
    return None


class DiagnosticCalls(ida_hexrays.ctree_visitor_t):
    def __init__(self, target, sys_error):
        super().__init__(ida_hexrays.CV_FAST)
        self.target = target
        self.sys_error = sys_error
        self.sites = []

    def visit_expr(self, expr):
        if (expr.op == ida_hexrays.cot_call and expr.x.op == ida_hexrays.cot_obj
                and resolve_elf_plt(int(expr.x.obj_ea)) == self.sys_error
                and expr.a.size() and constant(expr.a[0]) == self.target):
            site = int(expr.ea)
            insn = idautils.DecodeInstruction(site)
            if (insn is not None and idc.print_insn_mnem(site) == 'call'
                    and local_call_target(site) == self.sys_error):
                self.sites.append(site)
        return 0


def candidates(target):
    owners = set()
    for ref in idautils.DataRefsTo(target):
        owner = ida_funcs.get_func(ref)
        if owner is not None:
            owners.add(int(owner.start_ea))
    if owners:
        return owners
    # Only a hint. PIC registers may have been copied (eax -> ecx -> ebx).
    for start in idautils.Functions():
        base, register = got_anchor(start)
        if base is None:
            continue
        for ea in idautils.FuncItems(start):
            if idc.print_insn_mnem(ea) != 'lea':
                continue
            insn = idautils.DecodeInstruction(ea)
            if insn is not None and int(insn.ops[1].type) == int(idaapi.o_displ):
                if (base + signed32(insn.ops[1].addr)) & 0xFFFFFFFF == target:
                    owners.add(int(start))
    return owners


located = {}
evidence = {}
for name, literal in values['diagnostics'].items():
    matches = [int(item.ea) for item in idautils.Strings() if str(item) == literal]
    if len(matches) != 1:
        raise RuntimeError(name + ': expected one exact diagnostic string')
    target = matches[0]
    validated = {}
    direct = set()
    for ref in idautils.DataRefsTo(target):
        function = ida_funcs.get_func(ref)
        if function is not None:
            direct.add(int(function.start_ea))
    # A target-owned direct string xref is already the strongest locator. Do
    # not require Hex-Rays to inline a compiler's temporary format-pointer local.
    if direct:
        for start in direct:
            sites = direct_calls(start).get(int(values['sys_error'], 0), [])
            if sites:
                validated[start] = sites
    for start in sorted(candidates(target)):
        if direct:
            continue
        function = ida_hexrays.decompile(start)
        if function is None:
            raise RuntimeError(name + ': candidate could not be decompiled')
        visitor = DiagnosticCalls(target, int(values['sys_error'], 0))
        visitor.apply_to(function.body, None)
        if visitor.sites:
            validated[start] = visitor.sites
    if len(validated) != 1:
        raise RuntimeError(name + ': fatal diagnostic owner missing or ambiguous: ' + repr(validated))
    start = next(iter(validated))
    located[name] = hex(start)
    evidence[name] = {'string': hex(target), 'owner': hex(start), 'calls': [hex(ea) for ea in validated[start]]}
result = {'pointer_size': 4, 'functions': located, 'evidence': evidence}
"""


async def preprocess_skill(
    session, skill_name, expected_outputs, old_yaml_map, new_binary_dir, platform, image_base, debug=False
):
    _ = old_yaml_map
    artifact = _load_yaml_mapping(Path(new_binary_dir) / f"Sys_Error.{platform}.yaml")
    if not artifact or "func_va" not in artifact:
        return False
    located = await run_walk(session, WALK, {"diagnostics": DIAGNOSTICS, "sys_error": artifact["func_va"]})
    if debug:
        print(f"{skill_name}: {located}")
    if located.get("error") or located.get("pointer_size") != 4:
        return False
    payloads = {}
    for name in DIAGNOSTICS:
        output = _output_for_symbol(expected_outputs, name)
        if output is None:
            return False
        function = await inspect_func(session, int(located["functions"][name], 0), image_base, name)
        if function is None:
            return False
        payloads[output] = function
    for output, payload in payloads.items():
        write_func_yaml(output, payload)
    return True
