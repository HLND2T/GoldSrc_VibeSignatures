"""Extend current Panel method identities with SetPos/SetBounds and their callers."""

IDENTIFY_BOUNDS = r"""
positions = dispatches(init, ("arg", 1), ("arg", 2), False, flow=init_flow)
for c in init_flow["calls"]:
    if c["direct"] and args(c)[:3] == [THIS, ("arg", 1), ("arg", 2)]:
        positions.extend(dispatches(c["direct"], ("arg", 1), ("arg", 2)))
posslots = {slot for g, slot, site in positions if g == getter}
if len(posslots) != 1:
    raise ValueError("position init " + repr(positions))
posslot = posslots.pop()
if posslot == sizeslot:
    raise ValueError("position and size dispatches must be distinct")

position_methods = set()
for ea in wrapper_owners:
    try:
        ds = dispatches(ea, ("arg", 1), ("arg", 2))
    except ValueError:
        continue
    if len(ds) == 1 and ds[0][:2] == (getter, posslot):
        position_methods.add(ea)
if len(position_methods) != 1:
    raise ValueError("non-unique Panel position method: " + repr(position_methods))

size_methods = set(methods["SetSize"])
candidates = set(wrapper_owners)
for target in position_methods | size_methods:
    candidates.update(owner for owner, _ in callers(target))
if values.get("bounds_owner") is not None:
    # A consumer scoped to one caller proves SetBounds among that caller's direct callees.
    candidates &= {c["direct"] for c in flow_at(values["bounds_owner"], platform)["calls"] if c["direct"]}


def bounds_body(ea):
    if platform == "windows" and callee_stack_purge(ea) != 4 * WORD_SIZE:
        return False
    flow = trace_panel_method(ea)
    return bounds_body_matches(flow, platform, ea, getter, getvp, vpanel_member, posslot, sizeslot,
                               position_methods, size_methods, preserved)


bounds = []
for ea in sorted(candidates):
    try:
        if bounds_body(ea):
            bounds.append(ea)
    except ValueError:
        continue
if len(bounds) != 1:
    raise ValueError("non-unique Panel SetBounds: " + repr(bounds))
target = bounds[0]
"""

COLLECT = r"""
sites = []
rejects = []
unproven_cleanup = []


def receiver_table(constructor):
    ctor_flow = flow_at(constructor, platform)
    return constructor_vtable(dict(ctor_flow, start=constructor))


def resolve_cleanup(ea, c, calls, owner):
    insn = idautils.DecodeInstruction(ea)
    operand = decoded_operand(insn.ops[0])
    if operand[0] != "mem" or operand[3] is not None or operand[2] < 0 or operand[2] % WORD_SIZE:
        raise ValueError("unresolved anomalous call cleanup")
    previous = idc.prev_head(ea, owner)
    load = idautils.DecodeInstruction(previous)
    if (idc.print_insn_mnem(previous) != "mov" or not load
        or decoded_operand(load.ops[0]) != ("reg", operand[1], WORD_SIZE)
        or decoded_operand(load.ops[1]) != ("mem", "ecx", 0, None, 1, WORD_SIZE)):
        raise ValueError("virtual table load is not correlated with the current receiver")
    constructors = constructor_receivers(c["this"], c["registers"].get(operand[1]), calls)
    if not constructors:
        raise ValueError("anomalous call lacks a constructed receiver")
    actual_purges = set()
    for constructor in constructors:
        table = receiver_table(constructor)
        if not table:
            # Some compilers keep operator new's pointer instead of using the
            # constructor's equal return value. Follow construction on that
            # exact allocation, rejecting ambiguous table assignments.
            allocation_results = {v for v in alternatives(c["this"]) if v and v[0] == "result"
                                  and calls.get(v[1], {}).get("direct") == constructor}
            tables = set()
            for prior in calls.values():
                if prior["ea"] < ea and prior.get("direct") and prior["this"] in allocation_results:
                    candidate = receiver_table(prior["direct"])
                    if candidate:
                        tables.add(candidate)
            if len(tables) != 1:
                raise ValueError("unproven constructor vptr")
            table = tables.pop()
        method = int(ida_bytes.get_dword(table + operand[2]))
        method_func = ida_funcs.get_func(method)
        if not method_func or method_func.start_ea != method:
            raise ValueError("invalid current virtual method")
        actual_purges.add(callee_stack_purge(method))
    if len(actual_purges) != 1:
        raise ValueError("ambiguous actual virtual call cleanup")
    return actual_purges.pop()


def bounds_caller_flow(owner, entry):
    purges = {}
    unsafe = set()
    original = flow_at(owner, platform, entry_state=entry)
    if platform == "windows":
        function = ida_funcs.get_func(owner)
        calls = call_map(original)
        setters = [c for c in original["calls"] if c["direct"] == target and not c.get("tail")]
        suspicious = []
        for ea in idautils.FuncItems(owner):
            if idc.print_insn_mnem(ea) != "call":
                continue
            delta = ida_frame.get_spd(function, ea + ida_bytes.get_item_size(ea)) - ida_frame.get_spd(function, ea)
            if delta > MAX_ARGUMENTS * WORD_SIZE:
                call = calls.get(ea)
                if not call:
                    continue
                affected = calls_reached_after(original, call, setters)
                if affected:
                    suspicious.append((ea, affected))
        if suspicious:
            # IDA can infer a fictitious 136-byte purge on a one-bool VGUI call
            # in aligned-stack constructors. Resolve the actual current target
            # from the constructed receiver's vptr, never from a fixed slot.
            memory_flow = flow_at(owner, platform, entry_state=entry, track_memory=True)
            calls = call_map(memory_flow)
            for ea, affected in suspicious:
                c = calls.get(ea)
                try:
                    if not c:
                        raise ValueError("missing current call event")
                    purges[ea] = resolve_cleanup(ea, c, calls, owner)
                except ValueError as error:
                    unsafe.update(affected)
                    unproven_cleanup.append(dict(ea=hex(ea), excluded=[hex(s) for s in sorted(affected)], reason=str(error)))
    return (flow_at(owner, platform, entry_state=entry, call_purges=purges) if purges else original), unsafe


for owner in sorted({owner for owner, _ in callers(target)}):
    entry = {("stack", 4 * (i + 1)): ("arg", i + (platform == "windows")) for i in range(MAX_ARGUMENTS)}
    entry.update({r: ("entry_register", owner, r) for r in ("eax", "ecx", "edx", "ebx", "esi", "edi", "ebp")})
    if platform == "windows":
        entry["ecx"] = THIS
    try:
        flow, unsafe = bounds_caller_flow(owner, entry)
    except ValueError as e:
        rejects.append([hex(owner), str(e)])
        continue
    calls = call_map(flow)
    for c in flow["calls"]:
        if c["direct"] != target or c.get("tail") or c["ea"] in unsafe:
            continue
        constants = bounds_constants(c, calls, platform)
        if constants is not None:
            sites.append(dict(ea=hex(c["ea"]), owner=hex(owner), constants=constants, mode="Const"))
        else:
            constants = bounds_scaled_constants(c, calls, platform, scale)
            if constants is not None:
                sites.append(dict(ea=hex(c["ea"]), owner=hex(owner), constants=constants, mode="ScaledConst"))
result = dict(method=hex(target), position=hex(next(iter(position_methods))),
              size=hex(next(iter(size_methods))), scale=hex(scale) if scale else None,
              sites=sites, rejects=rejects, unproven_cleanup=unproven_cleanup)
"""
