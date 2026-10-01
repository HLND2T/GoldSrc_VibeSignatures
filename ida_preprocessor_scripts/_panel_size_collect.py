"""Current-binary discovery for constant Panel size callsites.

Frame constructor literals locate the source SetMinimumSize(128,66) statement.
Its callee must be a pure IPanel forwarding wrapper; the current Panel table
proves GetVPanel. Panel::Init forwards its third/fourth explicit arguments to
IPanel::SetSize, identifying that slot independently of ABI slot numbers.
"""

COLLECT = r"""
platform = values["platform"]
THIS = ("arg", 0)
init = values["init"]
panel = table_for("vgui2::Panel")
entries = {int(k): int(v, 0) for k, v in panel["vtable_entries"].items()}
original_flow_at = flow_at
preserved = set()
checked = set()


def flow_at(ea, platform, **kwargs):
    stack_check_helpers([ea], stack_check_preserves_registers, checked, preserved)
    return original_flow_at(ea, platform, preserved_calls=preserved, **kwargs)


def args(c):
    return ([c["this"]] + c["stack_args"]) if platform == "windows" else c["stack_args"]


owners = {s: set() for s in ["Untitled", "MinimizeToSysTray"]}
strings = idautils.Strings()
strings.setup(strtypes=[ida_nalt.STRTYPE_C])
for s in strings:
    if str(s) in owners:
        for x in idautils.XrefsTo(s.ea):
            f = ida_funcs.get_func(x.frm)
            if f:
                owners[str(s)].add(f.start_ea)
roots = set.intersection(*owners.values())
minimum = []
for ea in roots:
    flow = flow_at(ea, platform)
    calls = call_map(flow)
    for c in flow["calls"]:
        candidate = frame_minimum_candidate(c, calls, platform)
        if candidate:
            minimum.append((*candidate, ea, c["ea"]))
if not minimum:
    raise ValueError("minimum identity " + repr(minimum) + " roots " + repr(roots))
minimum_candidates = minimum
flow = {"calls": [c for e in [init] + [m[0] for m in minimum_candidates] for c in flow_at(e, platform)["calls"]]}
getvp = []
for c in flow["calls"]:
    for recv, offset in virtual_targets(c["target"]):
        if recv == THIS and offset // 4 in entries:
            leaf = flow_at(entries[offset // 4], platform)
            returns = {r["value"] for r in leaf["returns"]}
            if len(returns) == 1 and not leaf["calls"]:
                v = next(iter(returns))
                if v and v[0] == "load" and v[1] == THIS and v[2] > 0:
                    getvp.append((offset, v[2]))
if len(set(getvp)) != 1:
    raise ValueError("getvp " + repr(getvp))
getvp, vpanel_member = getvp[0]


def trace_panel_method(ea):
    flow = flow_at(ea, platform)
    purges = (
        {c["ea"]: 0 for c in flow["calls"] if (THIS, getvp) in virtual_targets(c["target"])}
        if platform == "windows"
        else {}
    )
    return flow_at(ea, platform, call_purges=purges) if purges else flow


def dispatches(ea, width, height, require_vpanel=True, flow=None):
    # Two explicit int arguments; this is an ABI width, not a vtable slot.
    if require_vpanel and platform == "windows" and callee_stack_purge(ea) != 2 * WORD_SIZE:
        return []
    flow = trace_panel_method(ea) if flow is None else flow
    calls = call_map(flow)
    found = []
    for c in flow["calls"]:
        a = args(c)
        for recv, slot in virtual_targets(c["target"]):
            if len(a) < 4 or a[0] != recv or a[2:4] != [width, height]:
                continue
            vp = a[1]
            if not require_vpanel or all(
                v == ("load", THIS, vpanel_member)
                or (v and v[0] == "result" and (THIS, getvp) in virtual_targets(calls.get(v[1], {}).get("target")))
                for v in alternatives(vp)
            ):
                getter = direct_receiver(recv, calls)
                if getter:
                    if require_vpanel and not forwarding_calls_only(
                        flow["calls"], c["ea"], getter, getvp, virtual_targets
                    ):
                        continue
                    found.append((getter, slot, c["ea"]))
    return found


valid = []
for candidate in minimum_candidates:
    try:
        ds = dispatches(candidate[0], ("arg", 1), ("arg", 2))
    except ValueError:
        continue
    if len(ds) == 1:
        valid.append((candidate, ds))
if len(valid) != 1:
    raise ValueError("minimum dispatch " + repr(valid))
(minimum, scale, ctor, minsite), mind = valid[0]
getter, minslot, _ = mind[0]


def trace_init():
    flow = trace_panel_method(init)
    if platform != "windows":
        return flow
    calls = call_map(flow)
    purges = {c["ea"]: 0 for c in flow["calls"] if (THIS, getvp) in virtual_targets(c["target"])}
    for c in flow["calls"]:
        for recv, slot in virtual_targets(c["target"]):
            if direct_receiver(recv, calls) == getter:
                # IPanel::Init(VPANEL, IClientPanel*) versus SetPos/SetSize(VPANEL,int,int).
                purges[c["ea"]] = WORD_SIZE * (2 if c["stack_args"][1] == THIS else 3)
    return flow_at(init, platform, call_purges=purges)


init_flow = trace_init()
sizes = dispatches(init, ("arg", 3), ("arg", 4), False, flow=init_flow)
for c in init_flow["calls"]:
    if c["direct"] and args(c)[:3] == [THIS, ("arg", 3), ("arg", 4)]:
        sizes.extend(dispatches(c["direct"], ("arg", 1), ("arg", 2)))
sizes = [d for d in sizes if d[0] == getter]
if len(sizes) != 1:
    raise ValueError("size init " + repr(sizes))
sizeslot = sizes[0][1]
wrapper_owners = {owner for owner, _ in callers(getter)}
methods = {"SetSize": [], "SetMinimumSize": []}
for ea in wrapper_owners:
    try:
        dispatch = dispatches(ea, ("arg", 1), ("arg", 2))
    except ValueError:
        continue
    for g, slot, site in dispatch:
        if g == getter and slot in [sizeslot, minslot]:
            methods["SetSize" if slot == sizeslot else "SetMinimumSize"].append(ea)
result = {
    "init": hex(init),
    "minimum": hex(minimum),
    "scale": hex(scale) if scale else None,
    "ctor": hex(ctor),
    "getvp": getvp,
    "slots": [sizeslot, minslot],
    "methods": methods,
}
if any(len(set(v)) != 1 for v in methods.values()):
    raise ValueError("non-unique Panel size methods: " + repr(methods))
if values["scaled"] and scale is None:
    raise ValueError("scaled mode requires a current proportional helper")
if scale is not None and not proportional_helper_dispatches(flow_at(scale, platform), platform, virtual_targets):
    raise ValueError("proportional helper lacks identity/normal/HD scalar dispatches")
sites = {k: [] for k in methods}
rejects = []
for kind, targets in methods.items():
    owners = set()
    for target in targets:
        owners.update(owner for owner, _ in callers(target))
    for owner in sorted(owners):
        entry = {("stack", 4 * (i + 1)): ("arg", i + (platform == "windows")) for i in range(MAX_ARGUMENTS)}
        entry.update({r: ("entry_register", owner, r) for r in ("eax", "ecx", "edx", "ebx", "esi", "edi", "ebp")})
        if platform == "windows":
            entry["ecx"] = THIS
        try:
            flow = flow_at(owner, platform, entry_state=entry)
        except ValueError as e:
            rejects.append([hex(owner), str(e)])
            continue
        calls = call_map(flow)
        for c in flow["calls"]:
            if c["direct"] not in targets or c.get("tail"):
                continue
            a = args(c)
            if len(a) < 3:
                continue
            constants = size_constants(c, calls, platform, scaled=values["scaled"], scale_method=scale)
            if constants is None:
                continue
            sites[kind].append({"ea": hex(c["ea"]), "owner": hex(owner), "constants": constants, "this": a[0]})
result["sites"] = sites
result["rejects"] = rejects
"""
