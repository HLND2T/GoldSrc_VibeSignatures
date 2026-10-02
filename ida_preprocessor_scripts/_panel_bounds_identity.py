"""Argument provenance and forwarding contract for nonvirtual Panel::SetBounds."""

from ida_preprocessor_scripts._panel_size_identity import call_arguments, constant, scaled_constant
from ida_preprocessor_scripts._x86_vcall_flow import alternatives, virtual_targets


def bounds_constants(call, calls, platform):
    """Require all four explicit arguments, including coordinates, to be constants."""
    args = call_arguments(call, platform)
    if len(args) < 5:
        return None
    values = tuple(constant(value) for value in args[1:5])
    return values if all(value is not None for value in values) else None


def bounds_scaled_constants(call, calls, platform, scale_method):
    """Allow literal zero coordinates, otherwise require same-Panel scaled constants."""
    args = call_arguments(call, platform)
    if len(args) < 5 or not scale_method:
        return None
    values = []
    for index, value in enumerate(args[1:5]):
        if index < 2 and constant(value) == 0:
            values.append(0)
            continue
        scaled = scaled_constant(value, calls, args[0], platform)
        if scaled is None or scaled[0] != scale_method:
            return None
        values.append(scaled[1])
    return tuple(values)


def bounds_forwarder(operations):
    """SetBounds forwards its own four parameters to SetPos then SetSize."""
    return operations == [
        ("pos", ("arg", 0), ("arg", 1), ("arg", 2)),
        ("size", ("arg", 0), ("arg", 3), ("arg", 4)),
    ]


def constructor_vtable(flow):
    """A single vptr assignment on the object returned by a constructor."""
    this = ("arg", 0)
    if not flow["returns"] or any(r["value"] != this for r in flow["returns"]):
        return None
    stores = [s for s in flow["stores"] if s["address"] == this]
    if len(stores) != 1 or stores[0]["width"] != 4:
        return None
    table = constant(stores[0]["value"])
    if table is None or not table:
        return None
    required = stores[0]["block"]
    start = flow["start"]
    pending, visited = [start], {required}
    while pending:
        block = pending.pop()
        if block in visited:
            continue
        if not flow["blocks"].get(block):
            return None
        visited.add(block)
        pending.extend(flow["blocks"][block])
    return table


def constructor_receivers(receiver, table_value, calls):
    """Resolve non-null constructed receivers of a virtual call; null paths trap."""
    constructors = set()
    for value in alternatives(receiver):
        if value == ("const", 0):
            continue
        if not value or value[0] != "result" or ("load", value, 0) not in alternatives(table_value):
            return None
        target = calls.get(value[1], {}).get("direct")
        if not target:
            return None
        constructors.add(target)
    return constructors or None


def calls_reached_after(flow, call, targets):
    """Return downstream callsites without depending on their argument classification."""
    reached, pending = set(), list(flow["blocks"].get(call["block"], []))
    while pending:
        block = pending.pop()
        if block in reached:
            continue
        reached.add(block)
        pending.extend(flow["blocks"].get(block, []))
    return {c["ea"] for c in targets if (c["block"] == call["block"] and c["ea"] > call["ea"]) or c["block"] in reached}


def bounds_body_matches(
    flow, platform, start, getter, getvp, vpanel_member, posslot, sizeslot, position_methods, size_methods, preserved=()
):
    """Validate direct or inlined setters, their receiver, and unavoidable execution."""
    this = ("arg", 0)
    calls = {c["ea"]: c for c in flow["calls"]}
    operations, operation_blocks = [], []
    for c in sorted(calls.values(), key=lambda c: c["ea"]):
        a = call_arguments(c, platform)
        if c["direct"] in position_methods | size_methods:
            if len(a) < 3:
                return False
            operations.append(("pos" if c["direct"] in position_methods else "size", *a[:3]))
            operation_blocks.append(c["block"])
            continue
        if c["direct"] == getter or c["direct"] in preserved:
            continue
        targets = virtual_targets(c["target"])
        if targets == [(this, getvp)] and a and a[0] == this:
            continue
        matched = False
        for receiver, slot in targets:
            if not receiver or receiver[0] != "result" or calls.get(receiver[1], {}).get("direct") != getter:
                continue
            if slot not in (posslot, sizeslot) or len(a) < 4 or a[0] != receiver:
                continue
            if not all(
                vp == ("load", this, vpanel_member)
                or (vp and vp[0] == "result" and (this, getvp) in virtual_targets(calls.get(vp[1], {}).get("target")))
                for vp in alternatives(a[1])
            ):
                return False
            operations.append(("pos" if slot == posslot else "size", this, *a[2:4]))
            operation_blocks.append(c["block"])
            matched = True
        if not matched:
            return False
    if not bounds_forwarder(operations):
        return False
    if any(not s["address"] or s["address"][0] != "stack" for s in flow["stores"]):
        return False
    graph = flow["blocks"]
    exits = {b for b, successors in graph.items() if not successors}
    if not exits:
        return False
    for required in operation_blocks:
        if required == start:
            continue
        pending, visited = [start], {required}
        while pending:
            block = pending.pop()
            if block in visited:
                continue
            if block in exits:
                return False
            visited.add(block)
            pending.extend(graph.get(block, []))
    return True
