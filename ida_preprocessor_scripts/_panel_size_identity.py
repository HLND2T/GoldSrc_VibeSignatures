"""Pure value-provenance predicates for Panel sizing callsites.

Constants are values, not byte-pattern anchors. The Frame minimum is a source
invariant (Frame.cpp constructor), used only after locating that constructor by
its own strings and before validating the callee's IPanel forwarding behavior.
"""

FRAME_MINIMUM_SIZE = (128, 66)


def call_arguments(call, platform):
    return [call.get("this"), *call["stack_args"]] if platform == "windows" else call["stack_args"]


def constant(value):
    if isinstance(value, tuple) and len(value) == 2 and value[0] == "const":
        return value[1]
    return None


def scaled_constant(value, calls, receiver, platform):
    """Return (callee, constant) for an unmodified result on the same receiver."""

    def unambiguous(part):
        if part is None:
            return False
        return not isinstance(part, tuple) or (part[0] != "choice" and all(unambiguous(p) for p in part[1:]))

    if not unambiguous(receiver) or not isinstance(value, tuple) or len(value) != 2 or value[0] != "result":
        return None
    call = calls.get(value[1])
    if not call or not call.get("direct"):
        return None
    args = call_arguments(call, platform)
    if len(args) < 2 or args[0] != receiver:
        return None
    number = constant(args[1])
    return (call["direct"], number) if number is not None else None


def size_constants(call, calls, platform, *, scaled, scale_method=None):
    """Accept two constant values, or two exact results from the verified scaler."""
    args = call_arguments(call, platform)
    if len(args) < 3:
        return None
    if not scaled:
        values = tuple(constant(value) for value in args[1:3])
        return values if all(value is not None for value in values) else None
    if not scale_method:
        return None
    values = [scaled_constant(value, calls, args[0], platform) for value in args[1:3]]
    if any(value is None or value[0] != scale_method for value in values):
        return None
    return tuple(value[1] for value in values)


def frame_minimum_candidate(call, calls, platform):
    """Candidate only; the current callee must separately prove IPanel forwarding."""
    args = call_arguments(call, platform)
    if not call.get("direct") or len(args) < 3 or args[0] != ("arg", 0):
        return None
    if tuple(constant(value) for value in args[1:3]) == FRAME_MINIMUM_SIZE:
        return (call["direct"], None)
    values = [scaled_constant(value, calls, args[0], platform) for value in args[1:3]]
    if all(values) and values[0][0] == values[1][0] and tuple(v[1] for v in values) == FRAME_MINIMUM_SIZE:
        return (call["direct"], values[0][0])
    return None


def proportional_helper_dispatches(flow, platform, virtual_targets):
    """Verify identity return plus two scalar interface paths on one accessor.

    HL25 delegates normal/HD scaling to distinct current ISchemeManager slots and
    returns its input on the unscaled path. Slot numbers are recovered, never fixed.
    """
    calls = {call["ea"]: call for call in flow["calls"]}
    dispatches = []
    for call in calls.values():
        args = call_arguments(call, platform)
        for receiver, slot in virtual_targets(call["target"]):
            if len(args) < 2 or args[:2] != [receiver, ("arg", 1)]:
                continue
            if receiver is None or receiver[0] != "result":
                continue
            getter = calls.get(receiver[1], {}).get("direct")
            if getter:
                dispatches.append((getter, slot, call["ea"]))
    if len(dispatches) != 2 or len({d[0] for d in dispatches}) != 1 or len({d[1] for d in dispatches}) != 2:
        return None
    returned = set()
    for item in flow["returns"]:
        value = item["value"]
        returned.update(value[1:] if value and value[0] == "choice" else (value,))
    returned.update(("result", c["ea"]) for c in calls.values() if c.get("tail"))
    expected = {("arg", 1), *(("result", d[2]) for d in dispatches)}
    return dispatches if returned == expected else None


def forwarding_calls_only(calls, setter, getter, getvpanel_slot, virtual_targets):
    """Reject SetBounds and other helpers that do more than forward one setter."""
    return all(
        call["ea"] == setter
        or call.get("direct") == getter
        or (("arg", 0), getvpanel_slot) in virtual_targets(call["target"])
        for call in calls
    )
