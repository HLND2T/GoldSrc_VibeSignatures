"""Pure validation for native storage callsites; values come from the current image.

Strategy 0 is a branch redirect, 1 a filesystem Open vtable hook filtered by
return address, and 2 an engine Cvar_Set entry hook filtered by return address.
The latter two records are observation points, never instructions to overwrite.
"""


def unique(items, role):
    items = list(items)
    if len(items) != 1:
        raise ValueError(f"{role}: expected one result, got {len(items)}")
    return items[0]


def branch_strategy(raw, semantic):
    """Match the existing MetaHook branch API, without widening short calls."""
    raw = bytes(raw)
    if len(raw) == 5 and raw[0] == 0xE8:
        return 0
    if len(raw) == 6 and raw[:2] == b"\xff\x15":
        return 0
    if len(raw) >= 6 and raw[0] == 0xFF and (raw[1] >> 3) & 7 == 2 and raw[1] >> 6 == 2:
        return 0
    if semantic == "enumeration_open" and len(raw) in (2, 3) and raw[0] == 0xFF:
        mod, reg = raw[1] >> 6, (raw[1] >> 3) & 7
        if reg == 2 and mod in (0, 1):
            return 1
    if semantic == "resume_name_set" and len(raw) == 2 and raw[0] == 0xFF:
        if raw[1] >> 6 == 3 and (raw[1] >> 3) & 7 == 2:
            return 2
    raise ValueError(f"Unsupported {semantic} instruction: {raw.hex(' ')}")


def checked_capacity(destination, boundary, explicit=None):
    """Bound an output by a decoded stack object and any explicit CRT limit."""
    size = boundary - destination
    if not 0 < size <= 1 << 20:
        raise ValueError("Invalid stack destination boundary")
    if explicit is not None:
        if type(explicit) is not int or not 0 < explicit <= size:
            raise ValueError("CRT limit exceeds the destination")
        return explicit
    return size


def reconciled_call_cleanup(output_buffer, consumed_buffer, inferred_cleanup, pushed_arguments):
    """Reconcile one stack-output producer with its independently proven consumer.

    IDA can attribute a saved register to an indirect call's arguments. Require
    both the producer/consumer address difference and the actual argument
    pushes to agree before overriding that call's stack cleanup in the trace.
    """
    word_size = 4
    for value in (output_buffer, consumed_buffer):
        if not isinstance(value, tuple) or len(value) != 2 or value[0] != "stack" or type(value[1]) is not int:
            raise ValueError("Producer and consumer must address local stack buffers")
    if (
        type(inferred_cleanup) is not int
        or inferred_cleanup < 0
        or inferred_cleanup % word_size
        or type(pushed_arguments) is not int
        or pushed_arguments <= 0
    ):
        raise ValueError("Invalid x86 call cleanup evidence")
    cleanup = inferred_cleanup + output_buffer[1] - consumed_buffer[1]
    if cleanup != pushed_arguments * word_size:
        raise ValueError("Stack buffer identity disagrees with the decoded argument pushes")
    return cleanup


def edges_bypassing_block(graph, target):
    """Select paths reaching a producer in an already acyclic first-pass CFG."""
    if target not in graph:
        raise ValueError("Producer block is absent from the trace graph")
    ancestors = {target}
    while True:
        expanded = ancestors | {start for start, successors in graph.items() if ancestors.intersection(successors)}
        if expanded == ancestors:
            break
        ancestors = expanded
    return {
        (start, successor) for start in ancestors - {target} for successor in graph[start] if successor not in ancestors
    }


def relocated_stack_boundary(destination, members, relocations):
    """Keep frame object boundaries consistent with proven address relocations."""
    boundaries = []
    for offset in members:
        candidates = relocations.get(offset, {offset})
        if len(candidates) != 1:
            if offset >= destination or any(value > destination for value in candidates):
                raise ValueError("Stack object relocation is ambiguous")
            continue
        resolved = next(iter(candidates))
        if resolved > destination:
            boundaries.append(resolved)
    if not boundaries:
        raise ValueError("Missing next stack object boundary")
    return min(boundaries)


def validate_groups(discovered, declared):
    """Do not silently drop an inlined copy or synthesize an absent _1."""
    if set(discovered) != set(declared):
        raise ValueError("Callsite group inventory differs from the manifest")
    seen = set()
    for group, sites in discovered.items():
        if declared[group] != list(range(len(sites))):
            raise ValueError(f"{group}: incomplete contiguous numbering")
        for site in sites:
            if site["ea"] in seen:
                raise ValueError("A native callsite has multiple semantic owners")
            seen.add(site["ea"])
