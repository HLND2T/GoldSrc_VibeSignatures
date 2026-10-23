"""Frame key-message identities over decoded x86 values and control flow."""

FRAME_THIS = ("arg", 0)
FRAME_KEY = ("arg", 1)
KEY_ESCAPE = 70
KEY_ENTER = 64
KEY_F4 = 95
ESCAPE_FEATURE = 3
MODIFIER_KEYS = frozenset(range(79, 85))


def key_dispatch(call):
    """Require the vptr and actual call receiver to agree."""
    args, target = call["args"], call["target"]
    if not args or args[0] is None or not isinstance(target, tuple) or len(target) != 3:
        return None
    if target[:2] != ("load", ("load", args[0], 0)):
        return None
    offset = target[2]
    return (args[0], offset // 4) if isinstance(offset, int) and offset >= 0 and offset % 4 == 0 else None


def key_reachable(graph, start):
    pending, seen = [start], set()
    while pending:
        block = pending.pop()
        if block not in seen:
            seen.add(block)
            pending.extend(graph.get(block, []))
    return seen


def key_guard(flow, positive, negative, block):
    return block in key_reachable(flow["blocks"], positive) and block not in key_reachable(flow["blocks"], negative)


def key_equals(flow, value, block):
    return any(
        set(c["values"]) == {FRAME_KEY, ("const", value)} and key_guard(flow, c["equal"], c["unequal"], block)
        for c in flow["equalities"]
    )


def key_truth(flow, value, block):
    return any(c["condition"] == value and key_guard(flow, c["nonzero"], c["zero"], block) for c in flow["branches"])


def key_sole(items, label):
    items = list(items)
    if len(items) != 1:
        raise ValueError(f"{label}: expected one candidate, found {len(items)}")
    return items[0]


def unique_slot(entries, address):
    return key_sole([i for i, ea in entries.items() if ea == address], "current Frame slot")


def key_alternatives(value):
    return value[1:] if value and value[0] == "choice" else (value,)


def message_posts(flow, literals, names):
    labels = {("const", a) for addresses in literals.values() for a in addresses}
    message_objects = set()
    for call in flow["calls"]:
        if call["direct"] and len(call["args"]) > 1 and call["args"][1] in labels:
            message_objects.update((("result", call["ea"]), call["args"][0]))
    message_objects.discard(None)
    message_objects.discard(("const", 0))
    constructors = [
        c
        for c in flow["calls"]
        if c["direct"]
        and len(c["args"]) > len(names)
        and all(c["args"][i + 1] in {("const", a) for a in literals[n]} for i, n in enumerate(names))
    ]
    posts = []
    for ctor in constructors:
        objects = {("result", ctor["ea"]), ctor["args"][0]}
        objects.discard(None)
        objects.discard(("const", 0))
        for call in flow["calls"]:
            dispatch = key_dispatch(call)
            if not dispatch or dispatch[0] != FRAME_THIS or len(call["args"]) < 4:
                continue
            parts = set(key_alternatives(call["args"][2]))
            if parts & objects and parts <= message_objects | {("const", 0)} and ctor["ea"] < call["ea"]:
                posts.append(dict(call, message_block=ctor["block"], message_constructor=ctor["ea"]))
    return posts


def interface_getter(flow, call):
    dispatch = key_dispatch(call)
    if not dispatch or not dispatch[0] or dispatch[0][0] != "result":
        return None
    return next((c["direct"] for c in flow["calls"] if c["ea"] == dispatch[0][1]), None)


def identify_pressed(flow, literals):
    posts = [
        c
        for c in message_posts(flow, literals, ("Command", "command", "Cancel"))
        if c["args"][1] == FRAME_THIS and key_equals(flow, KEY_ESCAPE, c["message_block"])
    ]
    post = key_sole(posts, "Escape Cancel to self")
    supports = [
        c
        for c in flow["calls"]
        if interface_getter(flow, c) is not None
        and c["args"][1:2] == [("const", ESCAPE_FEATURE)]
        and key_equals(flow, KEY_ESCAPE, c["block"])
        and key_truth(flow, ("result", c["ea"]), post["message_block"])
    ]
    support = key_sole(supports, "positive Escape capability")
    return interface_getter(flow, support), key_dispatch(support)[1], key_dispatch(post)[1]


def identify_typed(flow, literals):
    closes = [
        c
        for c in message_posts(flow, literals, ("CloseFrameButtonPressed",))
        if c["args"][1] == FRAME_THIS and key_equals(flow, KEY_F4, c["message_block"])
    ]
    key_sole(closes, "F4 close message")
    hotkeys = [
        c
        for c in message_posts(flow, literals, ("Hotkey",))
        if c["args"][1] not in (None, FRAME_THIS, ("const", 0)) and key_equals(flow, KEY_ENTER, c["message_block"])
    ]
    key_sole(hotkeys, "Enter default-button hotkey")
    modifiers = [
        (interface_getter(flow, c), key_dispatch(c)[1], c["args"][1][1])
        for c in flow["calls"]
        if key_dispatch(c)
        and interface_getter(flow, c) is not None
        and c["args"][1:2]
        and c["args"][1] in {("const", k) for k in MODIFIER_KEYS}
    ]
    provider, index = key_sole({(p, i) for p, i, k in modifiers}, "modifier input provider")
    if {k for p, i, k in modifiers} != MODIFIER_KEYS:
        raise ValueError("incomplete Shift/Ctrl/Alt query set")
    return provider, index
