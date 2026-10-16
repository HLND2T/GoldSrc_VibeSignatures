"""Current-table identities for Unicode ComboBox menu operations.

Arguments and receivers, rather than adjacent slots or call ordering, distinguish
the overloads. All displacements supplied to these checks come from the current
binary. Unknown or overlapping identities fail closed.
"""

from ida_preprocessor_scripts._vgui_private_method_identity import (
    THIS,
    contains_value,
    method_calls,
    pure_member_return,
    sole,
    virtual_dispatch,
)

# IDA_BODY


def member_value(value):
    return isinstance(value, tuple) and len(value) == 3 and value[:2] == ("load", THIS) and value[2] > 0


def message_calls(method, literals, text_argument):
    names = {("const", ea) for ea in literals["SetText"]["addresses"]}
    keys = {("const", ea) for ea in literals["text"]["addresses"]}
    return [
        call
        for call in method_calls(method)
        if call["direct"]
        and len(call["args"]) >= 4
        and call["args"][1] in names
        and call["args"][2] in keys
        and call["args"][3] == text_argument
        and call["args"][0] is not None
    ]


def add_item_evidence(method, literals, *, menu_index=None, dropdown=None, wide=False):
    messages = message_calls(method, literals, ("arg", 1))
    returns = set()
    for returned in method.get("flow", {}).get("returns", []):
        value = returned["value"]
        returns.update(value[1:] if value and value[0] == "choice" else (value,))
    found = []
    for call in method_calls(method):
        dispatch = virtual_dispatch(call)
        args = call["args"]
        if len(args) < 5 or not dispatch or not member_value(dispatch[0]) or args[0] != dispatch[0]:
            continue
        if dropdown is not None and dispatch[0][2] != dropdown:
            continue
        if menu_index is not None and dispatch[1] != menu_index:
            continue
        if args[3:5] != [THIS, ("arg", 2)] or ("result", call["ea"]) not in returns:
            continue
        for message in messages:
            choices = args[2][1:] if args[2] and args[2][0] == "choice" else (args[2],)
            identities = (message["args"][0], ("result", message["ea"]))
            if not any(value in identities for value in choices) or any(
                value not in identities + (("const", 0),) for value in choices
            ):
                continue
            if wide:
                # A current-IDB CTree comparison proves that this exact call
                # consumes the same local output buffer as Unicode conversion.
                if call["ea"] not in method.get("converted_menu_calls", ()):
                    continue
            elif args[1] != ("arg", 1):
                continue
            found.append(
                dict(method=method, call=call, message=message, dropdown=dispatch[0][2], menu_index=dispatch[1])
            )
    return sole(found, "ComboBox AddItem overload") if found else None


def recover_menu_getter(methods, dropdown):
    return sole([m for m in methods if pure_member_return(m) == ("load", THIS, dropdown)], "ComboBox GetMenu")


def stripped_result(value):
    while isinstance(value, tuple) and value and value[0] == "narrow":
        value = value[1]
    return value


def before_guard(graph, start, guard):
    visited, pending = set(), [start]
    while pending:
        current = pending.pop()
        if current == guard or current in visited:
            continue
        visited.add(current)
        pending.extend(graph.get(current, ()))
    return visited


def spectator_update_calls(method):
    """Bind the valid-ID test and its two arms on one ComboBox receiver."""
    flow = method.get("flow", {})
    virtual = [(c, virtual_dispatch(c)) for c in flow.get("calls", [])]
    virtual = [(c, d) for c, d in virtual if d and c["args"][0] == d[0]]
    found = []
    for check, dispatch in virtual:
        receiver = dispatch[0]
        if (
            len(check["args"]) < 2
            or not isinstance(receiver, tuple)
            or receiver[0] != "load"
            or check["args"][1] is None
        ):
            continue
        for branch in flow.get("branches", []):
            if stripped_result(branch["condition"]) != ("result", check["ea"]):
                continue
            zero = before_guard(flow["blocks"], branch["zero"], check["block"])
            nonzero = before_guard(flow["blocks"], branch["nonzero"], check["block"])
            for add, add_dispatch in virtual:
                if len(add["args"]) < 3:
                    continue
                if add_dispatch[0] != receiver or add["block"] not in zero - nonzero:
                    continue
                text, user = add["args"][1:3]
                if text is None or user is None or text == check["args"][1]:
                    continue
                for update, update_dispatch in virtual:
                    if len(update["args"]) < 4:
                        continue
                    if update_dispatch[0] != receiver or update["block"] not in nonzero - zero:
                        continue
                    if update["args"][1:4] != [check["args"][1], text, user]:
                        continue
                    if len({dispatch[1], add_dispatch[1], update_dispatch[1]}) != 3:
                        continue
                    found.append(dict(check=check, add=add, update=update, receiver=receiver))
    return sole(found, "spectator valid-ID/update/add branch") if found else None


def update_item_evidence(method, literals, dropdown):
    """Recover the wide menu update and deferred layout call on the valid-ID arm."""
    flow = method.get("flow", {})
    calls = method_calls(method)
    menu = ("load", THIS, dropdown)
    found = []
    for check in calls:
        dispatch = virtual_dispatch(check)
        if not dispatch or dispatch[0] != menu or check["args"][:2] != [menu, ("arg", 1)]:
            continue
        for branch in flow.get("branches", []):
            if stripped_result(branch["condition"]) != ("result", check["ea"]):
                continue
            zero = before_guard(flow["blocks"], branch["zero"], check["block"])
            nonzero = before_guard(flow["blocks"], branch["nonzero"], check["block"])
            valid = nonzero - zero
            for update in calls:
                target, args = virtual_dispatch(update), update["args"]
                if not target or target[0] != menu or update["block"] not in valid or len(args) < 5:
                    continue
                if args[:3] != [menu, ("arg", 1), ("arg", 2)] or args[4] != ("arg", 3):
                    continue
                # The old conversion's alloca buffer may be unknown to the tracer.
                # Bind the message object and literal keys, not that lossy text.
                messages = [
                    c for c in calls if len(c["args"]) >= 4 and c in message_calls(method, literals, c["args"][3])
                ]
                choices = args[3][1:] if args[3] and args[3][0] == "choice" else (args[3],)
                if not any(
                    any(v in (m["args"][0], ("result", m["ea"])) for v in choices)
                    and all(v in (m["args"][0], ("result", m["ea"]), ("const", 0)) for v in choices)
                    for m in messages
                ):
                    continue
                for invalidate in calls:
                    target = virtual_dispatch(invalidate)
                    if (
                        target
                        and target[0] == THIS
                        and invalidate["block"] in valid
                        and invalidate["args"][:3] == [THIS, ("const", 0), ("const", 0)]
                    ):
                        found.append(dict(update=update, invalidate=invalidate))
    return sole(found, "wide menu update and deferred layout") if found else None
