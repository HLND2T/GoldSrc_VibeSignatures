"""Source-level VGUI method identities over current-binary x86 flow facts.

No method position or object displacement is assumed here. The collector supplies
candidate table entries and their decoded calls/stores; related methods must agree
on the scrollbar, active page and font dispatch recovered from those same bodies.
"""

THIS = ("arg", 0)
CHARACTER_FILTER_CODES = frozenset((ord("\t"), ord("\n"), ord("\r")))
TAB_GEOMETRY = frozenset((2, 4, 25, 27))


def _member(value):
    return (
        isinstance(value, tuple)
        and len(value) == 3
        and value[:2] == ("load", THIS)
        and isinstance(value[2], int)
        and value[2] > 0
    )


def _virtual_slot(call):
    args = call["args"]
    target = call["target"]
    if (
        args
        and args[0] is not None
        and isinstance(target, tuple)
        and len(target) == 3
        and target[:2] == ("load", ("load", args[0], 0))
        and isinstance(target[2], int)
        and target[2] >= 0
        and target[2] % 4 == 0
    ):
        return target[2]
    return None


def _output_call(call, count):
    args = call["args"]
    return (
        len(args) >= count + 1
        and args[0] == THIS
        and all(isinstance(arg, tuple) and arg[0] == "stack" for arg in args[1 : count + 1])
        and len(set(args[1 : count + 1])) == count
    )


def _font_dispatches(method):
    calls = {call["ea"]: call for call in method["calls"]}
    found = set()
    for call in calls.values():
        args, slot = call["args"], _virtual_slot(call)
        if slot is None or len(args) < 2 or not _member(args[1]):
            continue
        receiver = args[0]
        if isinstance(receiver, tuple) and receiver[0] == "result":
            getter = calls.get(receiver[1], {}).get("direct")
            if getter is not None:
                found.add((getter, slot, args[1]))
    return found


def _unique(matches, name):
    if len(matches) != 1:
        raise ValueError(f"{name} behavior is ambiguous: {[(m['index'], m['address']) for m in matches]}")
    return matches[0]


def _character_filters(method):
    values = set()
    for comparison in method["comparisons"]:
        left, right = comparison["values"]
        # Windows wchar_t is a word; ELF uses the full argument. A load
        # through that argument belongs to InsertString, even when its loop
        # inlines all of InsertChar's warning/filtering logic.
        if isinstance(left, tuple) and left[0] == "narrow":
            left = left[1]
        if left == ("arg", 1) and isinstance(right, tuple) and right[0] == "const":
            values.add(right[1])
    return CHARACTER_FILTER_CODES <= values


def recover_private_methods(text_methods, sheet_methods, setsize):
    """Return five verified entries, failing closed on absent/ambiguous identities.

    TextEntry::InsertChar rejects CR/LF/Tab and plays Resource\\warning.wav.
    LayoutVerticalScrollBarSlider gets four insets, sizes its scrollbar using a
    member width and divides height by font height. GetStartDrawIndex shares the
    scrollbar/font dispatch and writes the caller's line-break index reference.
    HasHotkey forwards its key through a child returned from the active page.
    PerformLayout gets four bounds, lays out that page and the 25/27-high tabs,
    and calls the base implementation at its own dynamically discovered slot.
    """
    inherited = [method for method in text_methods if method["address"] == method["base"]]
    insert = _unique(
        [method for method in inherited if method["warning"] and _character_filters(method)],
        "TextEntry::InsertChar",
    )

    layouts = []
    for method in inherited:
        if not method["divides"] or not _font_dispatches(method):
            continue
        if not any(_virtual_slot(call) is not None and _output_call(call, 4) for call in method["calls"]):
            continue
        scrollbars = {
            call["args"][0]
            for call in method["calls"]
            if call["direct"] == setsize
            and len(call["args"]) >= 3
            and _member(call["args"][0])
            and _member(call["args"][1])
        }
        if len(scrollbars) == 1:
            layouts.append(dict(method, scrollbar=next(iter(scrollbars))))
    layout = _unique(layouts, "TextEntry::LayoutVerticalScrollBarSlider")
    scrollbar_slots = {
        _virtual_slot(call)
        for call in layout["calls"]
        if call["args"] and call["args"][0] == layout["scrollbar"] and _virtual_slot(call) is not None
    }
    draws = []
    for method in inherited:
        if not method["divides"] or not (_font_dispatches(method) & _font_dispatches(layout)):
            continue
        if not any(store["address"] == ("arg", 1) for store in method["stores"]):
            continue
        if any(
            call["args"] and call["args"][0] == layout["scrollbar"] and _virtual_slot(call) in scrollbar_slots
            for call in method["calls"]
        ):
            draws.append(method)
    draw = _unique(draws, "TextEntry::GetStartDrawIndex")

    overrides = [method for method in sheet_methods if method["address"] != method["base"]]
    hotkeys = []
    for method in overrides:
        calls = {call["ea"]: call for call in method["calls"]}
        pages = set()
        for call in calls.values():
            args = call["args"]
            if _virtual_slot(call) != method["index"] * 4 or len(args) < 2 or args[1] != ("arg", 1):
                continue
            child = args[0]
            if not isinstance(child, tuple) or child[0] != "result":
                continue
            producer = calls.get(child[1])
            if not producer or producer["direct"] is None or not producer["args"]:
                continue
            page = producer["args"][0]
            if _member(page) and any(
                other["direct"] is not None
                and other["direct"] != producer["direct"]
                and other["args"]
                and other["args"][0] == page
                for other in calls.values()
            ):
                pages.add(page)
        if len(pages) == 1:
            hotkeys.append(dict(method, page=next(iter(pages))))
    hotkey = _unique(hotkeys, "PropertySheet::HasHotkey")

    performs = []
    for method in overrides:
        # These are source tab geometry constants, not ABI positions. HL25
        # passes them through proportional scaling before setting tab bounds.
        if not TAB_GEOMETRY <= method["immediates"]:
            continue
        bounds = [call for call in method["calls"] if call["direct"] is not None and _output_call(call, 4)]
        page_bounds = [
            call
            for call in method["calls"]
            if call["direct"] is not None
            and len(call["args"]) >= 5
            and call["args"][:2] == [hotkey["page"], ("const", 0)]
        ]
        if (
            bounds
            and page_bounds
            and any(
                call["direct"] == method["base"] and call["ea"] < min(item["ea"] for item in bounds)
                for call in method["calls"]
            )
        ):
            performs.append(method)
    perform = _unique(performs, "PropertySheet::PerformLayout")
    return {"insert": insert, "layout": layout, "draw": draw, "hotkey": hotkey, "perform": perform}


def contains_value(value, needle):
    if value == needle:
        return True
    if isinstance(value, (tuple, list)):
        return any(contains_value(part, needle) for part in value)
    if isinstance(value, dict):
        return any(contains_value(part, needle) for part in value.values())
    return False


def sole(values, label):
    values = list(values)
    if len(values) != 1:
        raise ValueError(f"{label}: expected one identity, found {len(values)}")
    return values[0]


def virtual_dispatch(call):
    """Decode a full-width vtable load, including an embedded subobject."""
    target = call.get("target")
    if not isinstance(target, tuple) or len(target) != 3 or target[0] != "load":
        return None
    table, offset = target[1:]
    if not isinstance(table, tuple) or len(table) != 3 or table[0] != "load":
        return None
    if not isinstance(offset, int) or offset < 0 or offset % 4:
        return None
    receiver = table[1] if table[2] == 0 else ("address", table[1], table[2])
    return (receiver, offset // 4) if receiver is not None else None


def table_methods(data, class_name):
    entries = data["tables"][class_name]["vtable_entries"]
    return [
        dict(data["functions"][str(int(address, 0))], index=int(index))
        for index, address in entries.items()
        if str(int(address, 0)) in data["functions"] and "flow" in data["functions"][str(int(address, 0))]
    ]


def method_calls(method):
    return method.get("flow", {}).get("calls", [])


def dispatch_method(data, call, class_name="vgui2::Panel"):
    dispatch = virtual_dispatch(call)
    methods = table_methods(data, class_name)
    if dispatch is not None:
        return sole((m for m in methods if m["index"] == dispatch[1]), class_name + " dispatch")
    return sole((m for m in methods if m["ea"] == call.get("direct")), class_name + " direct entry")


def self_recursion(method):
    return any(
        (dispatch := virtual_dispatch(call)) and dispatch[1] == method["index"] and dispatch[0] != THIS
        for call in method_calls(method)
    )


def proportional_behavior(method):
    flow = method.get("flow", {})
    writes = [
        s
        for s in flow.get("stores", [])
        if isinstance(s["address"], tuple)
        and s["address"][:2] == ("address", THIS)
        and contains_value(s["value"], ("arg", 1))
    ]
    return (
        bool(writes)
        and self_recursion(method)
        and any(
            virtual_dispatch(c) and c["args"][:3] == [THIS, ("const", 0), ("const", 0)] for c in method_calls(method)
        )
    )


def recover_factory_parent(data):
    """Follow the factory's returned Panel, rejecting RequestInfo and inline siblings."""
    candidates = []
    for address in data["roots"]["stage1"]:
        owner = data["functions"][str(address)]
        calls = method_calls(owner)
        for getter in calls:
            if not any(
                contains_value(getter["args"] + getter["stack_args"], ("const", a))
                for a in data["literals"]["PanelPtr"]["addresses"]
            ):
                continue
            panel = ("result", getter["ea"])
            related = [c for c in calls if c["args"] and c["args"][0] == panel]
            positions = [
                c
                for c in related
                if c["direct"]
                and c["args"][:3] in ([panel, ("arg", 2), ("arg", 3)], [panel, ("const", 0), ("const", 0)])
            ]
            if len(positions) != 1:
                continue
            parents = []
            for call in related:
                if not virtual_dispatch(call) or len(call["args"]) < 2 or not _member(call["args"][1]):
                    continue
                body = dispatch_method(data, call)
                conversions = [
                    c for c in method_calls(body) if virtual_dispatch(c) and virtual_dispatch(c)[0] == ("arg", 1)
                ]
                forward = [
                    c
                    for c in method_calls(body)
                    if virtual_dispatch(c)
                    and virtual_dispatch(c)[0] == THIS
                    and any(contains_value(c["args"][1:], ("result", p["ea"])) for p in conversions)
                ]
                if len(forward) == 1 and conversions:
                    parents.append((body, dispatch_method(data, forward[0]), conversions))
            if len(parents) == 1:
                candidates.append((owner, positions[0], *parents[0]))
    full = [c for c in candidates if c[1]["args"][1:3] == [("arg", 2), ("arg", 3)]]
    owner, position, pointer_parent, vpanel_parent, conversions = sole(full or candidates, "BuildGroup factory chain")
    proportional = sole(
        [
            dispatch_method(data, c)
            for c in method_calls(vpanel_parent)
            if virtual_dispatch(c)
            and virtual_dispatch(c)[0] == THIS
            and len(c["args"]) > 1
            and c["args"][1]
            and c["args"][1][0] == "result"
            and proportional_behavior(dispatch_method(data, c))
        ],
        "SetParent -> SetProportional",
    )
    return dict(
        proportional=proportional, getvpanel=dispatch_method(data, conversions[0]), factory=owner, inline=not bool(full)
    )


def itanium_virtual_member_slot(encoded, adjustment):
    """Itanium member-pointer ABI: odd pfn is a vtable byte offset plus one."""
    if not isinstance(encoded, int) or encoded <= 1 or (encoded - 1) % 4 or adjustment != 0:
        raise ValueError("unsupported virtual member pointer or this adjustment")
    return (encoded - 1) // 4


def stack_check_preserves_registers(instructions):
    """Verify the current normal-return and debugger-trap paths of a stack check."""
    if len(instructions) < 3:
        return False
    first, normal = instructions[:2]
    if first["mnemonic"] not in ("jnz", "jne") or normal["mnemonic"] not in ("ret", "retn"):
        return False
    if instructions[-1]["mnemonic"] not in ("ret", "retn") or normal.get("purge", 0) != 0:
        return False
    if first.get("branch") not in {i["ea"] for i in instructions[2:]}:
        return False
    pushes = [i["register"] for i in instructions if i["mnemonic"] == "push" and i.get("register")]
    pops = [i["register"] for i in instructions if i["mnemonic"] == "pop" and i.get("register")]
    saved = {"eax", "edx", "ebx", "esi", "edi"}
    traps = [i.get("trap") for i in instructions if i["mnemonic"] == "int"]
    return (
        traps == [3]
        and pushes == list(reversed(pops))
        and saved <= set(pushes)
        and all(pushes.count(register) == 1 for register in saved)
    )


def map_storage_owned(value, roots, stored_values=(), project_result=lambda value: None, seen=()):
    """Require every possible destination to originate in proven array storage.

    Roots are the array loads recovered from dispatch, not the map object.
    Stored values must have been written to those exact array fields.
    """
    if value is None or value in seen or value[0] == "const":
        return False
    if value in roots or any(value in (stored[1:] if stored[0] == "choice" else (stored,)) for stored in stored_values):
        return True
    seen = (*seen, value)
    if value[0] == "choice":
        return all(map_storage_owned(v, roots, stored_values, project_result, seen) for v in value[1:])
    if value[0] in ("indexed", "address"):
        return map_storage_owned(value[1], roots, stored_values, project_result, seen)
    if value[0] == "result":
        return map_storage_owned(project_result(value), roots, stored_values, project_result, seen)
    return False


def message_dispatch_layout(method):
    """Derive the callback/count fields from the dispatcher's zero-argument arm."""
    flow = method["flow"]
    graph = {int(k): v for k, v in flow["blocks"].items()}

    def reachable(start, stop):
        visited, pending = set(), [start]
        while pending:
            node = pending.pop()
            if node not in visited and node != stop:
                visited.add(node)
                pending.extend(graph.get(node, ()))
        return visited

    def variants(value):
        return value[1:] if isinstance(value, tuple) and value[0] == "choice" else (value,)

    layouts = set()
    record_bases = {}
    for branch in flow["branches"]:
        condition = branch["condition"]
        if not all(isinstance(v, tuple) and v[0] == "load" for v in variants(condition)):
            continue
        if not all(
            any(c["values"] == [condition, ("const", n)] for c in flow["comparisons"])
            or any(
                set(variants(b["condition"])) == {("address", v, -n) for v in variants(condition)}
                for b in flow["branches"]
            )
            for n in (1, 2)
        ):
            continue
        counts = {
            s["field_offset"] for s in flow["loads"] if s["value"] == condition and s.get("field_offset") is not None
        }
        if len(counts) != 1:
            continue
        count = next(iter(counts))
        zero_arm = reachable(branch["zero"], branch["block"]) - reachable(branch["nonzero"], branch["block"])
        used = [c["target"] for c in flow["calls"] if c["block"] in zero_arm and not c["direct"]]
        # Itanium tests the low pfn bit before choosing direct/virtual dispatch.
        used += [
            c["values"][0][1] if c["values"][0] and c["values"][0][0] == "narrow" else c["values"][0]
            for c in flow["comparisons"]
            if c["block"] in zero_arm and c["values"][1] == ("const", 1)
        ]
        for load in flow["loads"]:
            if load["value"] not in used:
                continue
            for value in variants(load["value"]):
                if not isinstance(value, tuple) or value[0] != "load":
                    continue
                for num in variants(condition):
                    if value[1] != num[1]:
                        continue
                    offset = count + value[2] - num[2]
                    expected = {(v[0], v[1], v[2] + offset - count) for v in variants(condition)}
                    if 0 < offset < count and set(variants(load["value"])) == expected:
                        layouts.add((offset, count))
                        record_bases.setdefault((offset, count), set()).update(v[1] for v in variants(condition))
    callback, count = sole(layouts, "message dispatcher callback/count layout")
    return dict(callback=callback, count=count, record_bases=tuple(sorted(record_bases[(callback, count)], key=repr)))


def recover_setfocus_slot(data):
    records = data.get("message_records", [])
    roots = set(data["roots"]["setfocus_all"])
    if not records or {record["root"] for record in records} != roots:
        raise ValueError("SetFocus has no complete Panel-map registration evidence")
    slots = []
    labels = {("const", a) for a in data["literals"]["SetFocus"]["addresses"]}
    for record in records:
        fields = {int(k): v for k, v in record["fields"].items()}
        callback, count = record["layout"]["callback"], record["layout"]["count"]
        if (
            fields.get(0) not in labels
            or record["size"] < count + 4
            or fields.get(count) != ("const", 0)
            or not 0 < callback < count
            or callback % 4
            or count % 4
            or any(fields.get(offset) != ("const", 0) for offset in range(callback + 4, count, 4))
        ):
            raise ValueError("SetFocus record name, parameter count or member-pointer adjustment is invalid")
        pfn = fields.get(callback)
        if not pfn or pfn[0] != "const":
            raise ValueError("SetFocus record has no bound callback")
        if data["platform"] == "linux":
            index = itanium_virtual_member_slot(pfn[1], fields.get(callback + 4, (None, None))[1])
        else:
            calls = method_calls(data["functions"].get(str(pfn[1]), {}))
            if len(calls) != 1 or not (dispatch := virtual_dispatch(calls[0])) or dispatch[0] != THIS:
                raise ValueError("SetFocus callback thunk does not dispatch the original receiver")
            index = dispatch[1]
        if str(index) not in data["tables"]["vgui2::Panel"]["vtable_entries"]:
            raise ValueError("SetFocus record virtual member is absent from the current Panel table")
        slots.append(index)
    return sole(set(slots), "SetFocus registration agreement")


def recover_frame_focus(data, getvpanel):
    frame = sole(
        [m for m in table_methods(data, "vgui2::Frame") if m["ea"] in data["roots"]["stage2"]], "Frame::OnKeyCodeTyped"
    )
    calls = method_calls(frame)
    by_address = {c["ea"]: c for c in calls}
    navs = []
    for call in calls:
        if not virtual_dispatch(call) or virtual_dispatch(call)[0] != THIS:
            continue
        if str(virtual_dispatch(call)[1]) not in data["tables"]["vgui2::EditablePanel"]["vtable_entries"]:
            continue
        entry = data["tables"]["vgui2::EditablePanel"]["vtable_entries"][str(virtual_dispatch(call)[1])]
        if "flow" not in data["functions"].get(str(int(entry, 0)), {}):
            continue
        body = dispatch_method(data, call, "vgui2::EditablePanel")
        offsets = {
            r["value"][2]
            for r in body.get("flow", {}).get("returns", [])
            if isinstance(r["value"], tuple) and r["value"][:2] == ("address", THIS)
        }
        if len(offsets) == 1 and not method_calls(body):
            navs.append((body, next(iter(offsets))))
    nav, offset = sole(
        navs,
        "Frame focus navigation getter "
        + repr(
            [
                (virtual_dispatch(c), dispatch_method(data, c, "vgui2::EditablePanel").get("flow", {}).get("returns"))
                for c in calls
                if virtual_dispatch(c)
                and virtual_dispatch(c)[0] == THIS
                and str(virtual_dispatch(c)[1]) in data["tables"]["vgui2::EditablePanel"]["vtable_entries"]
            ]
        ),
    )
    invalidate = sole(
        [c for c in calls if virtual_dispatch(c) and c["args"][1:3] == [("const", 0), ("const", 1)]],
        "reload InvalidateLayout",
    )
    receiver = virtual_dispatch(invalidate)[0]
    provider = by_address[receiver[1]]
    embedded = by_address[provider["args"][1][1]]

    def getter(call, lookup=by_address):
        dispatch = virtual_dispatch(call)
        if dispatch and dispatch[0] and dispatch[0][0] == "result":
            return lookup.get(dispatch[0][1], {}).get("direct")
        return None

    surface = getter(embedded)
    modifiers = frozenset(range(79, 85))  # Source KeyCode enum: Shift/Ctrl/Alt pairs.
    input_getter = sole(
        {
            getter(c)
            for c in calls
            if virtual_dispatch(c) and len(c["args"]) > 1 and c["args"][1] in {("const", k) for k in modifiers}
        },
        "modifier input interface",
    )
    if surface is None or input_getter is None or surface == input_getter:
        raise ValueError("interface getter provenance is absent or aliased")
    supports = [c for c in calls if getter(c) == surface and c["args"][1:2] == [("const", 3)]]
    panel_returns = [r["value"] for r in getvpanel["flow"]["returns"] if r["value"]]

    def modal_queries(body, lookup):
        own = [c for c in method_calls(body) if virtual_dispatch(c) == (THIS, getvpanel["index"])]
        result = []
        for call in method_calls(body):
            if getter(call, lookup) != input_getter:
                continue
            if any(
                contains_value(comp["values"], ("result", call["ea"]))
                and (
                    any(contains_value(comp["values"], ("result", p["ea"])) for p in own)
                    or any(contains_value(comp["values"], value) for value in panel_returns)
                    or (
                        None in comp["values"]
                        and any(
                            load["value"] in panel_returns and call["ea"] <= load["ea"] <= comp["ea"]
                            for load in body["flow"]["loads"]
                        )
                    )
                )
                for comp in body["flow"]["comparisons"]
            ):
                result.append(call)
        return result

    modal = modal_queries(frame, by_address)
    if not supports:
        # Older Frame::OnKeyCodeTyped has no Escape path. Use the current
        # OnKeyCodePressed command path and OnClose modal-release behavior.
        for body in table_methods(data, "vgui2::Frame"):
            bc = method_calls(body)
            lookup = {c["ea"]: c for c in bc}
            if {"Command", "command", "Cancel"} <= {s[2] for s in body.get("strings", [])}:
                supports.extend(c for c in bc if getter(c, lookup) == surface and c["args"][1:2] == [("const", 3)])
            queries = modal_queries(body, lookup)
            if any(
                virtual_dispatch(c) and virtual_dispatch(c)[0] == THIS and c["args"][1:2] == [("const", 0)] for c in bc
            ):
                modal.extend(c for c in queries if any(p != c and getter(p, lookup) == input_getter for p in bc))
    reloads = [
        c
        for c in calls
        if getter(c) not in (None, input_getter, surface)
        and c["ea"] < invalidate["ea"]
        and receiver != ("result", c["ea"])
    ]
    interfaces = {
        name: virtual_dispatch(sole(items, name))[1]
        for name, items in (
            ("vgui2::ISurface::SupportsFeature(vgui2::ISurface::SurfaceFeature_e)", supports),
            ("vgui2::IInput::GetAppModalSurface()", modal),
            ("vgui2::ISchemeManager::ReloadSchemes()", reloads),
        )
    }
    slot = recover_setfocus_slot(data)
    panel_focus = sole([m for m in table_methods(data, "vgui2::Panel") if m["index"] == slot], "Panel OnSetFocus")
    editable_focus = sole(
        [m for m in table_methods(data, "vgui2::EditablePanel") if m["index"] == slot], "Editable OnSetFocus"
    )
    if not any(virtual_dispatch(c) and virtual_dispatch(c)[0] == THIS for c in method_calls(panel_focus)):
        raise ValueError("Panel OnSetFocus has no current Repaint dispatch")
    if not any(c["direct"] == panel_focus["ea"] for c in method_calls(editable_focus)):
        raise ValueError("Editable OnSetFocus has no current Panel base call")
    current = []
    for call in method_calls(editable_focus):
        dispatch = virtual_dispatch(call)
        call_receiver = dispatch[0] if dispatch else call["args"][0] if call["args"] else None
        if call_receiver != ("address", THIS, offset):
            continue
        if any(
            contains_value(comp["values"], ("result", call["ea"])) and contains_value(comp["values"], THIS)
            for comp in editable_focus["flow"]["comparisons"]
        ):
            current.append(dispatch_method(data, call, "vgui2::FocusNavGroup"))
    focus = sole(current, "current focus compared with this")
    handles = [
        c["args"][0]
        for c in method_calls(focus)
        if c["direct"] and c["args"] and isinstance(c["args"][0], tuple) and c["args"][0][:2] == ("address", THIS)
    ]
    handle = sole(set(v for v in handles if handles.count(v) >= 2), "current VPanelHandle member")
    setters = [
        m
        for m in table_methods(data, "vgui2::FocusNavGroup")
        if any(c["args"][:2] == [handle, ("arg", 1)] and c["direct"] for c in method_calls(m))
    ]
    sole(setters, "SetCurrentFocus handle write")
    return dict(
        nav=nav,
        nav_offset=offset,
        current=focus,
        current_offset=handle[2],
        interfaces=interfaces,
        panel_focus=panel_focus,
        editable_focus=editable_focus,
    )


def own_member_offsets(method):
    offsets = set()

    def visit(value):
        if isinstance(value, (tuple, list)):
            if len(value) == 3 and value[0] in ("load", "address") and value[1] == THIS and isinstance(value[2], int):
                offsets.add(value[2])
            for part in value:
                visit(part)
        elif isinstance(value, dict):
            for part in value.values():
                visit(part)

    visit(method.get("flow", {}))
    return offsets - {0}


def owned_labels(method):
    return {s[2] for s in method.get("strings", [])}


def pure_member_return(method):
    if any(c["ea"] not in method.get("leaf_calls", ()) for c in method_calls(method)):
        return None
    if any(s["address"] is None or s["address"][0] != "stack" for s in method.get("flow", {}).get("stores", [])):
        return None
    values = {r["value"] for r in method.get("flow", {}).get("returns", [])}
    return sole(values, "member getter") if len(values) == 1 and _member(next(iter(values))) else None


def expand_leaf_returns(data, method):
    """Inline proven side-effect-free getters/operators by actual argument values."""
    replacements = {}

    def rewrite(value, arguments=None):
        if not isinstance(value, (tuple, list, dict)):
            return value
        if isinstance(value, dict):
            return {k: rewrite(v, arguments) for k, v in value.items()}
        if isinstance(value, tuple):
            if arguments is not None and value[0] == "arg":
                return arguments[value[1]] if value[1] < len(arguments) else None
            if value[0] == "result" and value[1] in replacements:
                return replacements[value[1]]
            parts = tuple(rewrite(v, arguments) for v in value)
            if parts[0] in ("load", "address") and isinstance(parts[1], tuple) and parts[1][0] == "address":
                return (parts[0], parts[1][1], parts[1][2] + parts[2])
            return parts
        return [rewrite(v, arguments) for v in value]

    for call in method_calls(method):
        helper = data["functions"].get(str(call.get("direct")), {})
        flow = helper.get("flow", {})
        returns = {r["value"] for r in flow.get("returns", [])}
        if (
            len(returns) != 1
            or None in returns
            or method_calls(helper)
            or any(s["address"] is None or s["address"][0] != "stack" for s in flow.get("stores", []))
        ):
            continue
        replacements[call["ea"]] = rewrite(next(iter(returns)), call["args"])
    return dict(method, flow=rewrite(method.get("flow", {})), leaf_calls=set(replacements))


def recover_property_sheet(data, active_page, perform_index):
    """Identify methods independently through messages, containers and argument roles."""
    panel = data["tables"]["vgui2::Panel"]["vtable_entries"]
    methods = [
        expand_leaf_returns(data, m)
        for m in table_methods(data, "vgui2::PropertySheet")
        if str(m["index"]) not in panel or int(panel[str(m["index"])], 0) != m["ea"]
    ]
    found = {}
    for label, positive, negative in (
        ("AddPage", {"tab", "ResetData"}, set()),
        ("ChangeActiveTab", {"PageHide", "PageShow", "PageChanged"}, set()),
        ("ResetAllData", {"ResetData"}, {"tab"}),
        ("ApplyChanges", {"ApplyChanges"}, set()),
    ):
        found[label] = sole(
            [m for m in methods if positive <= owned_labels(m) and not negative & owned_labels(m)],
            "PropertySheet " + label,
        )
    change = found["ChangeActiveTab"]
    written = {
        s["address"][2]
        for s in change["flow"]["stores"]
        if isinstance(s["address"], tuple) and s["address"][:2] == ("address", THIS)
    }
    if active_page not in written:
        raise ValueError("ChangeActiveTab does not write the HasHotkey active page")
    found["GetActivePage"] = sole(
        [m for m in methods if pure_member_return(m) == ("load", THIS, active_page)], "PropertySheet active page getter"
    )
    active_titles = []
    for method in methods:
        for call in method_calls(method):
            if (
                virtual_dispatch(call)
                and _member(call["args"][0])
                and call["args"][0][2] in written - {active_page}
                and call["args"][1:3] == [("arg", 1), ("arg", 2)]
            ):
                active_titles.append((method, call["args"][0][2], virtual_dispatch(call)[1]))
    title, active_tab, text_slot = sole(active_titles, "active tab title output")
    found["GetActiveTabTitle"] = title
    found["GetActiveTab"] = sole(
        [m for m in methods if pure_member_return(m) == ("load", THIS, active_tab)], "active tab getter"
    )
    shared_pages = own_member_offsets(found["ResetAllData"]) & own_member_offsets(found["ApplyChanges"])
    counts = [
        m
        for m in methods
        if (value := pure_member_return(m)) and value[2] in shared_pages and value[2] not in (active_page, active_tab)
    ]
    found["GetNumPages"] = sole(counts, "pages Count getter")
    page_count = pure_member_return(found["GetNumPages"])[2]

    def uses_argument(method, index):
        # Linux and tail-call snapshots include unused following stack words.
        # Only values read/written by the body establish incoming parameters.
        return contains_value(
            {key: value for key, value in method.get("flow", {}).items() if key != "calls"}, ("arg", index)
        )

    def own_dispatches(method):
        return [
            virtual_dispatch(c)[1]
            for c in method_calls(method)
            if virtual_dispatch(c) and virtual_dispatch(c)[0] == THIS
        ]

    active = [
        m
        for m in methods
        if change["index"] in own_dispatches(m)
        and uses_argument(m, 1)
        and page_count in own_member_offsets(m)
        and not owned_labels(m)
        and set(own_dispatches(m)) == {change["index"]}
    ]
    found["SetActivePage"] = sole(active, "pages FindElement -> ChangeActiveTab")
    found["DeletePage"] = sole(
        [
            m
            for m in methods
            if change["index"] in own_dispatches(m)
            and perform_index in own_dispatches(m)
            and uses_argument(m, 1)
            and page_count in own_member_offsets(m)
            and any(virtual_dispatch(c) and virtual_dispatch(c)[0] == ("arg", 1) for c in method_calls(m))
        ],
        "page/tab deletion and relayout",
    )
    widths = []
    for method in methods:
        stores = [
            s
            for s in method["flow"]["stores"]
            if isinstance(s["address"], tuple)
            and s["address"][:2] == ("address", THIS)
            and s["value"] == ("arg", 1)
            and s["width"] == 4
        ]
        if (
            len(stores) == 1
            and stores[0]["address"][2] in own_member_offsets(found["AddPage"])
            and any(
                virtual_dispatch(c) and c["args"][:3] == [THIS, ("const", 0), ("const", 0)]
                for c in method_calls(method)
            )
        ):
            widths.append(method)
    found["SetTabWidth"] = sole(widths, "tab width store and layout invalidation")

    def returns_indexed_page(method):
        values = set()

        def collect(value):
            if isinstance(value, tuple) and value[0] == "choice":
                for part in value[1:]:
                    collect(part)
            else:
                values.add(value)

        for returned in method["flow"]["returns"]:
            collect(returned["value"])
        values.discard(("const", 0))
        # A null bounds-check path is valid, but cannot prove the page getter.
        # The array storage is independently used by both page-message loops;
        # neither the storage/count spacing nor the slot is a layout constant.
        if len(values) != 1:
            return False
        element = next(iter(values))
        return any(
            element == ("load", ("indexed", ("load", THIS, storage), ("arg", 1), 4), 0)
            for storage in shared_pages - {page_count, active_page, active_tab}
        )

    found["GetPage"] = sole(
        [
            m
            for m in methods
            if uses_argument(m, 1)
            and page_count in own_member_offsets(m)
            and not own_dispatches(m)
            and not owned_labels(m)
            and not uses_argument(m, 2)
            and not any(s["address"] and s["address"][0] != "stack" for s in m["flow"]["stores"])
            and returns_indexed_page(m)
        ],
        "indexed page return with bounds",
    )
    found["GetActivePageNum"] = sole(
        [
            m
            for m in methods
            if not uses_argument(m, 1)
            and {active_page, page_count} <= own_member_offsets(m)
            and not own_dispatches(m)
            and not owned_labels(m)
            and not any(s["address"] and s["address"][0] != "stack" for s in m["flow"]["stores"])
        ],
        "pages FindElement(active page)",
    )
    found["GetTabTitle"] = sole(
        [
            m
            for m in methods
            if uses_argument(m, 1)
            and any(
                c["args"][1:3] == [("arg", 2), ("arg", 3)]
                and (virtual_dispatch(c) is None or virtual_dispatch(c)[1] == text_slot)
                for c in method_calls(m)
            )
            and not owned_labels(m)
            and m["ea"] != title["ea"]
        ],
        "indexed tab title output",
    )
    forwarding = {}
    for label, state in (("DisablePage", 0), ("EnablePage", 1)):
        matches = [
            (m, c)
            for m in methods
            for c in method_calls(m)
            if virtual_dispatch(c)
            and c["args"][:3] == [THIS, ("arg", 1), ("const", state)]
            and not owned_labels(m)
            and len(method_calls(m)) == 1
        ]
        method, call = sole(matches, label + " title forwarding")
        found[label] = method
        forwarding[label] = virtual_dispatch(call)
    if forwarding["DisablePage"] != forwarding["EnablePage"]:
        raise ValueError("EnablePage/DisablePage forward to different helpers")
    if len({m["ea"] for m in found.values()}) != len(found):
        raise ValueError("PropertySheet method identities overlap")
    return found
