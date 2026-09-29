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
