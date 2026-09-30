"""RichText character-filter identity over decoded current-binary facts."""

THIS = ("arg", 0)
TEXT = ("arg", 1)
CR = ("const", ord("\r"))
# RichText.cpp: _recalculateBreaksIndex = m_LineBreaks.Count() - 2.
# This counts line breaks, not bytes or wchar_t elements.
LINEBREAK_RECALC_BACKTRACK = 2
FLAGS_PRESERVED = {"mov", "movzx", "movsx", "lea", "push", "pop", "nop"}


def pointer_increment(mnemonic, operands, width):
    if len(operands) != 2 or operands[0][0] != "reg" or operands[0][2:] != (4,):
        return False
    destination, source = operands
    if mnemonic == "add":
        return source == ("imm", width)
    return mnemonic == "lea" and source[:5] == ("mem", destination[1], width, None, 1)


def unnarrow(value):
    while isinstance(value, tuple) and value[0] == "narrow":
        value = value[1]
    return value


def member_address(value):
    return isinstance(value, tuple) and len(value) == 3 and value[:2] == ("address", THIS) and value[2] > 0


def receiver(call):
    return call["args"][0] if call["args"] else None


def virtual_call(call):
    target = call["target"]
    return (
        isinstance(target, tuple)
        and len(target) == 3
        and target[:2] == ("load", ("load", THIS, 0))
        and target[2] >= 0
        and target[2] % 4 == 0
        and receiver(call) == THIS
    )


def reachable_until(graph, start, stop):
    seen, pending = set(), [start]
    while pending:
        current = pending.pop()
        if current == stop or current in seen:
            continue
        seen.add(current)
        pending.extend(graph.get(current, []))
    return seen


def character_guard(flow, blocks, wide):
    """Prove one CR comparison controls the line-break update and repaint.

    The source character must be the scalar argument or the first character
    loaded through the string argument. Width/loop checks belong to the adapter.
    The comparison and branch must share a block with no intervening flags write.
    Work-only reachability excludes the next guard iteration and common epilogue.
    """
    graph = {b["start"]: b["succs"] for b in blocks}
    by_block = {b["start"]: b for b in blocks}
    calls = {call["ea"]: call for call in flow["calls"]}
    instruction_block = {i["ea"]: b["start"] for b in blocks for i in b["insns"]}
    expected = ("load", TEXT, 0) if wide else TEXT
    matches = []
    for comparison in flow["comparisons"]:
        left, right = comparison["values"]
        if unnarrow(left) != expected or right != CR:
            continue
        block = by_block[comparison["block"]]
        tail = [i for i in block["insns"] if i["ea"] > comparison["ea"]]
        branch = None
        for item in tail:
            if item["mnem"] in ("jz", "je", "jnz", "jne"):
                branch = item
                break
            if item["mnem"] not in FLAGS_PRESERVED:
                break
        if branch is None or len(block["succs"]) != 2 or branch.get("branch") not in block["succs"]:
            continue
        target = branch["branch"]
        fallthrough = next(s for s in block["succs"] if s != target)
        skip, work = (target, fallthrough) if branch["mnem"] in ("jz", "je") else (fallthrough, target)
        skip_blocks = reachable_until(graph, skip, block["start"])
        work_only = reachable_until(graph, work, block["start"]) - skip_blocks
        updates = []
        for store in flow["stores"]:
            value = store["value"]
            if (
                instruction_block.get(store["ea"]) not in work_only
                or not member_address(store["address"])
                or store["width"] != 4
                or not isinstance(value, tuple)
                or len(value) != 3
                or value[0] != "address"
                or value[2] != -LINEBREAK_RECALC_BACKTRACK
            ):
                continue
            count = value[1]
            # Optimized Count() reads the member directly; debug builds call
            # the vector getter on the corresponding subobject.
            if isinstance(count, tuple) and len(count) == 3 and count[:2] == ("load", THIS) and count[2] > 0:
                updates.append(store)
            elif (
                isinstance(count, tuple)
                and count[0] == "result"
                and member_address(receiver(calls.get(count[1], {"args": []})))
            ):
                updates.append(store)
        repaints = [call for call in calls.values() if call["block"] in work_only and virtual_call(call)]
        if len(updates) == 1 and repaints:
            matches.append(
                dict(
                    compare=comparison["ea"],
                    branch=branch["ea"],
                    mnemonic=branch["mnem"],
                    skip=skip,
                    work=work,
                    update=updates[0]["ea"],
                )
            )
    if len(matches) != 1:
        raise ValueError("expected one proven CR character guard, got %r" % matches)
    return matches[0]
