"""Relations between native sparse-list accessors, independent of object layout."""

THIS = ("arg", 0)
ROW = ("arg", 1)


def sole(values, description):
    values = list(values)
    if len(values) != 1:
        raise ValueError(f"{description}: expected one candidate, got {len(values)}")
    return values[0]


def member(value):
    return isinstance(value, tuple) and len(value) == 3 and value[:2] == ("load", THIS) and value[2] > 0


def nodes(value):
    if isinstance(value, tuple):
        yield value
        for child in value[1:]:
            yield from nodes(child)


def substitute(value, old, new):
    if value == old:
        return new
    return tuple(substitute(v, old, new) for v in value) if isinstance(value, tuple) else value


def normalized(value):
    """Compare equivalent LEA/ADD/SHL expressions without guessing node size."""
    if not isinstance(value, tuple):
        return value
    if value[0] != "indexed":
        return tuple(normalized(v) for v in value)
    terms = {}

    def collect(expression, scale):
        if expression is None:
            terms[None] = terms.get(None, 0) + scale
        elif expression[0] == "indexed":
            collect(expression[1], scale)
            collect(expression[2], scale * expression[3])
        elif expression != ("const", 0):
            key = normalized(expression)
            terms[key] = terms.get(key, 0) + scale

    collect(value, 1)
    return ("sum", *sorted(((key, scale) for key, scale in terms.items() if scale), key=repr))


def returned_pointer(flow):
    """Accept a single non-null pointer expression and an explicit null arm."""

    def alternatives(value):
        if value and value[0] == "choice":
            for item in value[1:]:
                yield from alternatives(item)
        else:
            yield value

    returns = {v for r in flow["returns"] for v in alternatives(r["value"])}
    if ("const", 0) not in returns:
        return None
    values = returns - {("const", 0)}
    if len(values) != 1:
        return None
    value = next(iter(values))
    return value if value and value[0] == "load" and ROW in set(nodes(value)) else None


def sparse_accessors(methods):
    """Prove row -> ID -> panel agrees with the item-ID panel getter.

    The other getter must access the other pointer in the same DATAITEM. We do
    not assume linked-list node size, member offsets, or virtual slot order.
    The recovered row vector fields let consumers read an ID then call native
    validity-checking getters, including after deletions leave sparse IDs.
    """
    candidates = []
    for renderer in methods:
        result = returned_pointer(renderer["flow"])
        if result is None:
            continue
        row_ids = {
            n
            for n in nodes(result)
            if len(n) == 3
            and n[0] == "load"
            and n[2] == 0
            and isinstance(n[1], tuple)
            and len(n[1]) == 4
            and n[1][0] == "indexed"
            and member(n[1][1])
            and n[1][2:] == (ROW, 4)
        }
        for row_id in row_ids:
            for panel in methods:
                p = returned_pointer(panel["flow"])
                if p is None or normalized(substitute(p, ROW, row_id)) != normalized(result):
                    continue
                labels = [
                    m
                    for m in methods
                    if (v := returned_pointer(m["flow"])) is not None and v[:-1] == p[:-1] and v[-1] != p[-1]
                ]
                if len(labels) != 1:
                    continue
                count_fields = {
                    value
                    for comparison in renderer["flow"]["comparisons"]
                    for value in comparison["values"]
                    if member(value) and ROW in comparison["values"]
                }
                # Debug builds also test allocation capacity in assertion
                # paths. The collector proves which bound returns nullptr.
                if not count_fields:
                    continue
                candidates.append(
                    dict(renderer=renderer, panel=panel, label=labels[0], row_id=row_id, counts=count_fields)
                )
    return sole(candidates, "native sparse-list accessor relation")
