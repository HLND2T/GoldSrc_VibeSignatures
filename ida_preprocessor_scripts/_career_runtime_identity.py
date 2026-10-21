"""Validate pointer paths recovered from the actual Career path consumers."""


def pointer_chain(value, depth):
    """Return the absolute pointer storage and byte offsets, rejecting guesses."""
    offsets = []
    for _ in range(depth):
        if not value or value[0] != "load" or len(value) != 3:
            raise ValueError("Incomplete pointer path")
        offset = value[2]
        if type(offset) is not int or offset < 0 or offset % 4:
            raise ValueError("Unaligned pointer field")
        offsets.append(offset)
        value = value[1]
    if not value or value[0] != "const" or len(value) != 2 or value[1] <= 0 or offsets[-1] != 0:
        raise ValueError("Pointer path does not start at absolute storage")
    return value[1], list(reversed(offsets[:-1]))


def common_pointer_chain(values, depth):
    paths = [pointer_chain(value, depth) for value in values]
    if not paths or any(path != paths[0] for path in paths):
        raise ValueError("Career consumers disagree about pointer ownership")
    return paths[0]


def byte_member_offsets(value, receiver, byte_offsets):
    """Match comparison provenance only where a byte-width access was decoded."""
    if not isinstance(value, tuple):
        return set()
    if len(value) == 3 and value[:2] == ("load", receiver) and value[2] in byte_offsets:
        return {value[2]}
    return set().union(*(byte_member_offsets(child, receiver, byte_offsets) for child in value))
