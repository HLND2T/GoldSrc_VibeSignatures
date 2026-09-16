"""Semantic predicate for the Sven client UpdatePlayerPitch store quad.

The source is injected verbatim into the remote layout walk by
find-UpdatePlayerPitch.py and imported by the synthetic-fixture regression
tests, so this module must stay pure Python with no IDA imports.
"""

PITCH_FIELD_DISPS = (0xB54, 0x2CC, 0x178, 0xB28)
# Only SSE scalar stores and x87 FST/FSTP carry float semantics; an integer
# mov to a pitch-field displacement must not satisfy the store quad.
FLOAT_STORES = ("movss", "movsd", "fst", "fstp")
COMPARISONS = ("comiss", "ucomiss", "fcom", "fcomp", "fucom", "fucomp", "fucomi", "fucomip", "fcomip", "fcompp")
# 'div' is the integer divide and 'fidiv' divides by an integer memory
# operand; neither proves the float division of the clamp arithmetic.
FLOAT_DIVISIONS = ("divss", "divsd", "fdiv", "fdivp", "fdivr")


def is_update_player_pitch_insns(insns):
    """Accept only the clamp-then-store quad over the four cl_entity_t pitch fields."""
    pitch_stores = [
        (insn, w) for insn in insns for w in insn.get("memory_writes", ()) if w.get("disp") in PITCH_FIELD_DISPS
    ]
    if any(insn["mnemonic"] not in FLOAT_STORES or w["size"] not in (4, 8) for insn, w in pitch_stores):
        return False
    if len(pitch_stores) != len(PITCH_FIELD_DISPS):
        return False
    if {w["disp"] for _, w in pitch_stores} != set(PITCH_FIELD_DISPS):
        return False
    if len({w["base"] for _, w in pitch_stores}) != 1:
        return False
    comparisons = sum(1 for insn in insns if insn["mnemonic"] in COMPARISONS)
    divisions = sum(1 for insn in insns if insn["mnemonic"] in FLOAT_DIVISIONS)
    return comparisons == 2 and divisions == 1
