import unittest

from ida_preprocessor_scripts._pitch_store_predicate import (
    PITCH_FIELD_DISPS,
    is_update_player_pitch_insns,
)


def insn(mnemonic, *writes):
    return {"mnemonic": mnemonic, "memory_writes": list(writes)}


def store(mnemonic, base, disp, size=4):
    return insn(mnemonic, {"kind": "mem", "base": base, "disp": disp, "size": size})


def sse_body(base="eax", div_mnem="divsd"):
    quad = [store("movss", base, disp) for disp in PITCH_FIELD_DISPS]
    return quad + [insn("comiss"), insn("comiss"), insn(div_mnem)]


def x87_body(base="edx"):
    quad = [store("fst", base, disp) for disp in PITCH_FIELD_DISPS[:-1]]
    quad.append(store("fstp", base, PITCH_FIELD_DISPS[-1]))
    return quad + [insn("fucom"), insn("fucomp"), insn("fdiv")]


class UpdatePlayerPitchPredicateTests(unittest.TestCase):
    def test_accepts_sse_store_quad(self):
        self.assertTrue(is_update_player_pitch_insns(sse_body()))

    def test_accepts_x87_store_quad(self):
        self.assertTrue(is_update_player_pitch_insns(x87_body()))

    def test_rejects_integer_mov_pitch_stores(self):
        # Reviewer-reproduced false positive: width alone must not satisfy the quad.
        body = [store("mov", "eax", disp) for disp in PITCH_FIELD_DISPS]
        body += [insn("comiss"), insn("comiss"), insn("divsd")]
        self.assertFalse(is_update_player_pitch_insns(body))

    def test_rejects_integer_division(self):
        # Reviewer-reproduced false positive: 'div' is an integer divide.
        self.assertFalse(is_update_player_pitch_insns(sse_body(div_mnem="div")))
        self.assertFalse(is_update_player_pitch_insns(x87_body()[:-1] + [insn("fidiv")]))

    def test_rejects_mixed_float_and_integer_pitch_stores(self):
        body = sse_body()
        body[2] = store("mov", "eax", PITCH_FIELD_DISPS[2])
        self.assertFalse(is_update_player_pitch_insns(body))

    def test_rejects_duplicate_displacement(self):
        body = sse_body()
        body.append(store("movss", "eax", PITCH_FIELD_DISPS[0]))
        self.assertFalse(is_update_player_pitch_insns(body))

    def test_rejects_multiple_store_bases(self):
        body = sse_body()
        body[1] = store("movss", "ecx", PITCH_FIELD_DISPS[1])
        self.assertFalse(is_update_player_pitch_insns(body))

    def test_rejects_unexpected_comparison_count(self):
        quad = sse_body()[: len(PITCH_FIELD_DISPS)]
        one_comparison = quad + [insn("comiss"), insn("divsd")]
        three_comparisons = sse_body() + [insn("comiss")]
        self.assertFalse(is_update_player_pitch_insns(one_comparison))
        self.assertFalse(is_update_player_pitch_insns(three_comparisons))

    def test_ignores_integer_stores_outside_pitch_fields(self):
        self.assertTrue(is_update_player_pitch_insns(sse_body() + [store("mov", "eax", 0x40)]))


if __name__ == "__main__":
    unittest.main()
