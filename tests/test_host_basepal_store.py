"""Synthetic dataflow checks for the host_basepal Hunk_AllocName store."""

import unittest

from ida_preprocessor_scripts.host_basepal_store import locate_palette_hunk_store

HUNK = 0x2000
NAME = 0x5000
GV = 0x4000
UNRELATED = 0x4100


def insn(mnem, ops=(), *, sp=0, call_target=None, written=(), ea=0, disp=0, length=5, disasm=""):
    return {
        "mnem": mnem,
        "ops": list(ops),
        "sp": sp,
        "call_target": call_target,
        "written": set(written),
        "ea": ea,
        "disp": disp,
        "len": length,
        "disasm": disasm or mnem,
    }


def locate(code, hunk=HUNK, names=(NAME,)):
    return locate_palette_hunk_store(code, hunk, 0x800, names)


def windows_alloc_store(*, callee=HUNK, store_src=("reg", "eax"), store_imm=None):
    store_ops = [("mem", GV), store_src if store_imm is None else ("imm", store_imm)]
    written = (GV,) if store_src[0] == "reg" or store_imm is not None else ()
    return [
        insn("push", [("imm", NAME)], sp=0, ea=0x10),
        insn("push", [("imm", 0x800)], sp=-4, ea=0x15),
        insn("call", sp=-8, call_target=callee, ea=0x1A),
        insn("add", [("reg", "esp"), ("imm", 8)], sp=-8, ea=0x1F),
        insn("mov", store_ops, sp=0, written=written, ea=0x22, disp=1),
    ]


class HostBasepalStoreTests(unittest.TestCase):
    def test_accepts_cdecl_size_and_name_then_eax_store(self):
        result = locate(windows_alloc_store())
        self.assertNotIn("error", result)
        self.assertEqual("0x4000", result["gv"]["gv_ea"])
        self.assertEqual("0x22", result["gv"]["insn_ea"])

    def test_accepts_linux_reserved_stack_and_register_copy(self):
        code = [
            insn("mov", [("reg", "ebp"), ("imm", NAME)], sp=-16, ea=0x10),
            insn("mov", [("stack", -12), ("reg", "ebp")], sp=-16, ea=0x16),
            insn("mov", [("stack", -16), ("imm", 0x800)], sp=-16, ea=0x19),
            insn("call", sp=-16, call_target=HUNK, ea=0x20),
            insn("mov", [("reg", "esi"), ("reg", "eax")], sp=-16, ea=0x25),
            insn("mov", [("mem", GV), ("reg", "esi")], sp=-16, written=(GV,), ea=0x28, disp=2),
        ]
        result = locate(code)
        self.assertEqual("0x4000", result["gv"]["gv_ea"])
        self.assertEqual("0x28", result["gv"]["insn_ea"])

    def test_rejects_unrelated_call_and_immediate_store(self):
        code = [
            insn("push", [("imm", 0x800)], sp=0, ea=0x10),
            insn("call", sp=-4, call_target=0x3000, ea=0x15),
            insn("mov", [("mem", UNRELATED), ("imm", 0)], sp=-4, written=(UNRELATED,), ea=0x1A, disp=1),
        ]
        self.assertIn("error", locate(code))

    def test_rejects_matching_args_when_store_is_immediate_zero(self):
        self.assertIn("error", locate(windows_alloc_store(store_imm=0)))

    def test_rejects_wrong_callee(self):
        self.assertIn("error", locate(windows_alloc_store(callee=0x3000)))

    def test_rejects_eax_clobber_before_store(self):
        code = [
            insn("push", [("imm", NAME)], sp=0, ea=0x10),
            insn("push", [("imm", 0x800)], sp=-4, ea=0x15),
            insn("call", sp=-8, call_target=HUNK, ea=0x1A),
            insn("xor", [("reg", "eax"), ("reg", "eax")], sp=-8, ea=0x1F),
            insn("mov", [("mem", GV), ("reg", "eax")], sp=-8, written=(GV,), ea=0x22, disp=1),
        ]
        self.assertIn("error", locate(code))

    def test_accepts_svengine_linux_store_after_scratch_register_moves(self):
        sp = -0x103C
        code = [
            insn("mov", [("reg", "ebp"), ("imm", NAME)], sp=sp, ea=0x10),
            insn("test", [("reg", "eax"), ("reg", "eax")], sp=sp, ea=0x14),
            insn("jz", [("imm", 0x100)], sp=sp, ea=0x16),
            insn("mov", [("stack", sp + 4), ("reg", "ebp")], sp=sp, ea=0x18),
            insn("mov", [("stack", sp), ("imm", 0x800)], sp=sp, ea=0x19),
            insn("call", sp=sp, call_target=HUNK, ea=0x20),
            insn("mov", [("reg", "ecx"), ("reg", "edi")], sp=sp, ea=0x25),
            insn("mov", [("reg", "edx"), ("imm", 2)], sp=sp, ea=0x28),
            insn("mov", [("unknown", None), ("reg", "eax")], sp=sp, written=(GV,), ea=0x2E, disp=2),
        ]
        result = locate(code)
        self.assertEqual("0x4000", result["gv"]["gv_ea"])
        self.assertEqual("0x2e", result["gv"]["insn_ea"])

    def test_rejects_jcc_that_skips_palette_name_assignment(self):
        sp = -0x103C
        code = [
            insn("jz", [("imm", 0x18)], sp=sp, ea=0x10),
            insn("mov", [("reg", "ebp"), ("imm", NAME)], sp=sp, ea=0x14),
            insn("mov", [("stack", sp + 4), ("reg", "ebp")], sp=sp, ea=0x18),
            insn("mov", [("stack", sp), ("imm", 0x800)], sp=sp, ea=0x19),
            insn("call", sp=sp, call_target=HUNK, ea=0x20),
            insn("mov", [("unknown", None), ("reg", "eax")], sp=sp, written=(GV,), ea=0x2E, disp=2),
        ]
        self.assertIn("error", locate(code))

    def test_rejects_implicit_eax_write_before_store(self):
        code = [
            insn("push", [("imm", NAME)], sp=0, ea=0x10),
            insn("push", [("imm", 0x800)], sp=-4, ea=0x15),
            insn("call", sp=-8, call_target=HUNK, ea=0x1A),
            insn("mul", [("reg", "ecx")], sp=-8, ea=0x1F),
            insn("mov", [("mem", GV), ("reg", "eax")], sp=-8, written=(GV,), ea=0x22, disp=1),
        ]
        self.assertIn("error", locate(code))

    def test_rejects_missing_palette_name_argument(self):
        code = [
            insn("push", [("imm", 0x800)], sp=0, ea=0x10),
            insn("call", sp=-4, call_target=HUNK, ea=0x15),
            insn("mov", [("mem", GV), ("reg", "eax")], sp=-4, written=(GV,), ea=0x1A, disp=1),
        ]
        self.assertIn("error", locate(code))
