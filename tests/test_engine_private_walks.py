"""Behavioral regression fixtures for private-symbol instruction walks."""

import runpy
import sys
import unittest
from pathlib import Path
from types import SimpleNamespace as NS
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
REG, MEM, DISPL, PHRASE = 1, 2, 4, 3
REGISTERS = ("eax", "ecx", "edx", "ebx", "esp", "ebp", "esi", "edi")


def walk(name):
    return runpy.run_path(str(ROOT / "ida_preprocessor_scripts" / name))["WALK"]


class OverviewWalkTests(unittest.TestCase):
    def locate(self, sizes, calls):
        sites = [0x1010 + i * 0x10 for i in range(len(sizes))]
        targets = {site - 1: 0x2000 + i * 0x1000 for i, site in enumerate(sites)}
        blocks = [NS(start_ea=site - 1, end_ea=site + 1, succs=lambda: []) for site in sites]
        functions = {ea: NS(start_ea=ea, end_ea=ea + size) for ea, size in zip(targets.values(), sizes)}
        ns = {
            "values": {"setdev": "0x9000", "hops": 6, "max_size": 0x80, "max_calls": 1},
            "callers": lambda ea: {(0x1000, site) for site in sites},
            "scan": lambda ea: [{"mnem": "call"}] * calls.get(ea, 0),
            "ida_funcs": NS(get_func=lambda ea: functions.get(ea, NS(start_ea=ea, end_ea=ea + 0x100))),
            "idautils": NS(Heads=lambda start, end: range(start, end)),
            "idc": NS(
                print_insn_mnem=lambda ea: "call",
                get_operand_type=lambda ea, n: 7,
                get_operand_value=lambda ea, n: targets[ea],
            ),
            "idaapi": NS(o_near=7),
            "resolve_elf_plt": lambda ea: ea,
        }
        with patch.dict(sys.modules, {"ida_gdl": NS(FlowChart=lambda owner: blocks)}):
            exec(walk("find-CL_IsDevOverviewMode.py"), ns)
        return ns["result"]

    def test_rejects_oversized_candidate(self):
        self.assertIn("error", self.locate([0x200], {}))

    def test_rejects_excess_calls(self):
        self.assertIn("error", self.locate([0x40], {0x2000: 2}))

    def test_rejected_candidate_does_not_make_valid_candidate_ambiguous(self):
        self.assertEqual(0x2000, self.locate([0x40, 0x200], {})["func_ea"])

    def test_rejects_two_valid_candidates(self):
        self.assertIn("error", self.locate([0x40, 0x40], {}))


def operand(kind, register="", addr=0):
    return NS(type=kind, reg=register, addr=addr)


def instruction(mnem, destination, source, raw=b"", written=()):
    return {
        "mnem": mnem,
        "written": set(written),
        "insn": NS(ops=[destination, source]),
        "raw": raw,
        "len": len(raw),
        "disasm": mnem,
        "disp": 0,
    }


class TextureWalkTests(unittest.TestCase):
    def locate(self, second_raw=b"\x8b\x56\x08", middle=(), first_raw=b"\x8b\x46\x04", split=False, entries=None):
        entries = (
            entries
            if entries is not None
            else [
                instruction("mov", operand(REG, "eax"), operand(DISPL, "esi", 4), first_raw),
                *middle,
                instruction("mov", operand(MEM, addr=0x4000), operand(REG, "eax"), written=[0x4000]),
                instruction("mov", operand(REG, "edx"), operand(DISPL, "esi", 8), second_raw),
                instruction("mov", operand(MEM, addr=0x5000), operand(REG, "edx"), written=[0x5000]),
            ]
        )
        for i, entry in enumerate(entries):
            entry["ea"] = 0x1000 + i * 0x10
        raw_by_ea = {entry["ea"]: entry["raw"] for entry in entries}
        blocks = (
            [NS(start_ea=0x1000, end_ea=0x1010), NS(start_ea=0x1010, end_ea=0x1100)]
            if split
            else [NS(start_ea=0x1000, end_ea=0x1100)]
        )
        api = NS(o_reg=REG, o_mem=MEM, o_displ=DISPL, o_phrase=PHRASE, o_void=0)
        ns = {
            "values": {"owner": "0x1000", "window": 6},
            "scan": lambda ea: entries,
            "reg4": lambda op: op.reg,
            "signed32": lambda n: n,
            "access": lambda entry, gv: {"gv_ea": hex(gv)},
            "changed_operand": lambda insn, index: index == 0,
            "ida_funcs": NS(get_func=lambda ea: NS(start_ea=ea)),
            "ida_bytes": NS(get_bytes=lambda ea, size: raw_by_ea[ea]),
            "ida_idp": NS(get_reg_name=lambda reg, size: REGISTERS[reg]),
        }
        with patch.dict(sys.modules, {"idaapi": api, "ida_gdl": NS(FlowChart=lambda owner: blocks)}):
            exec(walk("find-Draw_TextureMode_f-globals.py"), ns)
        return ns["result"]

    def test_accepts_shared_base(self):
        self.assertEqual("0x4000", self.locate()["gl_filter_min"]["gv_ea"])

    def test_rejects_different_base(self):
        self.assertIn("error", self.locate(second_raw=b"\x8b\x57\x08"))

    def test_rejects_different_index(self):
        self.assertIn("error", self.locate(first_raw=b"\x8b\x44\x8e\x04", second_raw=b"\x8b\x54\x96\x08"))

    def test_rejects_different_scale(self):
        self.assertIn("error", self.locate(first_raw=b"\x8b\x44\x8e\x04", second_raw=b"\x8b\x54\xce\x08"))

    def test_accepts_shared_indexed_address(self):
        self.assertEqual(
            "0x5000",
            self.locate(first_raw=b"\x8b\x44\x8e\x04", second_raw=b"\x8b\x54\x8e\x08")["gl_filter_max"]["gv_ea"],
        )

    def test_rejects_value_clobber(self):
        change = instruction("xor", operand(REG, "eax"), operand(REG, "eax"))
        self.assertIn("error", self.locate(middle=[change]))

    def test_rejects_address_clobber(self):
        change = instruction("add", operand(REG, "esi"), operand(REG, "edi"))
        self.assertIn("error", self.locate(middle=[change]))

    def test_rejects_cross_block_definition(self):
        self.assertIn("error", self.locate(split=True))

    def test_accepts_equivalent_reloaded_stack_index(self):
        self.assertEqual("0x4000", self.locate(entries=self.stack_index_entries())["gl_filter_min"]["gv_ea"])

    def test_rejects_changed_stack_index(self):
        entries = self.stack_index_entries()
        entries.insert(4, instruction("mov", operand(DISPL, "ebp", -4), operand(REG, "eax")))
        self.assertIn("error", self.locate(entries=entries))

    def test_rejects_call_clobber(self):
        change = instruction("call", operand(7), operand(0))
        self.assertIn("error", self.locate(middle=[change]))

    def test_rejects_implicit_multiply_clobber(self):
        change = instruction("imul", operand(REG, "edi"), operand(0))
        self.assertIn("error", self.locate(middle=[change]))

    @staticmethod
    def stack_index_entries():
        return [
            instruction("mov", operand(REG, "edx"), operand(DISPL, "ebp", -4), b"\x8b\x55\xfc"),
            instruction("imul", operand(REG, "edx"), operand(5), b"\x6b\xd2\x0c"),
            instruction("mov", operand(REG, "eax"), operand(DISPL, "edx", 0x6004), b"\x8b\x82\x04\x60\x00\x00"),
            instruction("mov", operand(MEM, addr=0x4000), operand(REG, "eax"), written=[0x4000]),
            instruction("mov", operand(REG, "ecx"), operand(DISPL, "ebp", -4), b"\x8b\x4d\xfc"),
            instruction("imul", operand(REG, "ecx"), operand(5), b"\x6b\xc9\x0c"),
            instruction("mov", operand(REG, "edx"), operand(DISPL, "ecx", 0x6008), b"\x8b\x91\x08\x60\x00\x00"),
            instruction("mov", operand(MEM, addr=0x5000), operand(REG, "edx"), written=[0x5000]),
        ]


class DecalInitWalkTests(unittest.TestCase):
    """Run the complete decal locator against controlled signature and instruction inputs."""

    def locate(self, hits=None, stores=(0x6000,), cache_form="absolute"):
        finder = runpy.run_path(str(ROOT / "ida_preprocessor_scripts/find-R_DecalInit.py"))
        signatures = finder["SIGNATURE_ORDER"]
        hits = ([0x1020], [0x1000]) if hits is None else hits
        matches = {bytes.fromhex(signature): addresses for (_, signature), addresses in zip(signatures, hits)}
        self.searched = []

        def find_bytes(pattern, start, end):
            self.searched.append(pattern)
            return next((ea for ea in matches[pattern] if start <= ea < end), 0xFFFFFFFF)

        def get_func(ea):
            for start in (0x1000, 0x2000, 0x3000):
                if start <= ea < start + 0x100:
                    return NS(start_ea=start, end_ea=start + 0x100)
            return None

        def op(kind, *, addr=0, value=0, reg=None):
            return NS(type=kind, addr=addr, value=value, reg=reg)

        entries = [
            ("push", NS(ops=[op(5, value=0x5000)], size=5, displacement=1)),
            ("call", NS(ops=[op(7, addr=0x3000)], size=5, displacement=1)),
        ]
        for address in stores:
            if cache_form in ("register", "pic"):
                source = (
                    op(5, value=address) if cache_form == "register" else op(DISPL, reg="ebx", addr=address - 0x4000)
                )
                entries.append(
                    (
                        "mov" if cache_form == "register" else "lea",
                        NS(ops=[op(REG, reg="eax"), source], size=6, displacement=2),
                    )
                )
                destination = op(PHRASE, reg="eax")
            elif cache_form == "indexed":
                destination = op(DISPL, reg="ecx", addr=address)
            else:
                destination = op(MEM, addr=address)
            entries.append(("mov", NS(ops=[destination, op(5, value=0xFFFFFFFF)], size=10, displacement=2)))
        instructions = {0x1000 + index * 0x10: entry for index, entry in enumerate(entries)}
        ns = {
            "values": {"signatures": signatures, "pool_lookback": finder["POOL_LOOKBACK"]},
            "idaapi": NS(
                o_void=0,
                o_reg=REG,
                o_mem=MEM,
                o_displ=DISPL,
                o_phrase=PHRASE,
                o_imm=5,
                BADADDR=0xFFFFFFFF,
                inf_get_min_ea=lambda: 0,
                inf_get_max_ea=lambda: 0x10000,
            ),
            "ida_bytes": NS(find_bytes=find_bytes),
            "ida_funcs": NS(get_func=get_func),
            "idautils": NS(
                FuncItems=lambda start: list(instructions), DecodeInstruction=lambda ea: instructions[ea][1]
            ),
            "idc": NS(
                print_insn_mnem=lambda ea: instructions[ea][0],
                generate_disasm_line=lambda ea, flags: instructions[ea][0],
            ),
            "got_anchor": lambda start: (0x4000, "ebx") if cache_form == "pic" else (None, None),
            "is_writable_data": lambda ea: 0x5000 <= ea < 0x8000,
            "is_got": lambda ea: False,
            "reg4": lambda operand: operand.reg,
            "signed32": lambda value: value,
            "disp32_offset": lambda insn: insn.displacement,
            "direct_calls": lambda start: {0x3000: [0x1010]},
        }
        exec(finder["LOCATE_BODY"], ns)
        return ns["result"]

    def test_accepts_unique_first_signature_and_supported_cache_operands(self):
        for form in ("absolute", "indexed", "register", "pic"):
            with self.subTest(form=form):
                result = self.locate(cache_form=form)
                self.assertNotIn("error", result)
                self.assertEqual("loop_store", result["signature"])
                self.assertEqual("0x5000", result["gDecalPool"]["gv_ea"])
                self.assertEqual("0x6000", result["gDecalCache"]["gv_ea"])
                self.assertEqual(1, len(set(self.searched)))

    def test_falls_back_only_when_first_signature_has_no_hits(self):
        result = self.locate(hits=([], [0x1000]))
        self.assertNotIn("error", result)
        self.assertEqual("pool_memset", result["signature"])

    def test_rejects_ambiguous_first_signature_without_searching_fallback(self):
        self.assertIn("error", self.locate(hits=([0x1020, 0x2020], [0x1000])))
        self.assertEqual(1, len(set(self.searched)))

    def test_rejects_ownerless_first_signature_without_searching_fallback(self):
        self.assertIn("error", self.locate(hits=([0x9000], [0x1000])))
        self.assertEqual(1, len(set(self.searched)))

    def test_accepts_multiple_hits_in_one_owner(self):
        self.assertNotIn("error", self.locate(hits=([0x1020, 0x1030], [])))

    def test_rejects_absent_or_ambiguous_fallback(self):
        for hits in (([], []), ([], [0x1000, 0x2000])):
            with self.subTest(hits=hits):
                self.assertIn("error", self.locate(hits=hits))

    def test_rejects_multiple_qualifying_stores_even_for_the_same_global(self):
        for form in ("absolute", "indexed", "register", "pic"):
            for stores in ((0x6000, 0x7000), (0x6000, 0x6000)):
                with self.subTest(form=form, stores=stores):
                    result = self.locate(stores=stores, cache_form=form)
                    self.assertIn("error", result)
                    self.assertNotIn("gDecalCache", result)

    def test_rejects_missing_cache_store(self):
        self.assertIn("error", self.locate(stores=()))


class TextureIdentityTests(unittest.TestCase):
    def test_family_names(self):
        from ida_preprocessor_scripts._engine_texture_mode_common import texture_mode_name

        for game, expected in [
            ("hl-6153", "Draw_TextureMode_f"),
            ("hl-8684", "gl_texturemode_hook_callback"),
            ("hl-10210", "gl_texturemode_hook_callback"),
            ("svencoop-8948", "GL_TextureMode_f"),
            ("svencoop-10257", "GL_TextureMode_f"),
        ]:
            with self.subTest(game=game):
                self.assertEqual(expected, texture_mode_name(ROOT / "bin_artifacts" / game / "engine"))


if __name__ == "__main__":
    unittest.main()
