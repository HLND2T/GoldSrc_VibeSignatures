"""Behavioral regression fixtures for private-symbol instruction walks."""

import contextlib
import io
import json
import runpy
import sys
import unittest
from pathlib import Path
from types import SimpleNamespace as NS
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
REG, MEM, DISPL, PHRASE = 1, 2, 4, 3
IMM = 5
NEAR = 7
REGISTERS = ("eax", "ecx", "edx", "ebx", "esp", "ebp", "esi", "edi")
SETUP_TRIPLE_MARKER = "__R124_SETUP_TRIPLE__"


def walk(name):
    return runpy.run_path(str(ROOT / "ida_preprocessor_scripts" / name))["WALK"]


class SysInitGameWalkTests(unittest.TestCase):
    """Exercise the complete finder with decoded operands and real flow recovery."""

    def locate(self, *, address="[eax]", displacement=0, width=4, load_width=4, branch=None, pic=False):
        entries = []
        sp = 0

        def op(kind, *, reg="", addr=0, value=0, dtype=4, text=""):
            return NS(type=kind, reg=reg, addr=addr, value=value, dtype=dtype, text=text)

        def emit(mnem, *ops, targets=()):
            nonlocal sp
            ea = 0x1000 + len(entries) * 8
            entries.append(
                dict(
                    ea=ea,
                    mnem=mnem,
                    insn=NS(ops=[*ops, op(0)]),
                    targets=set(targets),
                    written=set(),
                    disp=1 if targets else 0,
                    len=8,
                    disasm=mnem,
                    sp=sp,
                )
            )
            if mnem == "push":
                sp -= 4
            return ea

        if branch:
            emit("jz", op(7))
        emit(
            "mov",
            op(REG, reg="eax", dtype=load_width),
            op(DISPL if pic else MEM, reg="ebx", addr=0x4000, dtype=load_width, text="[ebx+4000h]"),
            targets=(0x4000,),
        )
        use = emit(
            "mov",
            op(REG, reg="eax"),
            op(DISPL if displacement else PHRASE, reg="eax", addr=displacement, dtype=width, text=address),
        )
        for gv in (0x6000, 0x5000):
            if pic:
                emit("lea", op(REG, reg="edx"), op(DISPL, reg="ebx", addr=gv, text=f"[ebx+{gv:x}h]"), targets=(gv,))
                emit("push", op(REG, reg="edx"))
            else:
                emit("push", op(5, value=gv), targets=(gv,))
        emit("push", op(REG, reg="eax"))
        emit("call", op(7, value=0x7000))
        end = emit("ret")
        by_ea = {e["ea"]: e for e in entries}
        edges = {e["ea"]: [entries[i + 1]["ea"]] if i + 1 < len(entries) else [] for i, e in enumerate(entries)}
        if branch:
            target = {"bypass": use, "unknown": 0x9000, "guarded": end}[branch]
            entries[0]["insn"].ops[0].value = target
            edges[0x1000].append(target)
        blocks = [
            NS(start_ea=ea, end_ea=ea + 8, succs=lambda ea=ea: [NS(start_ea=t) for t in edges[ea]]) for ea in by_ea
        ]
        ns = dict(
            values={"literal": "Sys_InitLauncherInterface()", "lookback": 12},
            exact_string_owner=lambda _: 0x1000,
            scan=lambda _: entries,
            got_anchor=lambda _: (0, "ebx") if pic else (None, None),
            local_call_target=lambda _: 0x7000,
            reg4=lambda operand: operand.reg,
            signed32=lambda value: value,
            is_writable_data=lambda ea: ea in (0x4000, 0x5000, 0x6000),
            access=lambda e, gv: {"gv_ea": hex(gv), "insn_ea": hex(e["ea"])},
            idaapi=NS(o_void=0, o_reg=REG, o_mem=MEM, o_phrase=PHRASE, o_displ=DISPL, o_imm=5, o_far=6, o_near=7),
            ida_funcs=NS(get_func=lambda _: NS(start_ea=0x1000)),
            ida_ua=NS(get_dtype_size=lambda dtype: dtype),
            idc=NS(
                print_operand=lambda ea, i: by_ea[ea]["insn"].ops[i].text,
                get_operand_value=lambda ea, i: by_ea[ea]["insn"].ops[i].value,
                print_insn_mnem=lambda ea: by_ea[ea]["mnem"],
            ),
        )
        modules = {
            "ida_frame": NS(get_spd=lambda _, ea: by_ea[ea]["sp"]),
            "ida_gdl": NS(FlowChart=lambda _: blocks),
            "ida_bytes": NS(get_item_size=lambda _: 8),
            "ida_nalt": NS(get_import_module_qty=lambda: 0),
            "idc": ns["idc"],
        }
        with patch.dict(sys.modules, modules):
            exec(walk("find-Sys_InitGame.py"), ns)
        return ns["result"]

    def test_plain_dereference_accepts_absolute_and_pic_globals(self):
        for pic in (False, True):
            with self.subTest(pic=pic):
                result = self.locate(pic=pic)
                self.assertEqual("0x4000", result["pmainwindow"]["gv_ea"])
                self.assertEqual("0x5000", result["maindc"]["gv_ea"])

    def test_nonzero_displacement_is_not_a_pointer_dereference(self):
        for offset in (4, -4):
            with self.subTest(offset=offset):
                self.assertIn("error", self.locate(address=f"[eax{offset:+d}]", displacement=offset))

    def test_indexed_address_is_not_a_pointer_dereference(self):
        self.assertIn("error", self.locate(address="[eax+ecx*4]"))

    def test_partial_width_dereference_is_rejected(self):
        for width in (1, 2):
            with self.subTest(width=width):
                self.assertIn("error", self.locate(width=width))

    def test_partial_pointer_load_is_rejected(self):
        self.assertIn("error", self.locate(load_width=1))

    def test_branch_bypassing_pointer_load_is_rejected(self):
        self.assertIn("error", self.locate(branch="bypass"))

    def test_unresolved_edge_cannot_prove_pointer_load(self):
        self.assertIn("error", self.locate(branch="unknown"))

    def test_guard_before_dominating_pointer_load_is_accepted(self):
        self.assertEqual("0x4000", self.locate(branch="guarded")["pmainwindow"]["gv_ea"])


class StudioSetupSkinWalkTests(unittest.TestCase):
    """Select the unload call, even when a later load call shares its buffer."""

    def locate(self, base, *, reload=False, stored=True, direct_dest=False):
        def op(kind, reg="", addr=0, value=0):
            return NS(type=kind, reg=REGISTERS.index(reg) if reg else -1, addr=addr, value=value, dtype=4)

        def reg(name):
            return op(REG, reg=name)

        # ESP operands are relative to the current stack pointer; EBP is fixed.
        stack_sp = -0x200
        buffer_disp = 0x80 if base == "esp" else -0x180
        slot_disp = 0x20 if base == "esp" else -0x1E0
        buffer = op(DISPL, reg=base, addr=buffer_disp)
        slot = op(DISPL, reg=base, addr=slot_disp)
        entries = []

        def emit(mnem, *ops, sp=stack_sp):
            ea = 0x1000 + len(entries) * 0x10
            entries.append(NS(ea=ea, mnem=mnem, ops=ops, sp=sp))
            return ea

        emit("lea", reg("eax"), buffer)
        if stored:
            emit("mov", slot, reg("eax"))
        format_use = emit("push", op(5, value=0x8000))
        dest_slot = op(DISPL, reg=base, addr=slot_disp + (4 if base == "esp" else 0))
        emit("push", dest_slot if direct_dest else reg("eax"), sp=stack_sp - 4)
        snprintf_site = emit("call", op(7, value=0x2000), sp=stack_sp - 8)
        emit("add", reg("esp"), op(5, value=8), sp=stack_sp - 8)
        if reload:
            emit("mov", reg("edx"), slot)
        emit("push", reg("edx") if reload else slot)
        unload_site = emit("call", op(7, value=0x3000), sp=stack_sp - 4)
        emit("add", reg("esp"), op(5, value=4), sp=stack_sp - 4)
        emit("lea", reg("eax"), buffer)
        emit("push", reg("eax"))
        load_site = emit("call", op(7, value=0x4000), sp=stack_sp - 4)
        by_ea = {entry.ea: entry for entry in entries}

        class FormatString:
            ea = 0x8000

            def __str__(self):
                return "%s%d"

        class Strings(list):
            def setup(self, **kwargs):
                pass

        def decode(insn, ea):
            insn.ops = by_ea[ea].ops
            return 1

        ns = {
            "values": {"dm_base": "DM_Base.bmp", "name_format": "%s%d"},
            "exact_string_owner": lambda literal: 0x1000,
            "ida_funcs": NS(get_func=lambda ea: NS(start_ea=0x1000)),
            "ida_nalt": NS(STRTYPE_C=0),
            "idaapi": NS(o_void=0, o_imm=5, o_near=7, o_far=6, o_reg=REG, o_displ=DISPL, o_phrase=PHRASE),
            "ida_idp": NS(get_reg_name=lambda index, size: REGISTERS[index]),
            "idautils": NS(
                Strings=lambda **kwargs: Strings([FormatString()]),
                XrefsTo=lambda ea, flags: [NS(frm=format_use)],
                FuncItems=lambda ea: list(by_ea),
            ),
            "idc": NS(
                print_insn_mnem=lambda ea: by_ea[ea].mnem,
                get_operand_value=lambda ea, index: by_ea[ea].ops[index].value,
            ),
            "reg4": lambda operand: REGISTERS[operand.reg],
            "signed32": lambda value: value,
            "local_call_target": {snprintf_site: 0x2000, unload_site: 0x3000, load_site: 0x4000}.get,
        }
        modules = {
            "ida_frame": NS(get_spd=lambda function, ea: by_ea[ea].sp),
            "ida_ua": NS(insn_t=NS, decode_insn=decode, get_dtype_size=lambda dtype: dtype),
        }
        with patch.dict(sys.modules, modules):
            exec(walk("find-R_StudioSetupSkin.py"), ns)
        return ns["result"]

    def test_direct_spill_argument_selects_unload_before_load(self):
        for base in ("esp", "ebp"):
            with self.subTest(base=base):
                self.assertEqual("0x3000", self.locate(base)["unload_ea"])

    def test_register_reload_preserves_unload_selection(self):
        for base in ("esp", "ebp"):
            with self.subTest(base=base):
                self.assertEqual("0x3000", self.locate(base, reload=True)["unload_ea"])

    def test_snprintf_destination_can_be_loaded_directly_from_spill(self):
        for base in ("esp", "ebp"):
            with self.subTest(base=base):
                self.assertEqual("0x3000", self.locate(base, direct_dest=True)["unload_ea"])

    def test_unknown_snprintf_destination_is_rejected(self):
        for base in ("esp", "ebp"):
            with self.subTest(base=base):
                self.assertIn("error", self.locate(base, stored=False, direct_dest=True))


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


class StudioLightingWalkTests(unittest.TestCase):
    def locate(self, *, form="mov", offsets=(0, 4, 8), mutation=None, width=4, pointer_call=False):
        from ida_preprocessor_scripts._studio_setup_common import RECOVER_LIGHTING_GVS_PY

        entries = []

        def op(kind=0, reg=0, addr=0, size=4):
            return NS(type=kind, reg=reg, addr=addr, value=addr, dtype=size, offb=2 if kind == MEM else 0)

        def add(mnem, dest=None, src=None):
            writes = mnem in ("mov", "movss", "xor", "add", "mulss")
            entries.append(
                (mnem, NS(size=6, ops=[dest or op(), src or op(), op()], get_canon_feature=lambda: int(writes)))
            )

        add("mov", op(REG, 6), op(DISPL, 5, 8))
        add("mov", op(REG, 0), op(PHRASE, 6))
        add("mov", op(MEM, addr=0x5000), op(REG, 0))
        add("fild", op(DISPL, 6, 4))
        add("fstp", op(MEM, addr=0x6000))
        if pointer_call:
            add("mov", op(REG, 1), op(REG, 6))
            add("call")
        add("mov", op(REG, 3), op(DISPL, 1 if pointer_call else 6, 20))
        for index, offset in enumerate(offsets):
            reg = 16 if form == "movss" else 0
            if form == "x87":
                add("fld", op(DISPL, 3, offset))
            else:
                add(form, op(REG, reg), op(DISPL, 3, offset))
            if mutation == "pointer":
                add("add", op(REG, 3), op(5, addr=4))
            elif mutation == "partial":
                add("xor", op(REG, 8, size=1), op(REG, 8, size=1))
            elif mutation:
                add(mutation, op(REG, reg), op(REG, reg))
            add("fstp" if form == "x87" else form, op(MEM, addr=0x7000 + index * 4, size=width), op(REG, reg))
        add("and", op(REG, 0), op(5, addr=0xFF00))
        for index in range(3):
            add("mov", op(REG, 0), op(DISPL, 6, 8 + index * 4))
            add("mov", op(MEM, addr=0x8000 + index * 4), op(REG, 0))
        by_ea = {0x1000 + 6 * index: entry for index, entry in enumerate(entries)}
        words = {ea + 2: insn.ops[0].addr for ea, (_, insn) in by_ea.items()}
        modules = {
            "idaapi": NS(
                o_reg=REG, o_mem=MEM, o_phrase=PHRASE, o_displ=DISPL, o_imm=5, o_void=0, inf_is_64bit=lambda: False
            ),
            "ida_funcs": NS(get_func=lambda ea: NS(start_ea=0x1000)),
            "ida_segment": NS(getseg=lambda ea: NS(perm=2), SEGPERM_EXEC=1, SEGPERM_WRITE=2),
            "ida_bytes": NS(get_bytes=lambda ea, size: b"", get_dword=lambda ea: words[ea]),
            "ida_ua": NS(get_dtype_size=lambda dtype: dtype),
            "ida_idp": NS(
                CF_CHG1=1,
                CF_CHG2=2,
                CF_CHG3=4,
                get_reg_name=lambda reg, size: REGISTERS[reg] if reg < 8 else ("al" if reg == 8 else "xmm0"),
            ),
            "idautils": NS(
                FuncItems=lambda ea: list(by_ea), DecodeInstruction=lambda ea: by_ea[ea][1], DataRefsFrom=lambda ea: []
            ),
            "idc": NS(print_insn_mnem=lambda ea: by_ea[ea][0], generate_disasm_line=lambda ea, flags: by_ea[ea][0]),
        }
        scope = {}
        with patch.dict(sys.modules, modules):
            exec(RECOVER_LIGHTING_GVS_PY.replace("SLOT_VA_PLACEHOLDER", "0x1000"), scope)
        result = json.loads(scope["result"])
        self.assertNotIn("trace", result, result)
        return result

    def test_accepts_component_copies(self):
        for form in ("mov", "movss", "x87"):
            with self.subTest(form=form):
                self.assertEqual(0x7000, self.locate(form=form)["r_plightvec"]["gv_ea"])

    def test_rejects_incorrect_component_mapping(self):
        for offsets in ((0, 0, 0), (8, 4, 0), (4, 8, 12), (0, 4), (0, 4, 8, 0, 4, 8)):
            with self.subTest(offsets=offsets):
                self.assertIn("error", self.locate(offsets=offsets))

    def test_rejects_non_dword_stores(self):
        for width in (1, 2, 8, 16):
            with self.subTest(width=width):
                self.assertIn("error", self.locate(width=width))

    def test_rejects_modified_sources(self):
        for form, mutation in (
            ("mov", "xor"),
            ("mov", "partial"),
            ("mov", "pointer"),
            ("mov", "mul"),
            ("movss", "mulss"),
            ("movss", "cvtdq2ps"),
            ("x87", "fmul"),
            ("mov", "call"),
            ("movss", "call"),
            ("x87", "call"),
        ):
            with self.subTest(form=form, mutation=mutation):
                self.assertIn("error", self.locate(form=form, mutation=mutation))

    def test_rejects_call_clobbered_pointer(self):
        self.assertIn("error", self.locate(pointer_call=True))


class PolyBlendScreenFadeWalkTests(unittest.TestCase):
    """Exercise both FFADE_MODULATE encodings that identify cl.sf."""

    def locate(self, entries):
        for index, entry in enumerate(entries):
            entry["ea"] = 0x1000 + index * 0x10
        api = NS(o_void=0, o_reg=REG, o_mem=MEM, o_displ=DISPL, o_phrase=PHRASE, o_imm=IMM)
        ns = {
            "values": {"owner": "0x1000", "fade_flags_offset": 20},
            "scan": lambda _ea: entries,
            "reg4": lambda op: op.reg,
            "changed_operand": lambda insn, index: index == 0,
            "access": lambda entry, gv: {
                "gv_ea": hex(gv),
                "insn_ea": hex(entry["ea"]),
                "insn_len": hex(entry["len"]),
                "insn_disp": hex(entry["disp"]),
            },
        }
        with patch.dict(sys.modules, {"idaapi": api}):
            exec(walk("find-R_PolyBlend-cl_sf.py"), ns)
        return ns["result"]

    def op(self, kind, register="", addr=0, value=0):
        return NS(type=kind, reg=register, addr=addr, value=value)

    def entry(self, mnem, ops, targets=(), disp=0, length=7):
        return {
            "mnem": mnem,
            "insn": NS(ops=ops),
            "targets": set(targets),
            "written": set(),
            "disp": disp,
            "len": length,
            "disasm": mnem,
        }

    def test_accepts_direct_byte_test(self):
        # ``test byte ptr ds:cl.sf.fadeFlags, 2`` (F6 05 <disp32> 02).
        result = self.locate(
            [self.entry("test", [self.op(MEM, addr=0x4000), self.op(IMM, value=2)], targets=(0x4000,), disp=2)]
        )
        self.assertEqual("0x3fec", result["gv_ea"])
        self.assertEqual(hex(0x1000), result["insn_ea"])
        self.assertEqual("0x2", result["insn_disp"])

    def test_accepts_register_form_anchored_on_the_load(self):
        # ``mov eax, dword ptr ds:cl.sf.fadeFlags`` + ``and eax, 2`` (CoF).
        result = self.locate(
            [
                self.entry(
                    "mov",
                    [self.op(REG, register="eax"), self.op(MEM, addr=0x4000)],
                    targets=(0x4000,),
                    disp=1,
                    length=5,
                ),
                self.entry("and", [self.op(REG, register="eax"), self.op(IMM, value=2)]),
            ]
        )
        self.assertEqual("0x3fec", result["gv_ea"])
        self.assertEqual(hex(0x1000), result["insn_ea"])

    def test_rejects_both_encodings_in_one_function(self):
        result = self.locate(
            [
                self.entry("test", [self.op(MEM, addr=0x4000), self.op(IMM, value=2)], targets=(0x4000,), disp=2),
                self.entry(
                    "mov",
                    [self.op(REG, register="eax"), self.op(MEM, addr=0x5000)],
                    targets=(0x5000,),
                    disp=1,
                    length=5,
                ),
                self.entry("and", [self.op(REG, register="eax"), self.op(IMM, value=2)]),
            ]
        )
        self.assertIn("error", result)

    def test_rejects_other_immediates(self):
        for imm in (1, 4, 8):
            with self.subTest(imm=imm):
                result = self.locate(
                    [
                        self.entry(
                            "test", [self.op(MEM, addr=0x4000), self.op(IMM, value=imm)], targets=(0x4000,), disp=2
                        )
                    ]
                )
                self.assertIn("error", result)

    def test_rejects_register_only_test(self):
        # ``test eax, eax`` has no immediate and names no global.
        result = self.locate([self.entry("test", [self.op(REG, register="eax"), self.op(REG, register="eax")])])
        self.assertIn("error", result)

    def test_rejects_clobbered_load_register(self):
        result = self.locate(
            [
                self.entry(
                    "mov",
                    [self.op(REG, register="eax"), self.op(MEM, addr=0x4000)],
                    targets=(0x4000,),
                    disp=1,
                    length=5,
                ),
                self.entry("xor", [self.op(REG, register="eax"), self.op(REG, register="eax")]),
                self.entry("and", [self.op(REG, register="eax"), self.op(IMM, value=2)]),
            ]
        )
        self.assertIn("error", result)

    def test_rejects_load_across_call(self):
        for register in ("eax", "ecx", "edx"):
            for target in (self.op(NEAR, addr=0x2000), self.op(MEM, addr=0x6000), self.op(REG, register="edi")):
                with self.subTest(register=register, call_target=target.type):
                    result = self.locate(
                        [
                            self.entry(
                                "mov",
                                [self.op(REG, register=register), self.op(MEM, addr=0x4000)],
                                targets=(0x4000,),
                                disp=1,
                                length=5,
                            ),
                            self.entry("call", [target]),
                            self.entry("and", [self.op(REG, register=register), self.op(IMM, value=2)]),
                        ]
                    )
                    self.assertIn("error", result)

    def test_accepts_fresh_load_after_call(self):
        result = self.locate(
            [
                self.entry("call", [self.op(NEAR, addr=0x2000)]),
                self.entry(
                    "mov",
                    [self.op(REG, register="eax"), self.op(MEM, addr=0x4000)],
                    targets=(0x4000,),
                    disp=1,
                    length=5,
                ),
                self.entry("and", [self.op(REG, register="eax"), self.op(IMM, value=2)]),
            ]
        )
        self.assertEqual("0x3fec", result["gv_ea"])
        self.assertEqual("0x1010", result["insn_ea"])

    def test_rejects_multi_target_load(self):
        result = self.locate(
            [
                self.entry(
                    "mov",
                    [self.op(REG, register="eax"), self.op(MEM, addr=0x4000)],
                    targets=(0x4000, 0x4004),
                    disp=1,
                    length=5,
                ),
                self.entry("and", [self.op(REG, register="eax"), self.op(IMM, value=2)]),
            ]
        )
        self.assertIn("error", result)

    def test_rejects_absent_test(self):
        result = self.locate([self.entry("ret", [])])
        self.assertIn("error", result)


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


class PatchSignatureRelocationTests(unittest.TestCase):
    def candidates(self, raw, kind, offset, width):
        from ida_preprocessor_scripts._patch_signature_common import CANDIDATE_PY

        api = NS(o_void=0, o_reg=REG, o_mem=MEM, o_displ=DISPL, o_imm=IMM, o_near=NEAR, o_far=6)
        ua = NS(get_dtype_size=lambda dtype: dtype)
        insn = NS(size=len(raw), ops=[NS(type=kind, offb=offset, dtype=width)])
        modules = {
            "idaapi": api,
            "ida_ua": ua,
            "ida_bytes": NS(get_bytes=lambda ea, size: raw),
            "idautils": NS(DecodeInstruction=lambda ea: insn if ea == 0x1000 else None),
        }
        ns = {"idaapi": api, "ida_ua": ua, "json": json}
        with patch.dict(sys.modules, modules):
            exec(CANDIDATE_PY.replace("TARGET_EA_PLACEHOLDER", "4096"), ns)
            return ns["candidates"](0x1000)

    def test_first_direct_call_displacement_is_relocation_independent(self):
        expected = ["E8 ?? ?? ?? ??"]
        for raw in (bytes.fromhex("E8 FC FF FF FF"), bytes.fromhex("E8 16 0D 33 01")):
            self.assertEqual(expected, self.candidates(raw, NEAR, 1, 4))

    def test_first_indirect_call_absolute_address_is_wildcarded(self):
        self.assertEqual(["FF 15 ?? ?? ?? ??"], self.candidates(bytes.fromhex("FF 15 20 25 2B 10"), MEM, 2, 4))

    def test_byte_load_absolute_address_masks_all_four_address_bytes(self):
        self.assertEqual(["A0 ?? ?? ?? ??"], self.candidates(bytes.fromhex("A0 12 34 56 78"), MEM, 1, 1))


class EnginePatchDataflowTests(unittest.TestCase):
    def call_path(self, code, anchor):
        from ida_preprocessor_scripts._engine_patch_common import CALL_FLOW_PY

        modules = {
            "ida_frame": NS(),
            "ida_gdl": NS(FlowChart=lambda _: [NS(start_ea=0x100, end_ea=0x120)]),
        }
        ns = {"ida_funcs": NS(get_func=lambda _: object())}
        with patch.dict(sys.modules, modules):
            exec(CALL_FLOW_PY, ns)
            return ns["anchored_call_path"](0x100, code, anchor)

    def test_default_argument_path_follows_backward_shared_copy_tail(self):
        from ida_preprocessor_scripts.x86_call_arguments import recover_call_arguments

        buffer = ("local_address", "frame", -128)
        code = [
            {"ea": 0x80, "mnem": "push", "ops": [("reg", "eax")], "sp": -4},
            {"ea": 0x81, "mnem": "push", "ops": [("imm", buffer)], "sp": -8},
            {"ea": 0x82, "mnem": "call", "ops": [("imm", 0x9000)], "sp": -12},
            {"ea": 0x100, "mnem": "push", "ops": [("imm", 128)], "sp": 0},
            {"ea": 0x105, "mnem": "mov", "ops": [("reg", "eax"), ("imm", 0x5000)], "sp": -4},
            {"ea": 0x110, "mnem": "jmp", "ops": [("imm", 0x80)], "sp": -4},
        ]
        path = self.call_path(code, 0x105)
        self.assertEqual(0x82, path[-1]["ea"])
        self.assertEqual([buffer, 0x5000, 128], recover_call_arguments(path, len(path) - 1, 3))

    def test_argument_path_rejects_conditional_and_cyclic_tails(self):
        for mnem, target in (("jz", 0x110), ("jmp", 0x100), ("jmp", 0x9000)):
            code = [
                {"ea": 0x100, "mnem": "mov", "ops": [("reg", "eax"), ("imm", 0x5000)], "sp": 0},
                {"ea": 0x110, "mnem": mnem, "ops": [("imm", target)], "sp": 0},
            ]
            self.assertIsNone(self.call_path(code, 0x100))

    def test_language_abi_and_owner_classification(self):
        from ida_preprocessor_scripts._engine_patch_common import language_role

        buffer = ("local_address", "frame", -128)
        strings = {"GAME", "%s/%s_%s"}
        self.assertEqual(
            "FileSystem_SetGameDirectory_V_strncpy_callsite_0",
            language_role([buffer, 0x5000, 128], strings | {"DEFAULTGAME"}, {0x5000}),
        )
        self.assertEqual(
            "FileSystem_AddFallbackGameDir_V_strncpy_callsite_0",
            language_role([buffer, 0x5000, 128], strings, {0x5000}),
        )
        for arguments in ([buffer, 0x5000, None], [buffer, 0x5000, 32], [buffer, 0x6000, 128], [None, 0x5000, 128]):
            self.assertIsNone(language_role(arguments, strings, {0x5000}))
        self.assertIsNone(language_role([buffer, 0x5000, 128], {"GAME"}, {0x5000}))

    def test_factory_query_traces_return_value_through_spill(self):
        from ida_preprocessor_scripts._engine_patch_common import factory_origin

        code = [
            {"ea": 0x10, "mnem": "call", "ops": [("imm", 0x9000)]},
            {"ea": 0x15, "mnem": "mov", "ops": [("frame", -4), ("reg", "eax")]},
            {"ea": 0x18, "mnem": "call", "ops": [("frame", -4)]},
        ]
        self.assertEqual(0, factory_origin(code, 2))
        code.insert(0, {"ea": 0x8, "mnem": "jz", "ops": [("imm", 0x18)]})
        self.assertIsNone(factory_origin(code, 3))

    def test_factory_query_rejects_overwritten_return_register(self):
        from ida_preprocessor_scripts._engine_patch_common import factory_origin

        code = [
            {"ea": 0x10, "mnem": "call", "ops": [("imm", 0x9000)]},
            {"ea": 0x15, "mnem": "xor", "ops": [("reg", "eax"), ("reg", "eax")]},
            {"ea": 0x18, "mnem": "call", "ops": [("reg", "eax")]},
        ]
        self.assertIsNone(factory_origin(code, 2))

    def branch_tail(self, code, blocks, primary_ea=0x100):
        from ida_preprocessor_scripts import _engine_patch_common as common

        with (
            patch.object(common, "ida_funcs", NS(get_func=lambda _: object()), create=True),
            patch.object(common, "ida_gdl", NS(FlowChart=lambda _: blocks), create=True),
        ):
            return common.branch_tail_call(0x100, code, primary_ea)

    def test_branch_tail_call_finds_duplicate_copy_on_sibling_branch(self):
        # Dispatch (0x100) branches to the sibling call (0x200) or the primary
        # call's block (0x300), exactly CoF's per-branch duplication.
        code = [
            {"ea": 0x100, "mnem": "cmp", "ops": [("reg", "eax"), ("imm", 0)]},
            {"ea": 0x110, "mnem": "jz", "ops": [("imm", 0x300)]},
            {"ea": 0x200, "mnem": "call", "ops": [("imm", 0x9000)]},
            {"ea": 0x210, "mnem": "jmp", "ops": [("imm", 0x310)]},
            {"ea": 0x300, "mnem": "call", "ops": [("imm", 0x9000)]},
        ]
        blocks = [
            NS(start_ea=0x100, end_ea=0x200, succs=lambda: [NS(start_ea=0x200), NS(start_ea=0x300)]),
            NS(start_ea=0x200, end_ea=0x220, succs=lambda: [NS(start_ea=0x310)]),
            NS(start_ea=0x300, end_ea=0x320, succs=lambda: []),
        ]
        self.assertEqual(2, self.branch_tail(code, blocks, primary_ea=0x300))

    def test_branch_tail_call_ignores_merged_call_tail(self):
        # Both arms reach the primary call's block before any call, as in every
        # other engine family: there is no second copy to redirect.
        code = [
            {"ea": 0x100, "mnem": "cmp", "ops": [("reg", "eax"), ("imm", 0)]},
            {"ea": 0x110, "mnem": "jz", "ops": [("imm", 0x300)]},
            {"ea": 0x200, "mnem": "mov", "ops": [("reg", "ecx"), ("reg", "eax")]},
            {"ea": 0x210, "mnem": "jmp", "ops": [("imm", 0x300)]},
            {"ea": 0x300, "mnem": "call", "ops": [("imm", 0x9000)]},
        ]
        blocks = [
            NS(start_ea=0x100, end_ea=0x200, succs=lambda: [NS(start_ea=0x200), NS(start_ea=0x300)]),
            NS(start_ea=0x200, end_ea=0x220, succs=lambda: [NS(start_ea=0x300)]),
            NS(start_ea=0x300, end_ea=0x320, succs=lambda: []),
        ]
        self.assertIsNone(self.branch_tail(code, blocks))

    def test_callsite_name_numbers_duplicates_only(self):
        finder = runpy.run_path(
            str(ROOT / "ida_preprocessor_scripts" / "find-FileSystem_SetGameDirectory_V_strncpy_callsite_0.py")
        )
        callsite_name = finder["_callsite_name"]
        name = "FileSystem_SetGameDirectory_V_strncpy_callsite_0"
        self.assertEqual(name, callsite_name(name, 0))
        self.assertEqual("FileSystem_SetGameDirectory_V_strncpy_callsite_1", callsite_name(name, 1))


class HostParmsWalkTests(unittest.TestCase):
    """Exercise find-host_parms through decoded operands and real flow recovery.

    The finder locates ``host_parms`` as the single argument of the direct
    ``LoadEntityDLLs`` call inside the revalidated Host_InitializeGameDLL body.
    """

    def locate(self, argument):
        api = NS(o_void=0, o_reg=REG, o_mem=MEM, o_phrase=PHRASE, o_displ=DISPL, o_imm=IMM, o_near=NEAR)
        entries = []
        sp = 0

        def op(kind, *, reg="", addr=0, value=0, dtype=4, sf1=0, sf2=0, text=""):
            return NS(
                type=kind,
                reg=reg,
                addr=addr,
                value=value,
                dtype=dtype,
                specflag1=sf1,
                specflag2=sf2,
                text=text,
            )

        def emit(mnem, *ops, targets=(), written=(), disp=0):
            nonlocal sp
            ea = 0x1000 + len(entries) * 8
            entries.append(
                dict(
                    ea=ea,
                    mnem=mnem,
                    insn=NS(ops=[*ops, op(0)]),
                    targets=set(targets),
                    written=set(written),
                    disp=disp,
                    len=6,
                    disasm=mnem,
                    sp=sp,
                )
            )
            if mnem == "push":
                sp -= 4
            return ea

        emit("push", op(REG, reg="ebx"))
        emit("mov", op(REG, reg="ebx"), op(IMM, value=1))
        emit("sub", op(REG, reg="esp"), op(IMM, value=0x20))
        # The ESP store's text operand embeds a variable name that itself
        # contains a register name ("szBaseDir" -> "edi"); only the structural
        # SIB base=esp test may classify it as a stack slot.
        if argument["form"] == "push-abs":
            emit("push", op(MEM, addr=0x4000, text="dword ptr ds:[4000h]"), targets=(0x4000,), disp=2)
            emit("call", op(NEAR, value=0x7000))
        else:
            emit(
                "mov",
                op(REG, reg="eax"),
                op(MEM, addr=0x4000, text="ds:[4000h]"),
                targets=(0x4000,),
                disp=1,
            )
            emit("mov", op(DISPL, reg="esp", addr=0, sf1=1, sf2=36, text="[esp+2Ch+szBaseDir]"), op(REG, reg="eax"))
            emit("call", op(NEAR, value=0x7000))
        by_ea = {e["ea"]: e for e in entries}
        edges = {e["ea"]: [entries[i + 1]["ea"]] if i + 1 < len(entries) else [] for i, e in enumerate(entries)}
        blocks = [
            NS(start_ea=ea, end_ea=ea + 8, succs=lambda ea=ea: [NS(start_ea=t) for t in edges[ea]]) for ea in by_ea
        ]
        idc = NS(
            print_operand=lambda ea, i: by_ea[ea]["insn"].ops[i].text,
            print_insn_mnem=lambda ea: by_ea[ea]["mnem"],
            get_operand_type=lambda ea, i: by_ea[ea]["insn"].ops[i].type,
            get_operand_value=lambda ea, i: by_ea[ea]["insn"].ops[i].value,
        )
        ida_bytes = NS(get_item_size=lambda _: 8, get_bytes=lambda *a: b"GetNewDLLFunctions\x00")
        ns = dict(
            values={"loadent_anchor": "GetNewDLLFunctions", "owner": "0x1000", "lookback": 12},
            scan=lambda _: entries,
            got_anchor=lambda _: (None, None),
            local_call_target=lambda _: 0x7000,
            reg4=lambda operand: operand.reg,
            signed32=lambda value: value,
            is_writable_data=lambda ea: ea in (0x4000,),
            is_got=lambda _: False,
            changed_operand=lambda insn, index: True,
            access=lambda e, gv: {
                "gv_ea": hex(gv),
                "insn_ea": hex(e["ea"]),
                "insn_len": "0x6",
                "insn_disp": hex(e["disp"]),
                "insn_disasm": e["disasm"],
            },
            idaapi=api,
            ida_funcs=NS(get_func=lambda ea: NS(start_ea=ea)),
            ida_ua=NS(get_dtype_size=lambda dtype: dtype),
            idc=idc,
            idautils=NS(
                Segments=lambda: [0],
                DataRefsTo=lambda ea: [0x7000] if ea == 0 else [],
                DataRefsFrom=lambda _: [],
                FuncItems=lambda _: [],
            ),
            ida_segment=NS(getseg=lambda ea: NS(perm=4, end_ea=0x1000)),
            ida_bytes=ida_bytes,
        )
        modules = {
            "ida_frame": NS(get_spd=lambda _, ea: by_ea[ea]["sp"]),
            "ida_gdl": NS(FlowChart=lambda _: blocks),
            "ida_nalt": NS(get_import_module_qty=lambda: 0),
            "ida_bytes": ida_bytes,
            "idc": idc,
            "ida_name": NS(get_name=lambda _: "sub"),
        }
        with patch.dict(sys.modules, modules):
            exec(walk("find-host_parms.py"), ns)
        return ns["result"]

    def test_push_absolute_argument_is_accepted(self):
        result = self.locate({"form": "push-abs"})
        self.assertEqual("0x4000", result["gv"]["gv_ea"])

    def test_esp_slot_structural_decode_defeats_embedded_register_name(self):
        result = self.locate({"form": "mov-spill"})
        self.assertEqual("0x4000", result["gv"]["gv_ea"])


class ForceCVarsSetupTripleWalkTests(unittest.TestCase):
    """Reject a neighbouring Cvar_DirectSet that only mimics R_ForceCVars inlined.

    The setup host's inlined force-cvar block ends with a two-argument
    Cvar_DirectSet call directly before R_CheckVariables. The walk must not
    report that call target as the standalone R_ForceCVars.
    """

    DSET = 0x4000
    FORCE = 0x5000
    RCV = 0x6000
    ANIM = 0x7000

    def locate(self, preceding):
        """``preceding`` is the direct call issued just before R_CheckVariables."""
        items = [0x1000, 0x1010, 0x1020, 0x1030, 0x1040, 0x1050]
        targets = {
            0x1000: 0x9000,
            0x1010: self.DSET,
            0x1020: 0x9000,
            0x1030: preceding,
            0x1040: self.RCV,
            0x1050: self.ANIM,
        }
        sizes = {
            self.DSET: 0x1A6,
            self.FORCE: 0x2CD,
            self.RCV: 0xBC,
            self.ANIM: 0x5B,
            0x9000: 0x100,
        }
        idautils = NS(
            FuncItems=lambda owner: items,
            CodeRefsTo=lambda ea, flags=0: [0x1000],
            DataRefsTo=lambda ea: [],
        )
        ida_funcs = NS(
            get_func=lambda ea: NS(start_ea=ea, end_ea=ea + sizes.get(ea, 0x40)),
            calc_thunk_func_target=lambda function: (0xFFFFFFFF, 0xFFFFFFFF),
        )
        idc = NS(
            print_insn_mnem=lambda ea: "call",
            get_operand_value=lambda ea, index: targets[ea],
            get_func_name=lambda ea: "sub",
        )
        ns = {
            "MARKER": SETUP_TRIPLE_MARKER,
            "RCV": self.RCV,
            "DSET": self.DSET,
            "MAX_GAP": 96,
            "idautils": idautils,
            "ida_funcs": ida_funcs,
            "idc": idc,
        }
        code = (
            walk("find-R_ForceCVars_R-AnimateLight.py")
            .replace("@@MARKER@@", repr(SETUP_TRIPLE_MARKER))
            .replace("@@RCV@@", repr(self.RCV))
            .replace("@@DSET@@", repr(self.DSET))
            .replace("@@MAX_GAP@@", "96")
        )
        modules = {
            "idautils": idautils,
            "ida_funcs": ida_funcs,
            "idc": idc,
            "ida_bytes": NS(is_loaded=lambda ea: False, get_dword=lambda ea: 0),
            "ida_segment": NS(getseg=lambda ea: None, get_segm_name=lambda seg: "", SEGPERM_EXEC=1),
            "idaapi": NS(BADADDR=0xFFFFFFFF),
        }
        capture = io.StringIO()
        with patch.dict(sys.modules, modules):
            with contextlib.redirect_stdout(capture):
                exec(code, ns)
        for line in capture.getvalue().splitlines():
            if line.startswith(SETUP_TRIPLE_MARKER):
                return json.loads(line[len(SETUP_TRIPLE_MARKER) :])
        raise AssertionError("walk produced no result line")

    def test_rejects_cvar_directset_alias_and_reports_inlined(self):
        result = self.locate(self.DSET)
        self.assertNotIn("error", result)
        self.assertIsNone(result["R_ForceCVars"])
        self.assertTrue(result["force_inlined"])
        self.assertEqual(hex(self.ANIM), result["R_AnimateLight"]["va"])

    def test_accepts_genuine_standalone_force_cvars(self):
        result = self.locate(self.FORCE)
        self.assertEqual(hex(self.FORCE), result["R_ForceCVars"]["va"])
        self.assertEqual(hex(self.ANIM), result["R_AnimateLight"]["va"])


class NetworkCreationWalkTests(unittest.TestCase):
    """Exercise argument provenance, rollback control flow and inline rejection."""

    def locate(
        self,
        *,
        id_mode="address",
        handle_before_test=True,
        bypass_cleanup=False,
        extra_work=False,
        memory_result=False,
        narrow_host_store=False,
        bypass_initialized=False,
    ):
        from ida_preprocessor_scripts import x86_call_arguments

        ns = {"LITERALS": (), "SYS_ERROR": 0x9000, "WANT_START": True}
        api = NS(o_void=0, o_reg=REG, o_mem=MEM, o_displ=DISPL, o_phrase=PHRASE, o_imm=IMM, o_near=NEAR, o_far=6)
        modules = {
            name: NS()
            for name in ("ida_auto", "ida_funcs", "ida_idp", "ida_nalt", "ida_segment", "ida_ua", "ida_bytes")
        }
        modules.update(
            {
                "idaapi": api,
                "idautils": NS(Segments=lambda: []),
                "idc": NS(),
            }
        )
        modules["ida_nalt"].get_import_module_qty = lambda: 0
        api.inf_is_64bit = lambda: False
        with patch.dict(sys.modules, modules):
            exec(walk("find-NET_StartThread-symbols.py"), ns)
        ns.update(vars(x86_call_arguments))
        entries, dwords = [], {}

        def op(kind, value=0, *, width=4):
            return NS(type=kind, value=value, addr=value, reg=value, dtype=width, offb=1, n=0)

        def emit(mnem, *ops):
            ea = 0x1000 + len(entries) * 8
            for index, operand in enumerate(ops):
                operand.n = index
                if operand.type in (IMM, MEM):
                    dwords[ea + operand.offb] = operand.value
            insn = NS(ops=[*ops, op(0)], size=8)
            entry = dict(ea=ea, size=8, insn=insn, mnem=mnem, successors=[ea + 8])
            entries.append(entry)
            return entry

        def store(gv, val):
            return emit("mov", op(MEM, gv), op(IMM, val))

        def call(target):
            return emit("call", op(MEM, target))

        emit("cmp", op(MEM, 0x4000), op(IMM))
        emit("cmp", op(MEM, 0x4004), op(IMM))
        if extra_work:
            call(0x9100)
        if narrow_host_store:
            emit("mov", op(MEM, 0x6008, width=2), op(REG, "eax", width=2))
        initialize = store(0x4004, 1)
        emit("push", op(IMM, 0x5000))
        call(0x8000)
        if id_mode == "register":
            emit("mov", op(REG, "edx"), op(IMM, 0x6000))
            emit("push", op(REG, "edx"))
        elif id_mode == "runtime_value":
            emit("push", op(MEM, 0x6000))
        else:
            emit("push", op(IMM, 0x6004 if id_mode == "handle" else 0x6000))
        emit("push", op(IMM))
        emit("push", op(IMM))
        emit("push", op(IMM, 0x3000))
        emit("push", op(IMM))
        emit("push", op(IMM))
        call(0x8004)
        if handle_before_test:
            emit("mov", op(MEM, 0x6004), op(REG, "eax"))
        if memory_result:
            emit("cmp", op(MEM, 0x6004), op(IMM))
        else:
            emit("test", op(REG, "eax"), op(REG, "eax"))
        if not handle_before_test:
            emit("mov", op(MEM, 0x6004), op(REG, "eax"))
        branch = emit("jnz", op(NEAR))
        emit("push", op(IMM, 0x5000))
        delete = call(0x8008)
        reset = store(0x4004, 0)
        store(0x4000, 0)
        site = emit("push", op(IMM, 0x7000))
        call(0x9000)
        end = emit("ret")
        end["successors"] = []
        branch["insn"].ops[0].addr = end["ea"]
        branch["successors"].append(end["ea"])
        if bypass_cleanup:
            branch["successors"][0] = reset["ea"]
        if bypass_initialized:
            entries[0]["successors"] = [initialize["ea"] + 8]
        ns["imports"] = {0x8000: "InitializeCriticalSection", 0x8004: "CreateThread", 0x8008: "DeleteCriticalSection"}
        ns["raw_body"] = lambda _: entries
        modules["ida_idp"].get_reg_name = lambda reg, _: reg
        modules["ida_ua"].get_dtype_size = lambda dtype: dtype
        modules["ida_bytes"].get_dword = lambda ea: dwords.get(ea, 0)
        modules["ida_bytes"].get_strlit_contents = lambda *_: None
        modules["ida_segment"].SEGPERM_WRITE, modules["ida_segment"].SEGPERM_EXEC = 2, 4
        modules["ida_segment"].getseg = lambda ea: (
            NS(perm=4, end_ea=0x4000) if ea == 0x3000 else NS(perm=2, end_ea=0x8000) if 0x4000 <= ea < 0x8000 else None
        )
        modules["idautils"].CodeRefsTo = lambda *_: []
        modules["idautils"].DataRefsFrom = lambda ea: [
            int(o.addr) for e in entries if e["ea"] == ea for o in e["insn"].ops if o.type == MEM
        ]
        modules["idc"].print_insn_mnem = lambda *_: ""
        return ns["inspect_path"](0x1000, site["ea"], 0x7000)

    def test_recovers_callback_and_thread_id_storage_with_register_transfer(self):
        result = self.locate(id_mode="register")
        self.assertIsNotNone(result)
        self.assertEqual(0x3000, result["thread"])
        self.assertEqual(0x6000, result["tid"])
        self.assertEqual(0x6004, result["handle"])
        self.assertTrue(result["standalone"])

    def test_accepts_handle_store_between_result_test_and_branch(self):
        self.assertIsNotNone(self.locate(handle_before_test=False))

    def test_accepts_result_test_through_stored_handle(self):
        self.assertIsNotNone(self.locate(memory_result=True))

    def test_rejects_runtime_id_and_handle_slot_as_thread_id_storage(self):
        for mode in ("runtime_value", "handle"):
            with self.subTest(mode=mode):
                self.assertIsNone(self.locate(id_mode=mode))

    def test_rejects_failure_path_that_bypasses_cleanup(self):
        self.assertIsNone(self.locate(bypass_cleanup=True))

    def test_rejects_creation_path_that_bypasses_initialized_store(self):
        self.assertIsNone(self.locate(bypass_initialized=True))

    def test_does_not_label_host_with_extra_work_as_standalone_start(self):
        result = self.locate(extra_work=True)
        self.assertIsNotNone(result)
        self.assertFalse(result["standalone"])

    def test_recovers_inline_creation_despite_unrelated_word_store(self):
        result = self.locate(narrow_host_store=True)
        self.assertIsNotNone(result)
        self.assertFalse(result["standalone"])


class PthreadCreationWalkTests(unittest.TestCase):
    """Check POSIX output/error-code roles, PIC provenance and failure flow."""

    def locate(
        self,
        *,
        runtime_output=False,
        alias_error=False,
        bypass_cleanup=False,
        bypass_initialized=False,
        clobber=False,
        extra_work=False,
        store_first=False,
        swap_args=False,
        wrong_state_guard=False,
        partial_result=False,
    ):
        entries = []

        def op(kind, value=0, reg=""):
            return NS(type=kind, value=value, addr=value, reg=reg, dtype=4, offb=2, specflag1=0, specflag2=0)

        def emit(mnem, *ops, targets=(), written=()):
            ea = 0x1000 + len(entries) * 8
            insn = NS(ops=[*ops, op(0)], size=8)
            entry = dict(
                ea=ea, len=8, insn=insn, mnem=mnem, targets=set(targets), written=set(written), disp=2, disasm=mnem
            )
            entries.append(entry)
            return entry

        def store(gv, source):
            return emit("mov", op(DISPL, gv - 0x2000, "ebx"), source, targets=(gv,), written=(gv,))

        state_guards = []
        for gv, branch_kind in ((0x4000, "jz"), (0x4004, "jnz")):
            emit("mov", op(REG, reg="eax"), op(DISPL, gv - 0x2000, "ebx"), targets=(gv,))
            emit("test", op(REG, reg="eax"), op(REG, reg="eax"))
            state_guards.append(emit("jz" if wrong_state_guard else branch_kind, op(NEAR)))
        if extra_work:
            emit("call", op(NEAR, 0x9100))
        initialized = store(0x4004, op(IMM, 1))
        for slot, gv in ((0, 0x3000 if swap_args else 0x6000), (8, 0x6000 if swap_args else 0x3000)):
            emit(
                "mov" if runtime_output and slot == 0 else "lea",
                op(REG, reg="eax"),
                op(DISPL, gv - 0x2000, "ebx"),
                targets=(gv,),
            )
            emit("mov", op(DISPL, slot, "esp"), op(REG, reg="eax"))
        for slot in (4, 12):
            emit("mov", op(DISPL, slot, "esp"), op(IMM))
        create = emit("call", op(NEAR, 0x8000))
        if clobber:
            emit("xor", op(REG, reg="eax"), op(REG, reg="eax"))
        if store_first:
            result_store = store(0x6000 if alias_error else 0x6004, op(REG, reg="eax"))
        result_test = emit("test", op(REG, reg="eax"), op(REG, reg="eax"))
        if partial_result:
            result_test["insn"].ops[0].dtype = result_test["insn"].ops[1].dtype = 1
        if not store_first:
            result_store = store(0x6000 if alias_error else 0x6004, op(REG, reg="eax"))
        branch = emit("jnz", op(NEAR))
        success = emit("ret")
        emit("lea", op(REG, reg="eax"), op(DISPL, 0x3000, "ebx"), targets=(0x5000,))
        emit("mov", op(DISPL, 0, "esp"), op(REG, reg="eax"))
        destroy = emit("call", op(NEAR, 0x8004))
        reset = store(0x4004, op(IMM))
        store(0x4000, op(IMM))
        emit("lea", op(REG, reg="eax"), op(DISPL, 0x5000, "ebx"))
        emit("mov", op(DISPL, 0, "esp"), op(REG, reg="eax"))
        fatal = emit("call", op(NEAR, 0x9000))
        emit("ret")
        branch["insn"].ops[0].addr = success["ea"] + 8
        by_ea = {e["ea"]: e for e in entries}
        edges = {e["ea"]: ([] if e["mnem"] == "ret" else [e["ea"] + 8]) for e in entries}
        edges[branch["ea"]].append(branch["insn"].ops[0].addr)
        for guard in state_guards:
            guard["insn"].ops[0].addr = success["ea"]
            edges[guard["ea"]].append(success["ea"])
        if bypass_cleanup:
            edges[branch["ea"]].append(reset["ea"])
        if bypass_initialized:
            edges[entries[0]["ea"]].append(initialized["ea"] + 8)
        ns = dict(
            values={"fatal": 0x9000, "literal": "unused"},
            scan=lambda _: entries,
            got_anchor=lambda _: (0x2000, "ebx"),
            reg4=lambda o: o.reg,
            signed32=lambda v: v,
            local_call_target=lambda ea: int(by_ea[ea]["insn"].ops[0].addr),
            is_code_address=lambda ea: ea == 0x3000,
            is_plt=lambda _: False,
            is_got=lambda _: False,
            is_writable_data=lambda ea: 0x4000 <= ea < 0x8000,
            access=lambda e, gv: {"gv_ea": hex(gv), "insn_ea": hex(e["ea"])},
            elf_data_refs_to=lambda _: [],
        )
        api = NS(
            o_void=0,
            o_reg=REG,
            o_mem=MEM,
            o_displ=DISPL,
            o_phrase=PHRASE,
            o_imm=IMM,
            o_near=NEAR,
            inf_is_64bit=lambda: False,
        )
        modules = {
            "idaapi": api,
            "ida_frame": NS(get_spd=lambda *_: 0),
            "ida_nalt": NS(get_import_module_qty=lambda: 0),
            "ida_funcs": NS(get_func=lambda ea: NS(start_ea=ea)),
            "ida_ua": NS(get_dtype_size=lambda v: v),
            "ida_segment": NS(getseg=lambda _: NS(end_ea=0x8000)),
            "idautils": NS(Segments=lambda: [], CodeRefsTo=lambda *_: []),
            "idc": NS(
                get_operand_value=lambda ea, _: by_ea[ea]["insn"].ops[0].addr,
                generate_disasm_line=lambda *_: "synthetic",
            ),
            "ida_bytes": NS(get_strlit_contents=lambda *_: None),
        }
        ns.update({k: v for k, v in modules.items() if k != "ida_frame"})
        with patch.dict(sys.modules, modules):
            exec(walk("find-NET_StartThread-pthread-symbols.py"), ns)
            ns["api_name"] = lambda ea: {create["ea"]: "pthread_create", destroy["ea"]: "pthread_mutex_destroy"}.get(ea)
            ns["decode_function_flow"] = lambda *_: edges
            ns["changed_operand"] = lambda insn, i: (
                insn.ops[0].type == REG
                and by_ea[next(e["ea"] for e in entries if e["insn"] is insn)]["mnem"] not in ("test", "cmp")
            )
            return ns["inspect_path"](0x1000, 0x7000)

    def test_recovers_pic_pthread_output_and_separate_error_code(self):
        for store_first in (False, True):
            result = self.locate(store_first=store_first)
            self.assertIsNotNone(result)
            self.assertEqual(0x3000, result["routine"])
            self.assertEqual("0x6000", result["thread"]["gv_ea"])
            self.assertEqual("0x6004", result["error_code"]["gv_ea"])
            self.assertTrue(result["standalone"])

    def test_rejects_runtime_value_in_output_argument(self):
        self.assertIsNone(self.locate(runtime_output=True))

    def test_rejects_error_store_aliasing_pthread_output(self):
        self.assertIsNone(self.locate(alias_error=True))

    def test_rejects_swapped_callback_and_output_arguments(self):
        self.assertIsNone(self.locate(swap_args=True))

    def test_rejects_branch_bypassing_mutex_cleanup(self):
        self.assertIsNone(self.locate(bypass_cleanup=True))

    def test_rejects_creation_bypassing_initialized_assignment(self):
        self.assertIsNone(self.locate(bypass_initialized=True))

    def test_rejects_clobbered_create_return_value(self):
        self.assertIsNone(self.locate(clobber=True))

    def test_rejects_inverted_initialized_guard(self):
        self.assertIsNone(self.locate(wrong_state_guard=True))

    def test_rejects_partial_width_return_test(self):
        self.assertIsNone(self.locate(partial_result=True))

    def test_does_not_publish_inline_host_as_start_function(self):
        result = self.locate(extra_work=True)
        self.assertIsNotNone(result)
        self.assertFalse(result["standalone"])


if __name__ == "__main__":
    unittest.main()
