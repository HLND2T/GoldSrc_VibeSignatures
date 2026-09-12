import json
import runpy
import unittest
from pathlib import Path
from types import SimpleNamespace as NS
from unittest.mock import patch


VOID, REG, MEM, PHRASE, DISPL, IMM, NEAR = range(7)
CALLBACK, CONSTRUCTOR, HANDLER = 0x1000, 0x2000, 0x3000
POINTER, TABLE, OTHER_TABLE, OTHER_HANDLER = 0x600000, 0x610000, 0x620000, 0x4000


def operand(kind=VOID, *, reg=0, addr=0, value=0):
    return NS(type=kind, reg=reg, phrase=reg, addr=addr, value=value, specflag1=0)


def instruction(mnemonic, *operands):
    return NS(mnemonic=mnemonic, ops=[*operands, *[operand() for _ in range(2 - len(operands))]], size=1)


def run_locator(*, alternative=None, loop=False, unknown_pointer=False):
    code = {
        CALLBACK: instruction("mov", operand(REG, reg=0), operand(MEM, addr=POINTER)),
        CALLBACK + 1: instruction("mov", operand(REG, reg=1), operand(PHRASE, reg=0)),
        CALLBACK + 2: instruction("call", operand(DISPL, reg=1, addr=4)),
        CALLBACK + 3: instruction("retn"),
        CONSTRUCTOR: instruction("mov", operand(REG, reg=6), operand(REG, reg=1)),
        CONSTRUCTOR + 1: instruction("lea", operand(REG, reg=0), operand(DISPL, reg=6, addr=8)),
        CONSTRUCTOR + 2: instruction("mov", operand(PHRASE, reg=0), operand(IMM, value=TABLE)),
        CONSTRUCTOR + 3: instruction("test", operand(REG, reg=6), operand(REG, reg=6)),
        CONSTRUCTOR + 4: instruction("jz", operand(NEAR, addr=CONSTRUCTOR + 7)),
        CONSTRUCTOR + 5: instruction("mov", operand(MEM, addr=POINTER), operand(REG, reg=0)),
        CONSTRUCTOR + 6: instruction("jmp", operand(NEAR, addr=CONSTRUCTOR + 9)),
        CONSTRUCTOR + 7: instruction("mov", operand(MEM, addr=POINTER), operand(IMM, value=0)),
        CONSTRUCTOR + 8: instruction("jmp", operand(NEAR, addr=CONSTRUCTOR + 9)),
        CONSTRUCTOR + 9: instruction("retn"),
        HANDLER: instruction("retn"),
        OTHER_HANDLER: instruction("retn"),
    }
    if alternative is not None:
        code[CONSTRUCTOR + 7] = instruction("mov", operand(PHRASE, reg=0), operand(IMM, value=alternative))
        code[CONSTRUCTOR + 8] = instruction("mov", operand(MEM, addr=POINTER), operand(REG, reg=0))
    if loop:
        code[CONSTRUCTOR + 8] = instruction("jmp", operand(NEAR, addr=CONSTRUCTOR + 7))
    if unknown_pointer:
        code[CONSTRUCTOR + 7] = instruction("mov", operand(MEM, addr=POINTER), operand(REG, reg=7))

    def function(ea):
        for start, length in ((CALLBACK, 4), (CONSTRUCTOR, 10), (HANDLER, 1), (OTHER_HANDLER, 1)):
            if start <= ea < start + length:
                return NS(start_ea=start, end_ea=start + length)
        return None

    def items(start):
        owner = function(start)
        return list(range(owner.start_ea, owner.end_ea))

    modules = {
        "ida_bytes": NS(get_dword=lambda ea: {TABLE + 4: HANDLER, OTHER_TABLE + 4: OTHER_HANDLER}.get(ea, 0)),
        "ida_funcs": NS(get_func=function),
        "ida_gdl": NS(),
        "ida_nalt": NS(),
        "ida_segment": NS(SEGPERM_EXEC=1, getseg=lambda ea: NS(perm=0 if ea >= POINTER else 1)),
        "ida_ua": NS(o_void=VOID, o_reg=REG, o_mem=MEM, o_phrase=PHRASE, o_displ=DISPL, o_imm=IMM, o_near=NEAR),
        "idaapi": NS(inf_is_64bit=lambda: False),
        "idautils": NS(
            FuncItems=items,
            DecodeInstruction=lambda ea: code.get(ea),
            DataRefsTo=lambda ea: [CONSTRUCTOR + 5, CONSTRUCTOR + 7] if ea == POINTER else [],
            DataRefsFrom=lambda ea: [],
        ),
        "idc": NS(print_insn_mnem=lambda ea: code[ea].mnemonic, print_operand=lambda ea, index: ""),
    }
    with patch("ida_preprocessor_scripts._client_registration_common.REGISTRATION_QUERY", ""):
        finder = runpy.run_path(
            str(Path(__file__).resolve().parents[1] / "ida_preprocessor_scripts/find-client-ScoreInfo-handler.py")
        )
    namespace = {"registered_callbacks": lambda name: {CALLBACK}}
    with patch.dict("sys.modules", modules):
        exec(finder["LOCATE"], namespace)
    return json.loads(namespace["result"])


class ScoreInfoConstructorTests(unittest.TestCase):
    def test_null_guard_keeps_proven_nonnull_interface(self):
        self.assertEqual(HANDLER, run_locator().get("target"))

    def test_agreeing_branches_keep_one_target(self):
        self.assertEqual(HANDLER, run_locator(alternative=TABLE).get("target"))

    def test_conflicting_branch_tables_fail_closed(self):
        self.assertNotIn("target", run_locator(alternative=OTHER_TABLE))

    def test_cyclic_constructor_fails_closed(self):
        self.assertNotIn("target", run_locator(loop=True))

    def test_unproven_nonnull_branch_fails_closed(self):
        self.assertNotIn("target", run_locator(unknown_pointer=True))
