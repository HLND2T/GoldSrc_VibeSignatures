"""Exercise the shipped studio-table walk with ordinary and ATI draw branches."""

import contextlib
import importlib.util
import io
import json
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "gl_studio_draw_points", ROOT / "ida_preprocessor_scripts/find-R_GLStudioDrawPoints.py"
)
FINDER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(FINDER)

TABLE = 0x8000
WRAPPER = 0x1000
DRAW = 0x2000
ATI_DRAW = 0x3000
SKIN = 0x4000
EXTRA = 0x5000
GL_PN_TRIANGLES_ATI = 0x87F0


def walk(*, ati_marker=True, ati_more_calls=True, draw_calls_skin=True, single=False):
    # The faulty call-count heuristic chooses ATI_DRAW when it has one extra
    # helper, as in the real HL 3266 engine. Both branches call StudioSetupSkin.
    bodies = {
        WRAPPER: [("call", DRAW)] + ([] if single else [("call", ATI_DRAW)]),
        DRAW: [("call", SKIN)] if draw_calls_skin else [],
        ATI_DRAW: [("push", GL_PN_TRIANGLES_ATI)] if ati_marker else [],
        SKIN: [("ret", 0)],
        EXTRA: [("ret", 0)],
    }
    bodies[ATI_DRAW].append(("call", SKIN))
    bodies[ATI_DRAW if ati_more_calls else DRAW].append(("call", EXTRA))
    sizes = {ea: (32 if ea == WRAPPER else 1000) for ea in bodies}
    instructions = {ea + i * 5: insn for ea, body in bodies.items() for i, insn in enumerate(body)}
    table = bytearray(46 * 4)
    slots = {6: 0x6000, 35: 0x6100, 36: 0x6200, 39: 0x6300, 25: WRAPPER, 29: SKIN}
    for slot, value in slots.items():
        table[slot * 4 : slot * 4 + 4] = value.to_bytes(4, "little")

    def get_func(ea):
        for start, size in sizes.items():
            if start <= ea < start + size:
                return SimpleNamespace(start_ea=start, end_ea=start + size)
        return None

    segment = SimpleNamespace(start_ea=TABLE, end_ea=TABLE + len(table))
    modules = {
        "ida_funcs": SimpleNamespace(get_func=get_func),
        "idautils": SimpleNamespace(FuncItems=lambda ea: [ea + i * 5 for i in range(len(bodies[ea]))]),
        "ida_segment": SimpleNamespace(
            get_segm_qty=lambda: 1, getnseg=lambda _: segment, get_segm_name=lambda _: ".data"
        ),
        "ida_bytes": SimpleNamespace(
            get_bytes=lambda ea, size: bytes(table),
            get_dword=lambda ea: int.from_bytes(table[ea - TABLE : ea - TABLE + 4], "little"),
        ),
        "idc": SimpleNamespace(
            o_imm=5,
            print_insn_mnem=lambda ea: instructions[ea][0],
            get_operand_value=lambda ea, index: instructions[ea][1] if index == 0 else 0,
            get_operand_type=lambda ea, index: 5 if index == 0 and instructions[ea][0] == "push" else 0,
            print_operand=lambda ea, index: str(instructions[ea][1]) if index == 0 else "",
        ),
    }
    anchors = {slot: slots[slot] for slot in (6, 35, 36, 39)}
    anchors["primary"] = slots[6]
    code = (
        FINDER.WALK.replace("@@MARKER@@", repr(FINDER.MARKER))
        .replace("@@ANCHORS@@", repr(anchors))
        .replace("@@DRAW_SLOT@@", "25")
        .replace("@@SKIN_SLOT@@", "29")
    )
    output = io.StringIO()
    with patch.dict("sys.modules", modules), contextlib.redirect_stdout(output):
        exec(code, {})
    payload = json.loads(output.getvalue().split(FINDER.MARKER, 1)[1])
    return [entry for entry in payload["entries"] if "error" not in entry and entry.get("cand_calls_skin")]


class StudioDrawPointsTests(unittest.TestCase):
    def test_ati_branch_with_more_callees_is_not_selected(self):
        self.assertEqual(hex(DRAW), walk()[0]["R_GLStudioDrawPoints"])

    def test_branch_selection_does_not_depend_on_callee_count(self):
        self.assertEqual(hex(DRAW), walk(ati_more_calls=False)[0]["R_GLStudioDrawPoints"])

    def test_ambiguous_two_branch_wrapper_is_rejected(self):
        self.assertEqual([], walk(ati_marker=False))

    def test_missing_skin_call_is_rejected(self):
        self.assertEqual([], walk(draw_calls_skin=False))

    def test_pre_ati_single_branch_still_resolves(self):
        self.assertEqual(hex(DRAW), walk(single=True)[0]["R_GLStudioDrawPoints"])


if __name__ == "__main__":
    unittest.main()
