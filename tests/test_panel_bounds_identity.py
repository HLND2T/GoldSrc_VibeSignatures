import ast
import copy
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

from ida_preprocessor_scripts._panel_bounds_identity import (
    bounds_body_matches,
    bounds_constants,
    bounds_forwarder,
    bounds_scaled_constants,
    calls_reached_after,
    constructor_receivers,
    constructor_vtable,
)
from ida_preprocessor_scripts._x86_vcall_flow import trace_function
from ida_preprocessor_scripts import _panel_bounds_callsites_common as producer
from ida_preprocessor_scripts._panel_bounds_collect import COLLECT


class PanelBoundsIdentityTests(unittest.TestCase):
    def test_cleanup_impact_includes_unclassified_sites_but_not_earlier_or_other_paths(self):
        flow = dict(blocks={1: [2, 3], 2: [4], 3: [], 4: []})
        call = dict(ea=20, block=2)
        targets = [
            dict(ea=10, block=2, stack_args=[None]),
            dict(ea=30, block=2, stack_args=[None]),
            dict(ea=40, block=3),
            dict(ea=50, block=4),
        ]
        self.assertEqual({30, 50}, calls_reached_after(flow, call, targets))

    def call(self, ea, target, receiver, *args, platform="windows"):
        return dict(
            ea=ea, direct=target, this=receiver, stack_args=list(args) if platform == "windows" else [receiver, *args]
        )

    def test_four_constants_on_both_abis(self):
        for platform in ("windows", "linux"):
            call = self.call(30, 900, None, *(("const", n) for n in (0, 0, 372, 160)), platform=platform)
            self.assertEqual((0, 0, 372, 160), bounds_constants(call, {}, platform))

    def test_constructor_requires_same_returned_object_and_unavoidable_vptr_store(self):
        flow = dict(
            start=1,
            blocks={1: [2], 2: []},
            returns=[dict(value=("arg", 0))],
            stores=[dict(address=("arg", 0), value=("const", 4096), width=4, block=2)],
        )
        self.assertEqual(4096, constructor_vtable(flow))
        flow["blocks"] = {1: [2, 3], 2: [], 3: []}
        self.assertIsNone(constructor_vtable(flow))
        flow["blocks"] = {1: [2], 2: []}
        flow["returns"][0]["value"] = ("arg", 1)
        self.assertIsNone(constructor_vtable(flow))

    def test_constructed_receiver_needs_matching_vtable_load(self):
        recv = ("choice", ("const", 0), ("result", 10))
        calls = {10: dict(direct=800)}
        table = ("choice", ("stack", -24), ("load", ("result", 10), 0))
        self.assertEqual({800}, constructor_receivers(recv, table, calls))
        self.assertIsNone(constructor_receivers(("arg", 0), table, calls))
        self.assertIsNone(constructor_receivers(recv, ("load", ("result", 11), 0), calls))
        self.assertIsNone(constructor_receivers(("const", 0), table, calls))

    def test_reject_variable_or_ambiguous_in_each_position(self):
        for index in range(4):
            for value in (None, ("arg", 1), ("choice", ("const", 1), ("const", 2))):
                args = [("const", n) for n in (0, 0, 372, 160)]
                args[index] = value
                call = self.call(30, 900, ("arg", 0), *args)
                self.assertIsNone(bounds_constants(call, {}, "windows"))

    def test_scaled_constants_with_zero_coordinates_on_both_abis(self):
        for platform in ("windows", "linux"):
            recv = ("arg", 0)
            calls = {
                ea: self.call(ea, 800, recv, ("const", n), platform=platform)
                for ea, n in ((10, 20), (11, 30), (12, 372), (13, 160))
            }
            for coords in (
                (("const", 0), ("const", 0)),
                (("result", 10), ("result", 11)),
                (("const", 0), ("result", 11)),
            ):
                call = self.call(20, 900, recv, *coords, ("result", 12), ("result", 13), platform=platform)
                expected = (0 if coords[0][0] == "const" else 20, 0 if coords[1][0] == "const" else 30, 372, 160)
                self.assertEqual(expected, bounds_scaled_constants(call, calls, platform, 800))
                self.assertIsNone(bounds_constants(call, calls, platform))

    def test_scaled_rejects_mixed_units_wrong_receiver_and_modified_results(self):
        receiver = ("arg", 0)
        calls = {10: self.call(10, 800, receiver, ("const", 20))}
        args = [("const", 0), ("const", 0), ("result", 10), ("result", 10)]
        for index, value in (
            (0, ("const", 1)),
            (1, ("arg", 2)),
            (2, ("const", 20)),
            (3, ("address", ("result", 10), 8)),
            (3, None),
        ):
            changed = list(args)
            changed[index] = value
            call = self.call(20, 900, receiver, *changed)
            self.assertIsNone(bounds_scaled_constants(call, calls, "windows", 800))
        for wrong in (None, ("arg", 1), ("choice", ("arg", 0), ("arg", 1))):
            call = self.call(20, 900, wrong, *args)
            self.assertIsNone(bounds_scaled_constants(call, calls, "windows", 800))
        call = self.call(20, 900, receiver, *args)
        self.assertIsNone(bounds_scaled_constants(call, calls, "windows", 801))
        self.assertIsNone(bounds_scaled_constants(call, calls, "windows", None))

    def test_exact_forwarding_order_and_receiver(self):
        operations = [("pos", ("arg", 0), ("arg", 1), ("arg", 2)), ("size", ("arg", 0), ("arg", 3), ("arg", 4))]
        self.assertTrue(bounds_forwarder(operations))
        self.assertFalse(bounds_forwarder(operations[::-1]))
        self.assertFalse(bounds_forwarder(operations + operations[:1]))
        self.assertFalse(bounds_forwarder(operations[:1]))
        for index in range(2):
            altered = list(operations)
            altered[index] = (operations[index][0], ("arg", 5), *operations[index][2:])
            self.assertFalse(bounds_forwarder(altered))
            altered[index] = (*operations[index][:2], ("const", 0), operations[index][3])
            self.assertFalse(bounds_forwarder(altered))

    def direct_flow(self, platform):
        calls = [
            self.call(10, 100, ("arg", 0), ("arg", 1), ("arg", 2), platform=platform),
            self.call(20, 200, ("arg", 0), ("arg", 3), ("arg", 4), platform=platform),
        ]
        for call in calls:
            call.update(block=1, target=("const", call["direct"]))
        return dict(calls=calls, stores=[], blocks={1: []})

    def matches(self, flow, platform="windows"):
        return bounds_body_matches(flow, platform, 1, 300, 12, 32, 40, 48, {100}, {200})

    def test_direct_forwarder_on_both_abis(self):
        for platform in ("windows", "linux"):
            self.assertTrue(self.matches(self.direct_flow(platform), platform))

    def test_reject_extra_calls_and_side_effect_stores(self):
        flow = self.direct_flow("windows")
        flow["calls"].append(dict(ea=30, direct=999, target=("const", 999), this=None, stack_args=[], block=1))
        self.assertFalse(self.matches(flow))
        flow = self.direct_flow("windows")
        flow["stores"] = [dict(address=("load", ("arg", 0), 24))]
        self.assertFalse(self.matches(flow))
        flow["stores"] = [dict(address=("stack", -4))]
        self.assertTrue(self.matches(flow))

    def test_reject_a_path_that_bypasses_either_setter(self):
        flow = self.direct_flow("windows")
        flow["blocks"] = {1: [2, 3], 2: [3], 3: []}
        for bypassed in range(2):
            for i, c in enumerate(flow["calls"]):
                c["block"] = 2 if i == bypassed else 1
            self.assertFalse(self.matches(flow))
        flow["blocks"] = {1: [2], 2: [3], 3: []}
        self.assertTrue(self.matches(flow))

    def test_inlined_dispatch_and_devirtualized_getvpanel_on_both_abis(self):
        for platform in ("windows", "linux"):
            calls = []
            for ea, slot, param in ((10, 40, 1), (30, 48, 3)):
                getter = self.call(ea, 300, None, platform=platform)
                getvp = self.call(ea + 1, None, ("arg", 0), platform=platform)
                getvp["target"] = ("load", ("load", ("arg", 0), 0), 12)
                receiver = ("result", ea)
                vp = ("choice", ("load", ("arg", 0), 32), ("result", ea + 1))
                setter = self.call(ea + 2, None, receiver, vp, ("arg", param), ("arg", param + 1), platform=platform)
                setter["target"] = ("load", ("load", receiver, 0), slot)
                calls.extend([getter, getvp, setter])
            for call in calls:
                call["block"] = 1
            flow = dict(calls=calls, stores=[], blocks={1: []})
            self.assertTrue(self.matches(flow, platform))
            wrong = copy.deepcopy(flow)
            wrong["calls"][2]["stack_args"][0 if platform == "windows" else 1] = ("load", ("arg", 1), 32)
            self.assertFalse(self.matches(wrong, platform))
            wrong = copy.deepcopy(flow)
            wrong["calls"][2]["target"] = ("load", ("load", ("result", 10), 0), 52)
            self.assertFalse(self.matches(wrong, platform))

    def test_linux_stack_arguments_and_variable_coordinate(self):
        def insn(ea, mnem, *ops, **kwargs):
            return dict(ea=ea, mnem=mnem, ops=list(ops), sp=-24, after=-24, **kwargs)

        def mem(offset):
            return ("mem", "esp", offset, None, 1)

        code = [insn(1, "mov", mem(0), ("reg", "esi"))]
        code += [insn(2 + i, "mov", mem(4 * (i + 1)), ("imm", n)) for i, n in enumerate((0, 0, 372, 160))]
        code.append(insn(6, "call", ("imm", 900), direct=900))
        flow = trace_function([dict(start=1, succs=[], insns=code)], 1, "linux")
        self.assertEqual((0, 0, 372, 160), bounds_constants(flow["calls"][0], {}, "linux"))
        code[1] = insn(2, "mov", mem(4), ("reg", "edi"))
        flow = trace_function([dict(start=1, succs=[], insns=code)], 1, "linux")
        self.assertIsNone(bounds_constants(flow["calls"][0], {}, "linux"))

    def test_verified_cleanup_keeps_eh_state_out_of_outgoing_arguments(self):
        def insn(ea, mnemonic, sp, after, *ops, **extra):
            return dict(ea=ea, mnem=mnemonic, sp=sp, after=after, ops=list(ops), **extra)

        code = [insn(1, "call", -148, -12, ("reg", "eax"))]
        code += [insn(2 + i, "push", -12 - 4 * i, -16 - 4 * i, ("imm", n)) for i, n in enumerate((20, 20, 0, 0))]
        code += [
            insn(6, "mov", -28, -28, ("mem", "ebp", -4, None, 1, 1), ("imm", 2)),
            insn(7, "call", -28, -12, ("imm", 900), direct=900),
        ]
        entry = {"ebp": ("stack", -12)}
        blocks = [dict(start=1, succs=[], insns=code)]
        bad = trace_function(blocks, 1, "windows", entry_state=entry)
        self.assertEqual((0, 0, 20, 2), bounds_constants(bad["calls"][-1], {}, "windows"))
        code[0]["purge"] = 4
        good = trace_function(blocks, 1, "windows", entry_state=entry)
        self.assertEqual((0, 0, 20, 20), bounds_constants(good["calls"][-1], {}, "windows"))
        code[1]["ops"] = [("reg", "edi")]
        good = trace_function(blocks, 1, "windows", entry_state=entry)
        self.assertIsNone(bounds_constants(good["calls"][-1], {}, "windows"))


class PanelBoundsOutputTests(unittest.IsolatedAsyncioTestCase):
    async def test_mode_counts_and_signatures_are_checked_before_writing(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "vgui2_Panel_Init.windows.yaml").write_text(
                "func_name: vgui2::Panel::Init(int, int, int, int)\nfunc_va: '0x1000'\n"
            )
            outputs = [
                root / f"vgui2_Panel_SetBounds_{mode}_callsite_0.windows.yaml" for mode in ("Const", "ScaledConst")
            ]
            found = dict(
                method="0x1100", sites=[dict(ea="0x1010", mode="Const"), dict(ea="0x1020", mode="ScaledConst")]
            )
            signatures = dict(
                sites=[
                    dict(ea=0x1010, patch_sig="E8 01", patch_sig_disp=0),
                    dict(ea=0x1020, patch_sig="E8 02", patch_sig_disp=0),
                ]
            )
            with (
                patch.object(producer, "discover_bounds_callsites", AsyncMock(return_value=found)),
                patch.object(producer, "generate_callsite_signatures", AsyncMock(return_value=signatures)),
                patch.object(producer, "_find_unique_bytes", AsyncMock(side_effect=[0x1010, None])),
            ):
                with self.assertRaisesRegex(ValueError, "Non-unique"):
                    await producer.preprocess_bounds_callsites(None, outputs, root, "windows", 0x1000)
                self.assertTrue(all(not output.exists() for output in outputs))
            with (
                patch.object(producer, "discover_bounds_callsites", AsyncMock(return_value=found)),
                patch.object(producer, "generate_callsite_signatures", AsyncMock(return_value=signatures)),
                patch.object(producer, "_find_unique_bytes", AsyncMock(side_effect=[0x1010, 0x1020])),
            ):
                self.assertTrue(await producer.preprocess_bounds_callsites(None, outputs, root, "windows", 0x1000))
            with (
                patch.object(producer, "discover_bounds_callsites", AsyncMock(return_value=found)),
                patch.object(producer, "generate_callsite_signatures", AsyncMock()) as sign,
            ):
                with self.assertRaisesRegex(ValueError, "ScaledConst: found 1 sites, declared 0"):
                    await producer.preprocess_bounds_callsites(None, outputs[:1], root, "windows", 0x1000)
                sign.assert_not_awaited()


class PanelBoundsCleanupTests(unittest.TestCase):
    def test_unresolved_cleanup_quarantines_only_downstream_calls_even_when_arguments_are_unknown(self):
        # Execute the actual worker functions with a synthetic IDA adapter. No
        # script layout or text is asserted; this covers the orchestration path.
        functions = [node for node in ast.parse(COLLECT).body if isinstance(node, ast.FunctionDef)]
        before = dict(ea=10, block=1, direct=900, tail=False)
        unknown = dict(ea=20, block=1, direct=None, tail=False)
        after = dict(ea=30, block=1, direct=900, tail=False, stack_args=[None] * 4)
        flow = dict(calls=[before, unknown, after], blocks={1: []})
        namespace = dict(
            platform="windows",
            target=900,
            MAX_ARGUMENTS=8,
            WORD_SIZE=4,
            unproven_cleanup=[],
            flow_at=lambda *args, **kwargs: flow,
            call_map=lambda f: {c["ea"]: c for c in f["calls"]},
            calls_reached_after=calls_reached_after,
            ida_funcs=SimpleNamespace(get_func=lambda owner: owner),
            idautils=SimpleNamespace(
                FuncItems=lambda owner: [20], DecodeInstruction=lambda ea: SimpleNamespace(ops=[None])
            ),
            idc=SimpleNamespace(print_insn_mnem=lambda ea: "call"),
            ida_frame=SimpleNamespace(get_spd=lambda f, ea: 100 if ea == 21 else 0),
            ida_bytes=SimpleNamespace(get_item_size=lambda ea: 1),
            decoded_operand=lambda operand: ("imm", 100),
        )
        exec(compile(ast.Module(body=functions, type_ignores=[]), "<bounds-worker-test>", "exec"), namespace)
        actual, unsafe = namespace["bounds_caller_flow"](1, {})
        self.assertIs(flow, actual)
        self.assertEqual({30}, unsafe)
        self.assertEqual(["0x1e"], namespace["unproven_cleanup"][0]["excluded"])


if __name__ == "__main__":
    unittest.main()
