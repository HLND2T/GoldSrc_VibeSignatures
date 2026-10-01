import ast
import builtins
import unittest
import sys
from types import SimpleNamespace
from unittest.mock import patch

from ida_preprocessor_scripts._x86_vcall_flow import trace_function, virtual_targets
from ida_preprocessor_scripts import _engine_private_globals_common as common
from ida_preprocessor_scripts._vgui_paint_common import IDA_FLOW
from ida_preprocessor_scripts import _vgui_private_symbols_common as private_symbols
from ida_analyze_util import _INSPECT_FUNCTION_PY_EVAL_TEMPLATE, _inspect_function_via_mcp


def instruction(ea, mnemonic, *operands, sp=0, after=None, **extra):
    return dict(ea=ea, mnem=mnemonic, ops=list(operands), sp=sp, after=sp if after is None else after, **extra)


def reg(name):
    return ("reg", name)


def imm(value):
    return ("imm", value)


def mem(base, offset=0):
    return ("mem", base, offset, None, 1)


class StagedPrivateWalkTests(unittest.IsolatedAsyncioTestCase):
    async def test_stages_share_exact_objects_and_release_worker_state(self):
        async def execute(session, body, values):
            namespace = {"values": values}
            try:
                exec(body, namespace)
                return namespace["result"]
            except Exception as exc:
                return {"error": str(exc)}

        existing = {key for key in vars(builtins) if key.startswith("_vgui_private_")}
        with patch.object(private_symbols, "walk", side_effect=execute):
            result = await private_symbols.walk_stages(
                None,
                [
                    "items = [values['number']]\noriginal = items",
                    "items.append(2)\nassert original is items",
                    "result = {'total': sum(items)}",
                ],
                {"number": 40},
            )
            self.assertEqual({"total": 42}, result)
            with self.assertRaisesRegex(ValueError, "failed registration"):
                await private_symbols.walk_stages(None, ["items = []", "raise ValueError('failed registration')"], {})
        self.assertEqual(existing, {key for key in vars(builtins) if key.startswith("_vgui_private_")})


class VcallFlowTests(unittest.TestCase):
    def test_simd_registration_zero_and_copy_preserve_each_word(self):
        vector = ("reg", "xmm0", 16)
        source = ("mem", "esp", -32, None, 1, 16)
        destination = ("mem", "ecx", 0, None, 1, 16)
        code = [
            instruction(1, "xorps", vector, vector),
            instruction(2, "movaps", source, vector),
            instruction(3, "movups", vector, source),
            instruction(4, "movups", destination, vector),
        ]
        flow = trace_function([dict(start=1, succs=[], insns=code)], 1, "windows", capture_stack=True)
        copied = [s for s in flow["stores"] if s.get("copy_source")]
        self.assertEqual([("stack", offset) for offset in (-32, -28, -24, -20)], [s["copy_source"] for s in copied])
        self.assertEqual([("const", 0)] * 4, [s["value"] for s in copied])
        self.assertEqual([4] * 4, [s["width"] for s in copied])
        code.insert(3, instruction(35, "call", imm(100), direct=100))
        flow = trace_function([dict(start=1, succs=[], insns=code)], 1, "windows", capture_stack=True)
        self.assertFalse(any(s.get("copy_source") for s in flow["stores"]))
        self.assertEqual([None] * 4, [s["value"] for s in flow["stores"] if s["ea"] == 4])

    def test_switch_decrements_preserve_zero_one_two_selector_provenance(self):
        blocks = [
            dict(
                start=1,
                succs=[10, 20],
                insns=[
                    instruction(1, "mov", reg("eax"), mem("ecx", 0x34)),
                    instruction(2, "sub", reg("eax"), imm(0)),
                    instruction(3, "jz", imm(20), branch=20),
                ],
            ),
            dict(
                start=10,
                succs=[30, 40],
                insns=[instruction(10, "dec", reg("eax")), instruction(11, "jz", imm(30), branch=30)],
            ),
            dict(
                start=40,
                succs=[50, 60],
                insns=[instruction(40, "dec", reg("eax")), instruction(41, "jnz", imm(50), branch=50)],
            ),
            *[dict(start=ea, succs=[], insns=[instruction(ea, "ret")]) for ea in (20, 30, 50, 60)],
        ]
        condition = ("load", ("arg", 0), 0x34)
        self.assertEqual(
            [condition, ("address", condition, -1), ("address", condition, -2)],
            [b["condition"] for b in trace_function(blocks, 1, "windows", arithmetic_conditions=True)["branches"]],
        )
        self.assertEqual([], trace_function(blocks, 1, "windows")["branches"])

    def test_registration_snapshots_capture_the_record_at_consumption(self):
        code = [
            instruction(1, "mov", mem("esp", -40), imm(0xA000)),
            instruction(2, "mov", mem("esp", -24), imm(0xB000)),
            instruction(3, "lea", reg("esi"), mem("esp", -40)),
            instruction(4, "mov", reg("edi"), reg("ecx")),
            instruction(5, "mov", reg("ecx"), imm(12)),
            instruction(6, "movsd", copy_width=4),
            instruction(7, "call", imm(100), direct=100),
        ]
        blocks = [dict(start=1, succs=[], insns=code)]
        flow = trace_function(blocks, 1, "windows", capture_stack=True)
        copied = next(s for s in flow["stores"] if s.get("copy"))
        self.assertEqual(("stack", -40), copied["value"])
        self.assertEqual(("arg", 0), copied["address"])
        self.assertEqual(("const", 12), copied["count"])
        self.assertEqual(("const", 0xB000), copied["stack_values"][-24])
        self.assertNotIn("stack_values", trace_function(blocks, 1, "windows")["calls"][0])

    def test_registration_memory_join_preserves_original_and_reallocated_storage(self):
        blocks = [
            dict(start=1, succs=[10, 20], insns=[instruction(1, "mov", reg("esi"), reg("ecx"))]),
            dict(start=10, succs=[30], insns=[instruction(10, "mov", mem("esi"), imm(0xA000))]),
            dict(start=20, succs=[30], insns=[]),
            dict(start=30, succs=[], insns=[instruction(30, "mov", reg("eax"), mem("esi")), instruction(31, "ret")]),
        ]
        flow = trace_function(blocks, 1, "windows", track_memory=True)
        self.assertEqual(("choice", ("const", 0xA000), ("load", ("arg", 0), 0)), flow["returns"][0]["value"])
        self.assertIsNone(trace_function(blocks, 1, "windows")["returns"][0]["value"])

    def test_registration_pointer_sum_is_separate_from_indexed_getter_support(self):
        code = [
            instruction(1, "mov", reg("eax"), mem("ecx")),
            instruction(2, "add", reg("eax"), reg("edx")),
            instruction(3, "ret"),
        ]
        blocks = [dict(start=1, succs=[], insns=code)]
        self.assertIsNone(trace_function(blocks, 1, "windows", symbolic_indices=True)["returns"][0]["value"])
        self.assertEqual(
            ("indexed", ("load", ("arg", 0), 0), None, 1),
            trace_function(blocks, 1, "windows", symbolic_sums=True)["returns"][0]["value"],
        )

    def test_verified_constant_return_is_used_without_erasing_the_call(self):
        code = [instruction(1, "call", imm(100), direct=100, return_value=("const", 0xA000)), instruction(2, "ret")]
        flow = trace_function([dict(start=1, succs=[], insns=code)], 1, "windows")
        self.assertEqual(("const", 0xA000), flow["returns"][0]["value"])
        self.assertEqual(100, flow["calls"][0]["direct"])

    def test_verified_preserving_call_keeps_business_result_and_stack(self):
        code = [
            instruction(1, "call", imm(100), direct=100),
            instruction(2, "push", reg("eax")),
            instruction(3, "call", imm(200), sp=-4, direct=200, preserves_registers=True),
            instruction(4, "push", reg("eax"), sp=-4),
            instruction(5, "call", imm(300), sp=-8, after=0, direct=300),
        ]
        blocks = [dict(start=1, succs=[], insns=code)]
        flow = trace_function(blocks, 1, "windows")
        self.assertEqual([1, 5], [c["ea"] for c in flow["calls"]])
        self.assertEqual([("result", 1), ("result", 1)], flow["calls"][-1]["stack_args"][:2])
        code[2].pop("preserves_registers")
        flow = trace_function(blocks, 1, "windows")
        self.assertEqual([("result", 3), ("result", 1)], flow["calls"][-1]["stack_args"][:2])

    def test_symbolic_container_index_is_opt_in_and_retains_base_and_argument(self):
        code = [
            instruction(1, "mov", reg("eax"), mem("ecx", 0x180)),
            instruction(2, "mov", reg("edx"), mem("esp", 4)),
            instruction(3, "mov", reg("eax"), ("mem", "eax", 0, "edx", 4, 4)),
            instruction(4, "ret"),
        ]
        blocks = [dict(start=1, succs=[], insns=code)]
        self.assertIsNone(trace_function(blocks, 1, "windows")["returns"][0]["value"])
        expected = ("load", ("indexed", ("load", ("arg", 0), 0x180), ("arg", 1), 4), 0)
        self.assertEqual(expected, trace_function(blocks, 1, "windows", symbolic_indices=True)["returns"][0]["value"])

    def test_member_reference_records_lea_and_add_operand_kind(self):
        code = [
            instruction(1, "mov", reg("eax"), reg("ecx")),
            instruction(2, "add", reg("eax"), imm(0x2A0)),
            instruction(3, "lea", reg("edx"), mem("ecx", 0x2A0)),
        ]
        flow = trace_function([dict(start=1, succs=[], insns=code)], 1, "windows")
        self.assertEqual(
            [("immediate", ("address", ("arg", 0), 0x2A0)), ("displacement", ("address", ("arg", 0), 0x2A0))],
            [(r["ref_kind"], r["value"]) for r in flow["addresses"]],
        )

    def test_word_mask_preserves_character_argument_without_preserving_pointer(self):
        code = [
            instruction(1, "mov", reg("eax"), mem("esp", 4)),
            instruction(2, "and", reg("eax"), imm(0xFFFF), writes=["eax"]),
            instruction(3, "cmp", reg("eax"), imm(13)),
            instruction(4, "mov", reg("ecx"), mem("eax")),
            instruction(5, "call", mem("ecx", 20)),
        ]
        flow = trace_function([dict(start=1, succs=[], insns=code)], 1, "windows")
        self.assertEqual([("narrow", ("arg", 1), 2), ("const", 13)], flow["comparisons"][0]["values"])
        self.assertEqual([], virtual_targets(flow["calls"][0]["target"]))

    def test_noncontiguous_mask_does_not_become_a_character_argument(self):
        code = [
            instruction(1, "mov", reg("eax"), mem("esp", 4)),
            instruction(2, "and", reg("eax"), imm(0xFF00), writes=["eax"]),
            instruction(3, "cmp", reg("eax"), imm(13)),
        ]
        flow = trace_function([dict(start=1, succs=[], insns=code)], 1, "windows")
        self.assertIsNone(flow["comparisons"][0]["values"][0])

    def test_reassigning_getter_cleanup_to_consumer_preserves_loop_stack(self):
        blocks = [
            dict(start=1, succs=[10], insns=[instruction(1, "mov", reg("esi"), reg("ecx"))]),
            dict(
                start=10,
                succs=[10, 20],
                insns=[
                    instruction(10, "push", imm(1)),
                    instruction(11, "mov", reg("ecx"), reg("esi"), sp=-4),
                    instruction(12, "mov", reg("eax"), mem("esi"), sp=-4),
                    instruction(13, "call", mem("eax"), sp=-4, after=0, purge=0),
                    instruction(14, "push", reg("eax")),
                    instruction(15, "call", imm(500), sp=-4, after=0, purge=8, direct=500),
                ],
            ),
            dict(start=20, succs=[], insns=[instruction(20, "ret")]),
        ]
        flow = trace_function(blocks, 1, "windows")
        consumer = next(c for c in flow["calls"] if c["ea"] == 15)
        self.assertEqual([("result", 13), ("const", 1)], consumer["stack_args"][:2])

    def test_simd_zero_initialization_preserves_integer_guard_flags(self):
        blocks = [
            dict(
                start=1,
                succs=[10, 20],
                insns=[
                    instruction(1, "cmp", (*mem("esp", 8), 1), imm(0)),
                    instruction(2, "pxor", reg("xmm0"), reg("xmm0"), writes=["xmm0"]),
                    instruction(
                        3, "movdqu", (*mem("esp", -16), 16), reg("xmm0"), memory_writes=[(*mem("esp", -16), 16)]
                    ),
                    instruction(4, "jz", imm(20), branch=20),
                ],
            ),
            dict(start=10, succs=[], insns=[]),
            dict(start=20, succs=[], insns=[]),
        ]
        result = trace_function(blocks, 1, "windows")
        self.assertEqual(("arg", 2), result["branches"][0]["condition"])

    def test_split_body_preserves_verified_register_arguments(self):
        from ida_preprocessor_scripts._x86_vcall_flow import entry_state_from_call

        caller = [
            instruction(1, "mov", reg("eax"), mem("esp", 4)),
            instruction(2, "movzx", reg("edx"), (*mem("esp", 8), 1)),
            instruction(3, "call", imm(100), direct=100),
        ]
        call = trace_function([dict(start=1, succs=[], insns=caller)], 1, "linux")["calls"][0]
        body = [
            instruction(100, "mov", reg("esi"), reg("eax")),
            instruction(101, "mov", reg("ecx"), mem("esi", 44)),
            instruction(102, "mov", reg("eax"), mem("ecx")),
            instruction(103, "call", mem("eax", 60)),
        ]
        flow = trace_function(
            [dict(start=100, succs=[], insns=body)], 100, "linux", entry_state=entry_state_from_call(call)
        )
        self.assertEqual([(("load", ("arg", 0), 44), 60)], virtual_targets(flow["calls"][0]["target"]))
        self.assertEqual(("address", ("arg", 0), 44), flow["loads"][0]["address"])

    def test_split_body_cannot_invent_default_arguments_or_alias_caller_stack(self):
        from ida_preprocessor_scripts._x86_vcall_flow import entry_state_from_call

        call = {"ea": 10, "registers": {"eax": None}, "stack_args": [("stack", 4), None]}
        body = [
            instruction(100, "mov", reg("ecx"), mem("esp", 4)),
            instruction(101, "mov", reg("eax"), mem("ecx")),
            instruction(102, "mov", reg("edx"), mem("esp", 8)),
            instruction(103, "ret"),
        ]
        flow = trace_function(
            [dict(start=100, succs=[], insns=body)], 100, "linux", entry_state=entry_state_from_call(call)
        )
        self.assertEqual(("load", ("caller_stack", 10, 4), 0), flow["returns"][0]["value"])
        self.assertIsNone(flow["loads"][2]["value"])

    def test_verified_callee_cleanup_preserves_prepushed_byte_arguments(self):
        code = [
            instruction(1, "mov", reg("esi"), reg("ecx")),
            instruction(2, "mov", ("reg", "eax", 1), (*mem("esp", 12), 1)),
            instruction(3, "push", reg("eax")),
            instruction(4, "mov", ("reg", "ecx", 1), (*mem("esp", 12), 1), sp=-4),
            instruction(5, "push", reg("ecx"), sp=-4),
            instruction(6, "push", mem("esp", 12), sp=-8),
            instruction(7, "mov", reg("ecx"), reg("esi"), sp=-12),
            instruction(8, "mov", reg("eax"), mem("esi"), sp=-12),
            instruction(9, "call", mem("eax", 232), sp=-12, after=0, purge=4),
            instruction(10, "mov", reg("ecx"), reg("eax")),
            instruction(11, "mov", reg("edx"), mem("eax")),
            instruction(12, "call", mem("edx", 12)),
        ]
        calls = trace_function([dict(start=1, succs=[], insns=code)], 1, "windows")["calls"]
        self.assertEqual([("arg", 0), ("arg", 1)], calls[0]["args"])
        self.assertEqual([("arg", 2), ("arg", 3)], calls[1]["stack_args"][:2])
        self.assertEqual([(("result", 9), 12)], virtual_targets(calls[1]["target"]))

    def test_byte_spill_preserves_boolean_but_cannot_become_pointer(self):
        code = [
            instruction(1, "movzx", reg("edx"), (*mem("esp", 4), 1)),
            instruction(2, "mov", (*mem("esp", -9), 1), ("reg", "edx", 1)),
            instruction(3, "movzx", reg("eax"), (*mem("esp", -9), 1)),
            instruction(4, "push", reg("eax")),
            instruction(5, "call", mem("eax", 12), sp=-4, after=0),
        ]
        flow = trace_function([dict(start=1, succs=[], insns=code)], 1, "windows")
        self.assertEqual(("arg", 1), flow["calls"][0]["args"][1])
        self.assertEqual([], virtual_targets(flow["calls"][0]["target"]))

    def test_implicit_multiply_write_invalidates_vtable(self):
        code = [
            instruction(1, "mov", reg("eax"), mem("ecx")),
            instruction(2, "mul", reg("ebx")),
            instruction(3, "call", mem("eax", 12)),
        ]
        flow = trace_function([dict(start=1, succs=[], insns=code)], 1, "windows")
        self.assertEqual([], virtual_targets(flow["calls"][0]["target"]))

    def test_narrow_memory_load_cannot_be_a_vtable_pointer(self):
        code = [instruction(1, "movzx", reg("eax"), (*mem("ecx"), 1)), instruction(2, "call", mem("eax", 12))]
        flow = trace_function([dict(start=1, succs=[], insns=code)], 1, "windows")
        self.assertEqual([], virtual_targets(flow["calls"][0]["target"]))

    def test_windows_tail_call_forwards_stack_parameters(self):
        code = [instruction(1, "mov", reg("eax"), mem("ecx")), instruction(2, "jmp", mem("eax", 12), tail=True)]
        flow = trace_function([dict(start=1, succs=[], insns=code)], 1, "windows")
        self.assertEqual([("arg", 0), ("arg", 1), ("arg", 2)], flow["calls"][0]["args"][:3])

    def test_escaped_stack_slot_is_invalidated_by_call(self):
        code = [
            instruction(1, "lea", reg("eax"), mem("esp", 4)),
            instruction(2, "push", reg("eax")),
            instruction(3, "call", imm(500), sp=-4, after=0),
            instruction(4, "mov", reg("eax"), mem("esp", 4)),
            instruction(5, "ret"),
        ]
        flow = trace_function([dict(start=1, succs=[], insns=code)], 1, "windows")
        self.assertIsNone(flow["returns"][0]["value"])

    def test_member_write_invalidates_reload_provenance(self):
        code = [
            instruction(1, "mov", reg("esi"), reg("ecx")),
            instruction(2, "mov", mem("esi"), imm(0)),
            instruction(3, "mov", reg("eax"), mem("esi")),
            instruction(4, "call", mem("eax", 12)),
        ]
        flow = trace_function([dict(start=1, succs=[], insns=code)], 1, "windows")
        self.assertEqual([], virtual_targets(flow["calls"][0]["target"]))

    def test_windows_receiver_stack_arguments_and_call_cleanup(self):
        code = [
            instruction(1, "mov", reg("esi"), reg("ecx")),
            instruction(2, "push", imm(1)),
            instruction(3, "push", imm(1), sp=-4),
            instruction(4, "push", mem("esp", 12), sp=-8),
            instruction(5, "mov", reg("eax"), mem("esi"), sp=-12),
            instruction(6, "call", mem("eax", 164), sp=-12, after=0),
        ]
        result = trace_function([dict(start=1, succs=[], insns=code)], 1, "windows")
        call = result["calls"][0]
        self.assertEqual([("arg", 0), ("arg", 1), ("const", 1), ("const", 1)], call["args"])
        self.assertEqual([(("arg", 0), 164)], virtual_targets(call["target"]))

    def test_linux_load_then_tail_jump_preserves_forwarded_arguments(self):
        code = [
            instruction(1, "mov", reg("eax"), mem("esp", 4)),
            instruction(2, "mov", reg("edx"), mem("eax")),
            instruction(3, "mov", reg("eax"), mem("edx", 12)),
            instruction(4, "jmp", reg("eax"), tail=True),
        ]
        result = trace_function([dict(start=1, succs=[], insns=code)], 1, "linux")
        call = result["calls"][0]
        self.assertEqual([(("arg", 0), 12)], virtual_targets(call["target"]))
        self.assertEqual([("arg", 0), ("arg", 1), ("arg", 2)], call["args"][:3])

    def test_guard_tracks_virtual_return_in_both_branch_successors(self):
        blocks = [
            dict(
                start=1,
                succs=[10, 20],
                insns=[
                    instruction(1, "mov", reg("eax"), mem("ecx")),
                    instruction(2, "call", mem("eax", 212)),
                    instruction(3, "test", reg("eax"), reg("eax")),
                    instruction(4, "jz", imm(20), branch=20),
                ],
            ),
            dict(start=10, succs=[], insns=[instruction(10, "ret")]),
            dict(start=20, succs=[], insns=[instruction(20, "ret")]),
        ]
        branch = trace_function(blocks, 1, "windows")["branches"][0]
        self.assertEqual(("result", 2), branch["condition"])
        self.assertEqual((20, 10), (branch["zero"], branch["nonzero"]))

    def test_devirtualized_client_paths_merge_without_losing_slot(self):
        blocks = [
            dict(start=1, succs=[10, 20], insns=[instruction(1, "mov", reg("esi"), reg("ecx"))]),
            dict(start=10, succs=[30], insns=[instruction(10, "mov", reg("eax"), mem("esi", 28))]),
            dict(start=20, succs=[30], insns=[instruction(20, "call", imm(500), direct=500)]),
            dict(
                start=30,
                succs=[],
                insns=[
                    instruction(30, "mov", reg("ecx"), reg("eax")),
                    instruction(31, "mov", reg("edx"), mem("eax")),
                    instruction(32, "call", mem("edx", 12)),
                ],
            ),
        ]
        call = next(c for c in trace_function(blocks, 1, "windows")["calls"] if c["ea"] == 32)
        self.assertEqual({12}, {offset for _, offset in virtual_targets(call["target"])})
        self.assertEqual(2, len(virtual_targets(call["target"])))

    def test_pc_thunk_does_not_clobber_existing_argument_registers(self):
        code = [
            instruction(1, "mov", reg("eax"), mem("esp", 8)),
            instruction(2, "call", imm(500), direct=500, pc_reg="ecx", next_ea=7),
            instruction(7, "add", reg("ecx"), imm(93)),
            instruction(8, "lea", reg("edx"), mem("ecx", 20)),
            instruction(9, "cmp", reg("eax"), reg("edx")),
        ]
        result = trace_function([dict(start=1, succs=[], insns=code)], 1, "linux")
        self.assertEqual([("arg", 1), ("const", 120)], result["comparisons"][0]["values"])
        self.assertEqual([], result["calls"])

    def test_unknown_register_write_cannot_reuse_stale_vtable(self):
        code = [
            instruction(1, "mov", reg("eax"), mem("ecx")),
            instruction(2, "mystery", reg("eax"), writes=["eax"]),
            instruction(3, "call", mem("eax", 12)),
        ]
        call = trace_function([dict(start=1, succs=[], insns=code)], 1, "windows")["calls"][0]
        self.assertEqual([], virtual_targets(call["target"]))

    def test_loop_index_becomes_unknown_but_interface_receiver_survives(self):
        blocks = [
            dict(
                start=1,
                succs=[10],
                insns=[instruction(1, "mov", reg("esi"), reg("ecx")), instruction(2, "xor", reg("ebx"), reg("ebx"))],
            ),
            dict(start=10, succs=[10, 20], insns=[instruction(10, "inc", reg("ebx"), writes=["ebx"])]),
            dict(
                start=20,
                succs=[],
                insns=[instruction(20, "mov", reg("eax"), mem("esi")), instruction(21, "call", mem("eax", 12))],
            ),
        ]
        call = trace_function(blocks, 1, "windows")["calls"][0]
        self.assertEqual([(("arg", 0), 12)], virtual_targets(call["target"]))

    def test_flag_write_invalidates_earlier_zero_test(self):
        blocks = [
            dict(
                start=1,
                succs=[10, 20],
                insns=[
                    instruction(1, "test", reg("ecx"), reg("ecx")),
                    instruction(2, "add", reg("ebx"), imm(1)),
                    instruction(3, "jz", imm(20), branch=20),
                ],
            ),
            dict(start=10, succs=[], insns=[]),
            dict(start=20, succs=[], insns=[]),
        ]
        self.assertEqual([], trace_function(blocks, 1, "windows")["branches"])

    def test_unknown_stack_write_invalidates_saved_argument(self):
        code = [
            instruction(1, "push", imm(1)),
            instruction(2, "mystery", mem("esp"), sp=-4, memory_writes=[mem("esp")]),
            instruction(3, "mov", reg("eax"), mem("ecx"), sp=-4),
            instruction(4, "call", mem("eax", 12), sp=-4, after=0),
        ]
        call = trace_function([dict(start=1, succs=[], insns=code)], 1, "windows")["calls"][0]
        self.assertIsNone(call["args"][1])


class OperandAdapterTests(unittest.TestCase):
    def test_decoder_preserves_width_and_sib_address_components(self):
        api = SimpleNamespace(o_reg=1, o_imm=2, o_near=3, o_mem=4, o_displ=5, o_phrase=6)
        registers = {
            1: ["al", "cl", "dl", "bl", "ah", "ch", "dh", "bh"],
            4: ["eax", "ecx", "edx", "ebx", "esp", "ebp", "esi", "edi"],
        }
        namespace = dict(
            idaapi=api,
            ida_ua=SimpleNamespace(get_dtype_size=lambda dtype: dtype),
            ida_idp=SimpleNamespace(get_reg_name=lambda index, size: registers[size][index]),
            reg4=lambda op: registers[4][op.reg],
            signed32=lambda value: value if value < 2**31 else value - 2**32,
        )
        with patch.dict(sys.modules, ida_frame=SimpleNamespace(), ida_gdl=SimpleNamespace()):
            exec(IDA_FLOW, namespace)
        decode = namespace["decoded_operand"]
        self.assertEqual(("reg", "eax", 1), decode(SimpleNamespace(type=1, reg=0, dtype=1)))
        self.assertEqual(
            ("mem", "esp", -4, "ecx", 4, 1),
            decode(SimpleNamespace(type=5, reg=4, dtype=1, addr=0xFFFFFFFC, specflag1=1, specflag2=0x8C)),
        )


class WalkTransportTests(unittest.IsolatedAsyncioTestCase):
    def test_extended_signature_budget_stays_within_body_and_masks_calls(self):
        tree = ast.parse(_INSPECT_FUNCTION_PY_EVAL_TEMPLATE)
        signature_function = next(
            node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == "_signature"
        )
        ua = SimpleNamespace(insn_t=lambda: SimpleNamespace(ops=[]), decode_insn=lambda insn, ea: 5)
        namespace = dict(
            allow_across_function_boundary=False,
            signature_byte_limit=512,
            ida_segment=SimpleNamespace(getseg=lambda ea: SimpleNamespace(start_ea=0)),
            ida_bytes=SimpleNamespace(
                get_full_flags=lambda ea: 1,
                is_code=lambda flags: True,
                is_head=lambda flags: True,
                get_bytes=lambda ea, size: b"\xe8\x11\x22\x33\x44",
            ),
            ida_ua=ua,
            _is_same_exec_segment=lambda ea, start: True,
        )
        exec(compile(ast.Module(body=[signature_function], type_ignores=[]), "<signature>", "exec"), namespace)
        tokens = namespace["_signature"](0, 400).split()
        self.assertEqual(400, len(tokens))
        self.assertEqual(["E8", "??", "??", "??", "??"], tokens[:5])
        namespace["signature_byte_limit"] = None
        self.assertLess(len(namespace["_signature"](0, 400).split()), 400)

    async def test_extended_signature_still_requires_unique_entry(self):
        class Session:
            async def call_tool(self, name, arguments):
                if name == "py_eval":
                    return {
                        "pointer_size": 4,
                        "function": dict(func_va="0x1000", func_rva="0x1000", func_size="0x500", func_sig="90 90"),
                    }
                return [{"matches": ["0x1000", "0x2000"], "n": 2}]

        self.assertIsNone(await _inspect_function_via_mcp(Session(), 0x1000, 0, "Synthetic", signature_byte_limit=512))
        with self.assertRaises(ValueError):
            await _inspect_function_via_mcp(Session(), 0x1000, 0, "Synthetic", signature_byte_limit=0)

    async def test_large_walk_result_uses_py_eval_structured_result(self):
        class Session:
            async def call_tool(self, name, arguments):
                namespace = {}
                exec(arguments["code"], namespace)
                return SimpleNamespace(structuredContent={"result": namespace.get("result")})

        with patch.object(common, "DECODER", ""):
            result = await common.run_walk(Session(), "result={'payload': 'x'*4096}")
        self.assertEqual({"payload": "x" * 4096}, result)


class RuntimeSlotRoleTests(unittest.TestCase):
    def fixture(self, platform="windows"):
        eng = ["load", ["const", 0x9000], 0]
        video = ["load", ["const", 0xA000], 0]
        game = ["load", ["const", 0xB000], 0]
        shift = int(platform == "windows")

        def call(ea, block, receiver, offset, *args):
            return dict(ea=ea, block=block, virtuals=[[receiver, offset]], args=[receiver, *args])

        def branch(call_ea, zero, nonzero):
            return dict(condition=["result", call_ea], zero=zero, nonzero=nonzero)

        return dict(
            blocks={
                100: [200],
                200: [300, 800],
                300: [400, 710],
                400: [500, 700],
                500: [510, 600],
                510: [500],
                600: [800],
                700: [705],
                705: [800],
                710: [800],
                800: [],
            },
            calls=[
                call(101, 100, eng, 84, ["const", 0]),
                call(201, 200, video, 8, ["arg", shift]),
                call(301, 300, game, 20, ["arg", shift]),
                call(401, 400, eng, 12, ["const", 0], ["arg", shift + 1], ["arg", shift + 2]),
                call(501, 500, eng, 80),
                call(511, 510, eng, 44),
                call(601, 600, game, 24),
                call(602, 600, video, 16),
                call(701, 700, game, 24),
                call(706, 705, game, 24),
                call(707, 705, video, 16),
                call(711, 710, video, 16),
            ],
            branches=[branch(201, 800, 300), branch(301, 710, 400), branch(401, 700, 500), branch(501, 510, 600)],
        )

    def select(self, flow, platform="windows"):
        from ida_preprocessor_scripts._engine_runtime_slots import select_runlistenserver_slots

        return select_runlistenserver_slots(flow, 100, 0x9000, 0xA000, platform)

    def test_roles_follow_control_flow_and_arguments_with_unrelated_slot_numbers(self):
        for platform in ("windows", "linux"):
            with self.subTest(platform=platform):
                result = self.select(self.fixture(platform), platform)
                self.assertEqual(
                    {
                        "IVideoMode_Init": 8,
                        "IGame_Init": 20,
                        "IEngine_Load": 12,
                        "IEngine_SetQuitting": 84,
                        "IEngine_GetQuitting": 80,
                        "IEngine_Frame": 44,
                        "IGame_Shutdown": 24,
                        "IVideoMode_Shutdown": 16,
                    },
                    {name: value["offset"] for name, value in result.items()},
                )
                self.assertEqual([701, 706], result["IGame_Shutdown"]["sites"])

    def test_conflicting_cleanup_slots_fail_closed(self):
        flow = self.fixture()
        next(c for c in flow["calls"] if c["ea"] == 706)["virtuals"][0][1] = 28
        with self.assertRaises(ValueError):
            self.select(flow)

    def test_quitting_initialization_must_dominate_video_initialization(self):
        flow = self.fixture()
        flow["blocks"][100] = [150, 200]
        flow["blocks"][150] = [200]
        flow["calls"][0].update(ea=151, block=150)
        with self.assertRaises(ValueError):
            self.select(flow)

    def test_ambiguous_virtual_receiver_fails_closed(self):
        flow = self.fixture()
        flow["calls"][5]["virtuals"].append([["load", ["const", 0xC000], 0], 44])
        with self.assertRaises(ValueError):
            self.select(flow)

    def test_receiver_argument_must_agree_with_dispatch_object(self):
        flow = self.fixture()
        flow["calls"][5]["args"][0] = ["const", 0xC000]
        with self.assertRaises(ValueError):
            self.select(flow)

    def test_unaligned_virtual_slot_fails_closed(self):
        flow = self.fixture()
        flow["calls"][5]["virtuals"][0][1] = 45
        with self.assertRaises(ValueError):
            self.select(flow)


class FrameSlotRoleTests(unittest.TestCase):
    def fixture(self):
        game = ["load", ["const", 0x9000], 0]
        audio = ["load", ["const", 0xA000], 0]

        def call(ea, block, receiver, offset):
            return dict(ea=ea, block=block, virtuals=[[receiver, offset]], args=[receiver])

        return dict(
            blocks={100: [200, 300], 200: [300], 300: []},
            branches=[dict(condition=["result", 102], zero=200, nonzero=300)],
            calls=[
                call(101, 100, audio, 12),
                call(102, 100, game, 48),
                call(201, 200, game, 28),
                call(301, 300, ["arg", 0], 4),
            ],
        )

    def select(self, flow):
        from ida_preprocessor_scripts._engine_runtime_slots import select_frame_slots

        return select_frame_slots(flow, 100)

    def test_slots_follow_receiver_and_inactive_branch_not_slot_numbers(self):
        result = self.select(self.fixture())
        self.assertEqual(
            {"IGame_IsActiveApp": 48, "IGame_SleepUntilInput": 28, "ICDAudio_Frame": 12},
            {name: role["offset"] for name, role in result.items()},
        )

    def test_sleep_on_active_branch_is_rejected(self):
        flow = self.fixture()
        flow["branches"][0].update(zero=300, nonzero=200)
        with self.assertRaises(ValueError):
            self.select(flow)

    def test_sleep_must_use_the_tested_object(self):
        flow = self.fixture()
        flow["calls"][2]["virtuals"][0][0] = ["load", ["const", 0xB000], 0]
        with self.assertRaises(ValueError):
            self.select(flow)

    def test_actual_receiver_must_match_dispatch(self):
        flow = self.fixture()
        flow["calls"][2]["args"][0] = ["arg", 0]
        with self.assertRaises(ValueError):
            self.select(flow)

    def test_ambiguous_audio_dispatch_is_rejected(self):
        flow = self.fixture()
        flow["calls"].insert(
            0,
            dict(
                ea=100, block=100, virtuals=[[["load", ["const", 0xB000], 0], 8]], args=[["load", ["const", 0xB000], 0]]
            ),
        )
        with self.assertRaises(ValueError):
            self.select(flow)

    def test_audio_must_dominate_the_activity_test(self):
        flow = self.fixture()
        flow["calls"][0].update(ea=202, block=200)
        with self.assertRaises(ValueError):
            self.select(flow)

    def test_unaligned_slot_is_rejected(self):
        flow = self.fixture()
        flow["calls"][2]["virtuals"][0][1] = 29
        with self.assertRaises(ValueError):
            self.select(flow)


class EventSlotRoleTests(unittest.TestCase):
    def fixture(self):
        state = ["load", ["arg", 0], 0x54]
        trapped = ["narrow", ["load", ["arg", 0], 0x24], 1]
        key_field = ["address", ["arg", 0], 0x34]
        buttons_field = ["address", ["arg", 0], 0x40]
        frame = FrameSlotRoleTests().fixture()
        frame["blocks"].update({300: [400, 500], 400: [500], 500: []})
        frame["branches"].append(dict(condition=state, zero=500, nonzero=400, block=300))

        def body(calls=(), returns=(), stores=(), conditions=()):
            return dict(
                calls=list(calls),
                returns=[dict(value=v) for v in returns],
                stores=list(stores),
                branches=[dict(condition=v) for v in conditions],
            )

        def store(address, value):
            return dict(address=address, value=value, width=4)

        engine = {
            2: dict(address=100, flow=frame),
            4: dict(
                address=600,
                flow=body(
                    calls=[dict(direct=0xF000, target=["const", 0xF100])],
                    stores=[store(key_field, ["arg", 1]), store(buttons_field, ["const", 0])],
                    conditions=[trapped],
                ),
            ),
            7: dict(
                address=700,
                flow=body(
                    stores=[store(key_field, ["const", 0]), store(buttons_field, ["arg", 1])], conditions=[trapped]
                ),
            ),
            9: dict(address=800, flow=body(returns=[trapped])),
            3: dict(address=900, flow=body(returns=[state])),
        }
        game = ["load", ["const", 0x9000], 0]
        video = ["load", ["const", 0xD000], 0]
        eng = ["load", ["const", 0xE000], 0]

        def call(ea, block, receiver, offset):
            return dict(ea=ea, block=block, virtuals=[[receiver, offset]], args=[receiver])

        event = dict(
            entry=1000,
            blocks={
                1000: [1100, 1400, 1500],
                1100: [1200, 1300],
                1200: [1300],
                1300: [1000],
                1400: [1300],
                1500: [1300],
            },
            branches=[dict(condition=["result", 1101], block=1100, zero=1300, nonzero=1200)],
            calls=[
                call(1101, 1100, video, 8),
                call(1201, 1200, game, 52),
                call(1202, 1200, video, 48),
                call(1401, 1400, game, 56),
                call(1501, 1500, eng, 12),
            ],
        )
        return engine, event

    def select(self, engine, event, sdl=True):
        from ida_preprocessor_scripts._engine_runtime_slots import select_event_slots

        return select_event_slots(engine, event, 2, 0xF000, 0xE000, 0xD000, 48, sdl=sdl)

    def test_mirrored_fields_and_cyclic_sdl_branch_select_unrelated_slots(self):
        result = self.select(*self.fixture())
        self.assertEqual(
            {
                "IEngine_TrapKey_Event": 16,
                "IEngine_TrapMouse_Event": 28,
                "IEngine_IsTrapping": 36,
                "IEngine_GetState": 12,
                "IVideoMode_IsWindowedMode": 8,
                "IGame_SetWindowXY": 52,
            },
            {name: role["offset"] for name, role in result.items()},
        )

    def test_native_path_requires_one_game_dispatch(self):
        engine, event = self.fixture()
        event["calls"] = [c for c in event["calls"] if c["ea"] != 1401]
        self.assertEqual(52, self.select(engine, event, sdl=False)["IGame_SetWindowXY"]["offset"])

    def test_raw_plt_address_cannot_replace_resolved_callee(self):
        engine, event = self.fixture()
        engine[4]["flow"]["calls"][0]["direct"] = 0xF100
        with self.assertRaises(ValueError):
            self.select(engine, event)

    def test_mouse_method_must_write_the_reciprocal_fields(self):
        engine, event = self.fixture()
        engine[7]["flow"]["stores"][1]["address"] = ["address", ["arg", 0], 0x44]
        with self.assertRaises(ValueError):
            self.select(engine, event)

    def test_ambiguous_state_getter_is_rejected(self):
        engine, event = self.fixture()
        engine[10] = engine[3]
        with self.assertRaises(ValueError):
            self.select(engine, event)

    def test_event_receiver_argument_must_agree(self):
        engine, event = self.fixture()
        event["calls"][1]["args"] = [["arg", 0]]
        with self.assertRaises(ValueError):
            self.select(engine, event)

    def test_window_position_requires_true_branch(self):
        engine, event = self.fixture()
        event["branches"][0].update(zero=1200, nonzero=1300)
        with self.assertRaises(ValueError):
            self.select(engine, event)

    def test_state_slot_must_be_observed_in_event_owner(self):
        engine, event = self.fixture()
        event["calls"] = [c for c in event["calls"] if c["ea"] != 1501]
        with self.assertRaises(ValueError):
            self.select(engine, event)

    def test_getter_with_global_write_is_rejected(self):
        engine, event = self.fixture()
        engine[3]["flow"]["stores"] = [dict(address=["const", 0xF800], value=["const", 1], width=4)]
        with self.assertRaises(ValueError):
            self.select(engine, event)
