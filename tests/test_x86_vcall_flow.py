import ast
import unittest
import sys
from types import SimpleNamespace
from unittest.mock import patch

from ida_preprocessor_scripts._x86_vcall_flow import trace_function, virtual_targets
from ida_preprocessor_scripts import _engine_private_globals_common as common
from ida_preprocessor_scripts._vgui_paint_common import IDA_FLOW
from ida_analyze_util import _INSPECT_FUNCTION_PY_EVAL_TEMPLATE, _inspect_function_via_mcp


def instruction(ea, mnemonic, *operands, sp=0, after=None, **extra):
    return dict(ea=ea, mnem=mnemonic, ops=list(operands), sp=sp, after=sp if after is None else after, **extra)


def reg(name):
    return ("reg", name)


def imm(value):
    return ("imm", value)


def mem(base, offset=0):
    return ("mem", base, offset, None, 1)


class VcallFlowTests(unittest.TestCase):
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
