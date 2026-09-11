from __future__ import annotations

import importlib
import re
import runpy
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

from ida_llm_decompile import (
    LLM_DECOMPILE_RESULT_SECTIONS,
    _build_llm_decompile_request_cache_key,
    _empty_llm_decompile_result,
    _is_transient_llm_error,
    call_llm_decompile,
    parse_llm_decompile_response,
)

CANONICAL_EMPTY = """\
found_vcall: []
found_call: []
found_funcptr: []
found_gv: []
found_struct_offset: []
"""


def scoreinfo_code(*, stride="imul eax, 74h", extra=(), store="mov word_600000[eax], di"):
    instructions = [
        "call sub_700000",  # BEGIN_READ
        "call sub_700100",  # READ_BYTE: player index
        "movzx esi, ax",
        "call sub_700200",  # First READ_SHORT: frags
        "movzx edi, ax",
        "call sub_700200",  # deaths
        "movzx ebx, ax",
        "call sub_700200",  # playerclass
        "mov ebp, eax",
        "call sub_700200",  # teamnumber
        "movsx eax, si",
        *stride.splitlines(),
        "cmp word_60002A[eax], 0",
        "mov word_600002[eax], bx",
        *extra,
        store,
        "ret",
    ]
    return "\n".join(f".text:{0x500000 + index * 0x10:08X} {line}" for index, line in enumerate(instructions))


class ScoreInfoWindowsDataflowTests(unittest.TestCase):
    def rule(self, code, stride=0x74):
        helper = importlib.import_module("ida_preprocessor_scripts._scoreinfo_dataflow")
        return helper.windows_frags_instruction_rule(code, stride)

    def test_selects_first_short_value_not_first_member_access(self):
        rule = self.rule(scoreinfo_code())
        self.assertIsNotNone(rule)
        self.assertIsNotNone(re.fullmatch(rule["regex"], "mov word_600000[eax], di"))
        self.assertIsNone(re.fullmatch(rule["regex"], "cmp word_60002A[eax], 0"))
        self.assertIsNone(re.fullmatch(rule["regex"], "mov word_600002[eax], bx"))

    def test_compiler_stride_forms_and_register_renaming(self):
        cases = (
            (0x74, "lea edx, ds:0[eax*8]\nsub edx, eax\nlea eax, [eax+edx*4]\nshl eax, 2", "eax"),
            (0x1C, "lea ecx, ds:0[eax*8]\nsub ecx, eax", "ecx*4"),
        )
        for stride, calculation, index in cases:
            with self.subTest(stride=stride):
                store = f"mov word_800000[{index}], di"
                code = scoreinfo_code(stride=calculation, store=store)
                renames = {"edi": "ebx", "di": "bx", "ebx": "edi", "bx": "di"}
                code = re.sub(r"\b(?:edi|di|ebx|bx)\b", lambda match: renames[match[0]], code)
                rule = self.rule(code, stride)
                self.assertIsNotNone(rule)
                self.assertIsNotNone(re.fullmatch(rule["regex"], store.replace(", di", ", bx")))

    def test_clobbers_wrong_values_and_biased_indexes_fail_closed(self):
        cases = (
            scoreinfo_code(extra=("xor edi, edi",)),
            scoreinfo_code(extra=("mov di, bx",)),
            scoreinfo_code(extra=("mov edi, eax",)),
            scoreinfo_code(extra=("add eax, 2",)),
            scoreinfo_code(extra=("mov al, 1",)),
            scoreinfo_code(extra=("mov ah, 1",)),
            scoreinfo_code(store="mov word_600000[eax], bx"),
            scoreinfo_code(store="mov dword_600000[eax], edi"),
            scoreinfo_code(stride="imul eax, 78h"),
            scoreinfo_code().replace("call sub_700200", "call eax", 1),
            scoreinfo_code().replace("movzx edi, ax", "movzx ecx, ax").replace(", di", ", cx"),
            scoreinfo_code(extra=("mov [ebp+var_4], edi", "xor edi, edi", "mov edi, [ebp+var_4]")),
        )
        for code in cases:
            with self.subTest(code=code):
                self.assertIsNone(self.rule(code))

    def test_register_copy_is_traced(self):
        rule = self.rule(scoreinfo_code(extra=("mov ecx, edi",), store="mov word_600000[eax], cx"))
        self.assertIsNotNone(rule)

    def test_ambiguous_stores_are_rejected(self):
        self.assertIsNone(self.rule(scoreinfo_code(extra=("mov word_610000[eax], di",))))

    def test_branch_merges_and_loops_cannot_supply_unproven_values(self):
        # The conditional branch can skip a clobber on the path to the same store.
        self.assertIsNone(self.rule(scoreinfo_code(extra=("jz loc_500100", "xor edi, edi"))))
        self.assertIsNone(self.rule(scoreinfo_code(extra=("jmp loc_500000",))))

    def test_player_bounds_branch_preserves_proven_value(self):
        code = scoreinfo_code(extra=("ja loc_500100",))
        self.assertIsNotNone(self.rule(code))


class ScoreInfoInstructionRuleTests(unittest.IsolatedAsyncioTestCase):
    async def test_windows_ambiguous_dataflow_stops_before_llm_and_generation(self):
        finder = runpy.run_path(
            str(
                Path(__file__).resolve().parents[1]
                / "ida_preprocessor_scripts/find-ClientScoreInfoHandler-decompiles.py"
            )
        )
        common = AsyncMock(return_value=True)
        with patch.dict(
            finder["preprocess_skill"].__globals__,
            {
                "preprocess_common_skill": common,
                "_prepare_llm_context": lambda *args: {"targets": [({}, 0x500000)]},
                "_export_llm_function": AsyncMock(
                    return_value={"disasm_code": scoreinfo_code(extra=("mov word_610000[eax], di",))}
                ),
            },
        ):
            result = await finder["preprocess_skill"](
                None, "find-ClientScoreInfoHandler-decompiles", [], {}, ".", "windows", 0
            )
        self.assertFalse(result)
        common.assert_not_called()

    async def test_windows_retries_ci_multi_member_response(self):
        finder = runpy.run_path(
            str(
                Path(__file__).resolve().parents[1]
                / "ida_preprocessor_scripts/find-ClientScoreInfoHandler-decompiles.py"
            )
        )
        code = scoreinfo_code()
        common = AsyncMock(return_value=True)
        with patch.dict(
            finder["preprocess_skill"].__globals__,
            {
                "preprocess_common_skill": common,
                "_prepare_llm_context": lambda *args: {"targets": [({}, 0x500000)]},
                "_export_llm_function": AsyncMock(return_value={"disasm_code": code}),
            },
        ):
            await finder["preprocess_skill"](None, "find-ClientScoreInfoHandler-decompiles", [], {}, ".", "windows", 0)
        spec = common.call_args.kwargs["llm_decompile_specs"][0]

        def response(entries):
            return "found_gv:\n" + "".join(
                f"  - insn_va: '{address}'\n    insn_disasm: '{line}'\n    gv_name: g_PlayerExtraInfo\n"
                for address, line in entries
            )

        accepted = ("0x5000E0", "mov word_600000[eax], di")
        wrong = [("0x5000C0", "cmp word_60002A[eax], 0"), ("0x5000D0", "mov word_600002[eax], bx")]
        for entries in (wrong + [accepted], [accepted] + wrong):
            with self.subTest(entries=entries):
                transport = AsyncMock(side_effect=[response(entries), response([accepted])])
                result = await call_llm_decompile(
                    model="test-model",
                    symbol_name_list=["g_PlayerExtraInfo"],
                    expected_result_sections={"g_PlayerExtraInfo": ["found_gv"]},
                    instruction_validations={
                        "g_PlayerExtraInfo": {"instruction_rules": spec.get("instruction_rules", [])}
                    },
                    target_disasm_codes=[code],
                    prompt_template="Find {symbol_name_list}.",
                    max_retries=2,
                    call_llm_text_func=transport,
                )
                self.assertEqual([accepted[0]], [entry["insn_va"] for entry in result["found_gv"]])
                self.assertEqual(2, transport.call_count)

    async def test_linux_retries_member_references_and_accepts_only_frags_store(self):
        finder = runpy.run_path(
            str(
                Path(__file__).resolve().parents[1]
                / "ida_preprocessor_scripts/find-ClientScoreInfoHandler-decompiles.py"
            )
        )
        with patch.dict(finder["preprocess_skill"].__globals__, {"preprocess_common_skill": AsyncMock()}) as namespace:
            await finder["preprocess_skill"](None, "find-ClientScoreInfoHandler-decompiles", [], {}, ".", "linux", 0)
            spec = namespace["preprocess_common_skill"].call_args.kwargs["llm_decompile_specs"][0]

        accepted = "mov word ptr ds:g_PlayerExtraInfo.frags[ebx], ax"
        rejected = (
            "mov word ptr ds:(g_PlayerExtraInfo.frags+2)[ebx], bp",
            "mov word ptr ds:(g_PlayerExtraInfo.frags+28h)[ebx], di",
            "mov ds:g_PlayerExtraInfo.deaths[ebx], bp",
            "add ebx, (offset g_PlayerExtraInfo+20h)",
            "mov ax, word ptr ds:g_PlayerExtraInfo.frags[ebx]",
        )

        def response(address, instruction):
            return (
                f"found_gv:\n  - insn_va: '{address}'\n"
                f"    insn_disasm: '{instruction}'\n    gv_name: g_PlayerExtraInfo\n"
            )

        for instruction in rejected:
            with self.subTest(instruction=instruction):
                transport = AsyncMock(side_effect=[response("0xDDD83", instruction), response("0xDDD8A", accepted)])
                result = await call_llm_decompile(
                    model="test-model",
                    symbol_name_list=["g_PlayerExtraInfo"],
                    expected_result_sections={"g_PlayerExtraInfo": ["found_gv"]},
                    instruction_validations={
                        "g_PlayerExtraInfo": {
                            "instruction_rules": spec.get("instruction_rules", []),
                        }
                    },
                    target_disasm_codes=[f"0xDDD83: {instruction}\n0xDDD8A: {accepted}"],
                    prompt_template="Find {symbol_name_list}.",
                    max_retries=2,
                    call_llm_text_func=transport,
                )
                self.assertEqual("0xDDD8A", result["found_gv"][0]["insn_va"])
                self.assertEqual(2, transport.call_count)


class LlmDecompileParserTests(unittest.TestCase):
    def test_disassembly_comments_need_no_space_before_semicolon(self):
        from ida_llm_decompile import _build_target_disasm_index, render_llm_decompile_blocks

        code = '.text:00401010 call sub_402000; source role\n.text:00401015 db "a;b" ; literal\n'
        reference, target = render_llm_decompile_blocks(
            [{"func_name": "Reference", "disasm_code": code}],
            [{"func_name": "Target", "disasm_code": code}],
        )
        self.assertIn("source role", reference)
        self.assertNotIn("source role", target)
        self.assertIn('db "a;b"', target)
        instructions, _ = _build_target_disasm_index([code])
        self.assertEqual({"call sub_402000"}, instructions[0x401010])
        self.assertEqual({'db "a;b"'}, instructions[0x401015])

    def test_parser_normalizes_all_canonical_sections(self):
        result = parse_llm_decompile_response(
            """\
```yaml
found_vcall:
  - insn_va: '0x401010'
    insn_disasm: call dword ptr [eax+14h]
    vfunc_offset: '0x14'
    func_name: VirtualTarget
found_call:
  - insn_va: '0x401020'
    insn_disasm: call sub_402000
    func_name: DirectTarget
found_funcptr:
  - insn_va: '0x401030'
    insn_disasm: lea eax, sub_403000
    funcptr_name: CallbackTarget
found_gv:
  - insn_va: '0x401040'
    insn_disasm: mov eax, ds:dword_404000
    gv_name: g_Target
found_struct_offset:
  - insn_va: '0x401050'
    insn_disasm: mov eax, [ecx+20h]
    offset: '0x20'
    size: 4
    struct_name: TargetStruct
    member_name: member
```
"""
        )

        self.assertEqual(LLM_DECOMPILE_RESULT_SECTIONS, tuple(result))
        self.assertEqual("CallbackTarget", result["found_funcptr"][0]["funcptr_name"])
        self.assertEqual("4", result["found_struct_offset"][0]["size"])

    def test_parser_returns_complete_empty_mapping_for_canonical_empty(self):
        self.assertEqual(_empty_llm_decompile_result(), parse_llm_decompile_response(CANONICAL_EMPTY))

    def test_request_cache_key_uses_request_shape(self):
        request = {
            "model": "test-model",
            "prompt_path": "D:/repo/prompt.md",
            "reference_yaml_paths": ["D:/repo/reference.windows.yaml"],
            "temperature": 0.2,
        }

        self.assertEqual(
            (
                "test-model",
                "D:/repo/prompt.md",
                ("D:/repo/reference.windows.yaml",),
                0.2,
            ),
            _build_llm_decompile_request_cache_key(request),
        )


class LlmDecompileCallTests(unittest.IsolatedAsyncioTestCase):
    async def test_unparseable_instruction_address_gets_actionable_retry(self):
        for address in ("000ABCDE", ".text:000ABCDE"):
            with self.subTest(address=address):
                calls = []

                def transport(**kwargs):
                    calls.append(kwargs)
                    if len(calls) == 1:
                        output_address = address
                    else:
                        output_address = "0xABCDE"
                    return (
                        "found_gv:\n"
                        f"  - insn_va: '{output_address}'\n"
                        "    insn_disasm: mov word ptr ds:g_Test.frags[ebx], ax\n"
                        "    gv_name: g_Test\n"
                    )

                result = await call_llm_decompile(
                    model="test-model",
                    symbol_name_list=["g_Test"],
                    expected_result_sections={"g_Test": ["found_gv"]},
                    target_disasm_codes=[".text:000ABCDE mov word ptr ds:g_Test.frags[ebx], ax"],
                    prompt_template="{symbol_name_list}",
                    max_retries=2,
                    call_llm_text_func=transport,
                )
                self.assertEqual(2, len(calls))
                self.assertEqual("0xABCDE", result["found_gv"][0]["insn_va"])
                correction = calls[1]["messages"][-1]["content"]
                self.assertIn("0x", correction)
                self.assertIn("segment", correction)
                self.assertIn("insn_va", correction)

    async def test_retries_invalid_yaml_then_accepts_canonical_response(self):
        responses = iter(
            [
                "not: [valid",
                """\
found_vcall: []
found_call:
  - insn_va: '0x401020'
    insn_disasm: call sub_402000
    func_name: build_number
found_funcptr: []
found_gv: []
found_struct_offset: []
""",
            ]
        )
        calls = []

        def transport(**kwargs):
            calls.append(kwargs)
            return next(responses)

        result = await call_llm_decompile(
            model="test-model",
            symbol_name_list=["build_number"],
            expected_result_sections={"build_number": ["found_call"]},
            target_disasm_codes=["0x401020: call sub_402000"],
            prompt_template="{target_blocks}\nFind {symbol_name_list}.",
            target_blocks="Target:\n0x401020: call sub_402000",
            reference_blocks="Reference:\ncall build_number",
            max_retries=2,
            call_llm_text_func=transport,
        )

        self.assertEqual("build_number", result["found_call"][0]["func_name"])
        self.assertEqual(2, len(calls))
        self.assertEqual(["system", "user", "assistant", "user"], [item["role"] for item in calls[1]["messages"]])
        self.assertIn("complete YAML", calls[1]["messages"][-1]["content"])

    async def test_retries_hallucinated_instruction_pair_with_full_context(self):
        responses = iter(
            [
                """\
found_vcall: []
found_call:
  - insn_va: '0x401020'
    insn_disasm: call sub_DEADBEEF
    func_name: build_number
found_funcptr: []
found_gv: []
found_struct_offset: []
""",
                """\
found_vcall: []
found_call:
  - insn_va: '0x401020'
    insn_disasm: call sub_402000
    func_name: build_number
found_funcptr: []
found_gv: []
found_struct_offset: []
""",
            ]
        )
        calls = []

        def transport(**kwargs):
            calls.append(kwargs)
            return next(responses)

        result = await call_llm_decompile(
            model="test-model",
            symbol_name_list=["build_number"],
            expected_result_sections={"build_number": ["found_call"]},
            target_disasm_codes=["0x401020: call sub_402000"],
            prompt_template="{reference_blocks}\n{target_blocks}\n{symbol_name_list}",
            reference_blocks="Reference block",
            target_blocks="Target block with 0x401020: call sub_402000",
            max_retries=2,
            call_llm_text_func=transport,
        )

        self.assertEqual("build_number", result["found_call"][0]["func_name"])
        self.assertEqual(2, len(calls))
        self.assertIn("sub_DEADBEEF", calls[1]["messages"][2]["content"])
        self.assertIn("0x401020", calls[1]["messages"][1]["content"])

    async def test_retries_transient_transport_error_with_backoff(self):
        responses = iter([RuntimeError("HTTP 503 service unavailable"), CANONICAL_EMPTY])

        def transport(**_kwargs):
            response = next(responses)
            if isinstance(response, Exception):
                raise response
            return response

        with patch("ida_llm_decompile.asyncio.sleep", new=AsyncMock()) as sleep:
            result = await call_llm_decompile(
                model="test-model",
                symbol_name_list=["build_number"],
                expected_result_sections={"build_number": ["found_call"]},
                prompt_template="Find {symbol_name_list}.",
                max_retries=2,
                retry_initial_delay=0.25,
                call_llm_text_func=transport,
            )

        self.assertEqual(_empty_llm_decompile_result(), result)
        sleep.assert_awaited_once_with(0.25)

    async def test_completes_unique_symbol_and_missing_empty_sections(self):
        result = await call_llm_decompile(
            model="test-model",
            symbol_name_list=["FreeBlob"],
            expected_result_sections={"FreeBlob": ["found_call"]},
            target_disasm_codes=[".text:001AED9F                 call    FreeBlob"],
            prompt_template="Find {symbol_name_list}.",
            max_retries=1,
            call_llm_text_func=lambda **_kwargs: (
                "found_call:\n  - insn_va: '0x001AED9F'\n    insn_disasm: call FreeBlob\n"
            ),
        )

        self.assertEqual(
            {
                "insn_va": "0x001AED9F",
                "insn_disasm": "call FreeBlob",
                "func_name": "FreeBlob",
            },
            result["found_call"][0],
        )
        self.assertEqual([], result["found_vcall"])

    async def test_accepts_zero_offsets_and_alternative_instruction_rules(self):
        response = """\
found_vcall:
  - insn_va: '0x401010'
    insn_disasm: call dword ptr [eax]
    vfunc_offset: '0x0'
    func_name: VirtualTarget
found_call: []
found_funcptr: []
found_gv: []
found_struct_offset:
  - insn_va: '0x401020'
    insn_disasm: mov edx, [ecx]
    offset: '0x0'
    size: 4
    struct_name: TargetStruct
    member_name: member
"""

        result = await call_llm_decompile(
            model="test-model",
            symbol_name_list=["VirtualTarget", "TargetStruct_member"],
            expected_result_sections={
                "VirtualTarget": ["found_vcall"],
                "TargetStruct_member": ["found_struct_offset"],
            },
            instruction_validations={
                "VirtualTarget": {
                    "instruction_rules": [
                        {"regex": r"jmp .+", "text": "jump form"},
                        {"regex": r"call dword ptr \[eax\]", "text": "call form"},
                    ]
                },
                "TargetStruct_member": {"expected_size": 4},
            },
            target_disasm_codes=[
                "0x401010: call dword ptr [eax]\n0x401020: mov edx, [ecx]",
            ],
            prompt_template="Find {symbol_name_list} in {target_blocks}.",
            target_blocks="Target disassembly",
            max_retries=1,
            call_llm_text_func=lambda **_kwargs: response,
        )

        self.assertEqual("0x0", result["found_vcall"][0]["vfunc_offset"])
        self.assertEqual("0x0", result["found_struct_offset"][0]["offset"])

    async def test_does_not_retry_non_transient_transport_error(self):
        calls = 0

        def transport(**_kwargs):
            nonlocal calls
            calls += 1
            raise RuntimeError("invalid API key")

        result = await call_llm_decompile(
            model="test-model",
            symbol_name_list=["build_number"],
            expected_result_sections={"build_number": ["found_call"]},
            prompt_template="Find {symbol_name_list}.",
            max_retries=3,
            call_llm_text_func=transport,
        )

        self.assertEqual(_empty_llm_decompile_result(), result)
        self.assertEqual(1, calls)

    def test_transient_status_code_classification(self):
        self.assertTrue(_is_transient_llm_error(SimpleNamespace(status_code=429)))
        self.assertTrue(_is_transient_llm_error(SimpleNamespace(status_code=503)))
        self.assertFalse(_is_transient_llm_error(SimpleNamespace(status_code=400)))

    def test_transient_connection_error_classification(self):
        api_connection_error = type("APIConnectionError", (RuntimeError,), {})
        self.assertTrue(_is_transient_llm_error(api_connection_error("Connection error.")))
        self.assertTrue(_is_transient_llm_error(RuntimeError("DNS name resolution failed")))
