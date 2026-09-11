from __future__ import annotations

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


class ScoreInfoInstructionRuleTests(unittest.IsolatedAsyncioTestCase):
    async def test_linux_retries_member_references_and_accepts_only_frags_store(self):
        finder = runpy.run_path(str(
            Path(__file__).resolve().parents[1]
            / "ida_preprocessor_scripts/find-ClientScoreInfoHandler-decompiles.py"
        ))
        with patch.dict(finder["preprocess_skill"].__globals__, {"preprocess_common_skill": AsyncMock()}) as namespace:
            await finder["preprocess_skill"](
                None, "find-ClientScoreInfoHandler-decompiles", [], {}, ".", "linux", 0
            )
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
                    instruction_validations={"g_PlayerExtraInfo": {
                        "instruction_rules": spec.get("instruction_rules", []),
                    }},
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
