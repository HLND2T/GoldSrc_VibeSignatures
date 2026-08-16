from __future__ import annotations

import unittest
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


class LlmDecompileParserTests(unittest.TestCase):
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
