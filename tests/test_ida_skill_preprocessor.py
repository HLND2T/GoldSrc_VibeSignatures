from __future__ import annotations

import ast
import asyncio
import io
import json
import os
import tempfile
import unittest
from contextlib import asynccontextmanager, redirect_stderr
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import ANY, AsyncMock, call, patch

import yaml

import ida_analyze_util
import ida_skill_preprocessor
from analysis_config import AnalysisConfigError
from ida_analyze_util import (
    _build_func_xref_py_eval,
    _build_llm_function_export_py_eval,
    _call_llm_for_targets,
    _export_llm_function,
    _inspect_function_via_mcp,
    _llm_entry_instruction_is_valid,
    _normalize_llm_decompile_specs,
    _prepare_llm_context,
    _preprocess_llm_target,
    _resolve_llm_template,
    _resolve_reference_resource,
    canonical_symbol_yaml_bytes,
    _gv_resolution_fields,
    parse_mcp_result,
    preprocess_common_skill,
    preprocess_func_sig_via_mcp,
    preprocess_func_xrefs_via_mcp,
    preprocess_index_based_vfunc_via_mcp,
)
from ida_preprocessor_scripts._indirect_vcall_target_common import preprocess_indirect_vcall_target_skill
from ida_preprocessor_scripts._ordinal_vtable_common import preprocess_ordinal_vtable_via_mcp
from ida_skill_preprocessor import (
    PREPROCESS_STATUS_ABSENT_OK,
    PREPROCESS_STATUS_FAILED,
    PREPROCESS_STATUS_NO_SCRIPT,
    PREPROCESS_STATUS_SUCCESS,
    _normalize_preprocess_status,
    _parse_image_base,
    preprocess_single_skill_via_mcp,
)


@asynccontextmanager
async def _bound_session(session):
    yield session


def _image_base_result(value="0x400000"):
    return SimpleNamespace(structuredContent={"result": value}, content=[], isError=False)


class PreprocessStatusTests(unittest.TestCase):
    def test_status_truthiness_and_legacy_normalization(self):
        self.assertTrue(PREPROCESS_STATUS_SUCCESS)
        self.assertTrue(PREPROCESS_STATUS_ABSENT_OK)
        self.assertFalse(PREPROCESS_STATUS_NO_SCRIPT)
        self.assertFalse(PREPROCESS_STATUS_FAILED)
        cases = (
            (True, PREPROCESS_STATUS_SUCCESS),
            ("success", PREPROCESS_STATUS_SUCCESS),
            ("absent_ok", PREPROCESS_STATUS_ABSENT_OK),
            ("no_script", PREPROCESS_STATUS_NO_SCRIPT),
            (False, PREPROCESS_STATUS_FAILED),
            (None, PREPROCESS_STATUS_FAILED),
            ("unexpected", PREPROCESS_STATUS_FAILED),
        )
        for raw, expected in cases:
            with self.subTest(raw=raw):
                self.assertIs(expected, _normalize_preprocess_status(raw))

    def test_sdk_snake_case_structured_content_is_unwrapped(self):
        result = SimpleNamespace(
            structuredContent=None,
            structured_content={"result": json.dumps({"pointer_size": 4})},
            content=[],
        )
        self.assertEqual({"pointer_size": 4}, parse_mcp_result(result))

    def test_sdk_snake_case_structured_content_supplies_image_base(self):
        result = SimpleNamespace(
            structuredContent=None,
            structured_content={"result": "0x1d00000"},
            content=[],
        )
        self.assertEqual(0x1D00000, _parse_image_base(result))

    def test_func_xref_py_eval_round_trips_json_only_values(self):
        spec = {"inline_alias": None, "enabled": True, "values": [1, "anchor"]}
        code = _build_func_xref_py_eval(spec, 0x400000)
        spec_line = next(line for line in code.splitlines() if line.startswith("spec = "))
        namespace = {"json": json}
        exec(spec_line, namespace)  # noqa: S102 - validates generated IDAPython source.
        self.assertEqual(spec, namespace["spec"])

    def test_func_xref_py_eval_preserves_cs2_semantic_contracts(self):
        code = _build_func_xref_py_eval(
            {
                "func_name": "Target",
                "vtable_entries": [0x401000],
                "allow_across_function_boundary": True,
            },
            0x400000,
        )

        ast.parse(code)
        self.assertIn("FUNCTION_RECOVERY_BACKTRACK_LIMIT", code)
        self.assertIn("return {start for start, count in counts.items() if count == 1}", code)
        self.assertIn("Strings(default_setup=False)", code)
        self.assertIn("strings.setup(strtypes=[ida_nalt.STRTYPE_C]", code)
        self.assertIn("name == '.rdata' or name.startswith('.rodata')", code)
        self.assertIn("required_hits = [False] * len(required_values)", code)
        self.assertIn("required_hits[index] = True", code)
        self.assertIn("return all(required_hits) and not excluded_hit", code)
        self.assertIn("if not callers and dep_start is not None and dep_start in vtable_candidates", code)
        self.assertIn("SIGNATURE_XREF_PROBE_MAX_CANDIDATES = 256", code)
        self.assertIn("def _function_contains_signature(start, signature):", code)
        self.assertIn("range_end=int(func.end_ea)", code)
        self.assertIn("def _signature_candidates(narrowed, signature, match_eas):", code)
        self.assertIn("excluded.update(_named_candidates(value))", code)
        self.assertIn("if spec.get('vtable_entries'):", code)
        self.assertIn("def _try_decode_padding_nop", code)
        self.assertIn("not ida_bytes.is_head(flags)", code)
        self.assertNotIn("if len(tokens) >= max_tokens:\n                break", code)
        self.assertIn("ida_ua.o_displ", ida_analyze_util._INSPECT_FUNCTION_PY_EVAL)
        self.assertIn("def _try_decode_padding_nop", ida_analyze_util._INSPECT_FUNCTION_PY_EVAL)

    def test_function_owner_recovery_replaces_false_suffix_with_unique_direct_call_entry(self):
        tree = ast.parse(ida_analyze_util._FUNCTION_OWNER_RECOVERY_PY_EVAL)
        function_node = next(
            node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == "_ensure_function_owner"
        )
        anchor_ea = 0x401120
        entry_ea = 0x401000
        suffix = SimpleNamespace(start_ea=anchor_ea, end_ea=0x401160)
        recovered = SimpleNamespace(start_ea=entry_ea, end_ea=0x401160)
        calls = []

        def recover(entry, anchor, expected_end, expected_signature):
            calls.append((entry, anchor, expected_end, expected_signature))
            return recovered

        namespace = {
            "FUNCTION_RECOVERY_BACKTRACK_LIMIT": 0x200,
            "ida_funcs": SimpleNamespace(get_func=lambda ea: suffix if ea == anchor_ea else None),
            "_direct_call_entry_candidates": lambda _anchor, _lower: {entry_ea},
            "_has_data_entry_reference": lambda _entry: False,
            "_recover_function_entry": recover,
            "_function_payload": lambda func, was_recovered, reason: {
                "function_start": int(func.start_ea),
                "function_end": int(func.end_ea),
                "recovered": was_recovered,
                "recovery_reason": reason,
            },
        }
        exec(  # noqa: S102 - executes only the selected generated recovery helper.
            compile(ast.Module(body=[function_node], type_ignores=[]), "<function-owner-recovery>", "exec"),
            namespace,
        )

        result = namespace["_ensure_function_owner"](anchor_ea)

        self.assertEqual(entry_ea, result["function_start"])
        self.assertTrue(result["recovered"])
        self.assertEqual([(entry_ea, anchor_ea, None, None)], calls)

    def test_function_owner_preserves_data_referenced_virtual_entry(self):
        tree = ast.parse(ida_analyze_util._FUNCTION_OWNER_RECOVERY_PY_EVAL)
        function_node = next(
            node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == "_ensure_function_owner"
        )
        entry = 0x401100
        existing = SimpleNamespace(start_ea=entry, end_ea=0x401190)
        namespace = {
            "FUNCTION_RECOVERY_BACKTRACK_LIMIT": 0x200,
            "ida_funcs": SimpleNamespace(get_func=lambda _ea: existing),
            "_has_data_entry_reference": lambda value: value == entry,
            "_direct_call_entry_candidates": lambda *_args: {0x401000, 0x401080},
            "_recover_function_entry": lambda *_args: self.fail("a vtable entry must not be merged with nearby code"),
            "_function_payload": lambda func, recovered, reason: (func.start_ea, recovered),
        }
        exec(
            compile(ast.Module(body=[function_node], type_ignores=[]), "<virtual-entry-recovery>", "exec"),
            namespace,
        )
        self.assertEqual((entry, False), namespace["_ensure_function_owner"](entry))

    def test_exact_function_exclusion_preserves_verified_dependency_entries(self):
        tree = ast.parse(ida_analyze_util._build_func_xref_py_eval({}, 0))
        node = next(
            node
            for node in tree.body
            if isinstance(node, ast.FunctionDef) and node.name == "_exact_function_candidates"
        )
        entry = 0x401100
        namespace = {
            "_named_ea": lambda value: value,
            "_is_executable_address": lambda ea: ea in (entry, entry + 4),
            "ida_funcs": SimpleNamespace(
                get_func=lambda ea: SimpleNamespace(start_ea=entry) if ea in (entry, entry + 4) else None
            ),
            "_function_start": lambda _ea: self.fail("a verified exclusion must not infer a neighboring owner"),
        }
        exec(compile(ast.Module(body=[node], type_ignores=[]), "<exact-function-exclusion>", "exec"), namespace)
        self.assertEqual({entry}, namespace["_exact_function_candidates"]([entry, entry + 4, None, 0x501000]))

    def test_function_owner_recovery_fails_closed_on_ambiguous_entries(self):
        tree = ast.parse(ida_analyze_util._FUNCTION_OWNER_RECOVERY_PY_EVAL)
        function_node = next(
            node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == "_ensure_function_owner"
        )
        anchor_ea = 0x401120
        namespace = {
            "FUNCTION_RECOVERY_BACKTRACK_LIMIT": 0x200,
            "ida_funcs": SimpleNamespace(get_func=lambda _ea: None),
            "_direct_call_entry_candidates": lambda _anchor, _lower: {0x401000, 0x401080},
            "_recover_function_entry": lambda *_args: self.fail("ambiguous recovery must not mutate IDA"),
            "_function_payload": lambda *_args: self.fail("ambiguous recovery must not produce a function"),
        }
        exec(  # noqa: S102 - executes only the selected generated recovery helper.
            compile(ast.Module(body=[function_node], type_ignores=[]), "<function-owner-recovery>", "exec"),
            namespace,
        )

        self.assertIsNone(namespace["_ensure_function_owner"](anchor_ea))

    def test_function_owner_destructive_recovery_requires_external_direct_call(self):
        tree = ast.parse(ida_analyze_util._FUNCTION_OWNER_RECOVERY_PY_EVAL)
        function_node = next(
            node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == "_recover_function_entry"
        )
        entry_ea = 0x401000
        anchor_ea = 0x401120
        cleanup_end = 0x401160
        add_func_calls = []
        namespace = {
            "FUNCTION_RECOVERY_MAX_SPAN": 0x4000,
            "ida_funcs": SimpleNamespace(
                get_func=lambda _ea: None,
                add_func=lambda *args: add_func_calls.append(args),
            ),
            "_verified_entry_function": lambda *_args: None,
            "_is_executable_address": lambda _ea: True,
            "_signature_matches": lambda _ea, _signature: True,
            "_direct_call_sources": lambda _ea: [anchor_ea],
            "_next_recovery_limit": lambda _entry, _anchor: cleanup_end,
            "_same_executable_segment": lambda *_args: self.fail(
                "internal direct calls must not reach destructive recovery gates"
            ),
        }
        exec(  # noqa: S102 - executes only the selected generated recovery helper.
            compile(ast.Module(body=[function_node], type_ignores=[]), "<function-entry-recovery>", "exec"),
            namespace,
        )

        result = namespace["_recover_function_entry"](entry_ea, anchor_ea, None, None)

        self.assertIsNone(result)
        self.assertEqual([(entry_ea,)], add_func_calls)

    def test_func_xref_float_filters_require_every_xref_and_exclude_any_hit(self):
        code = _build_func_xref_py_eval({"func_name": "Target"}, 0x400000)
        tree = ast.parse(code)
        function_nodes = [
            node
            for node in tree.body
            if isinstance(node, ast.FunctionDef) and node.name in {"_float_matches", "_function_matches_float_filters"}
        ]
        scalar_values = {
            0x5000: 64.0,
            0x5004: 0.5,
            0x5008: 128.0,
        }
        function_items = {
            0x1000: [0x4000],
            0x2000: [0x4000, 0x4004],
            0x3000: [0x4000, 0x4004, 0x4008],
        }
        namespace = {
            "MEMORY_OPERAND_TYPES": {1},
            "ida_bytes": SimpleNamespace(
                get_bytes=lambda target_ea, width: __import__("struct").pack("<f", scalar_values[target_ea])
            ),
            "idautils": SimpleNamespace(FuncItems=lambda start: function_items[start]),
            "idc": SimpleNamespace(
                get_operand_type=lambda _ea, operand_index: 1 if operand_index == 0 else 0,
                get_operand_value=lambda ea, _operand_index: ea + 0x1000,
            ),
            "math": __import__("math"),
            "struct": __import__("struct"),
            "_has_xmm_operand": lambda _ea: True,
            "_is_readonly_float_segment": lambda _ea: True,
            "_scalar_float_kind": lambda _ea: "float",
        }
        exec(  # noqa: S102 - executes only selected generated helper definitions.
            compile(ast.Module(body=function_nodes, type_ignores=[]), "<func-xref-floats>", "exec"),
            namespace,
        )
        matches = namespace["_function_matches_float_filters"]

        self.assertFalse(matches(0x1000, [64.0, 0.5], []))
        self.assertTrue(matches(0x2000, [64.0, 0.5], []))
        self.assertFalse(matches(0x3000, [64.0, 0.5], [128.0]))

    def test_func_xref_signature_probes_narrowed_candidates_else_uses_global_matches(self):
        code = _build_func_xref_py_eval({"func_name": "Target"}, 0x400000)
        tree = ast.parse(code)
        wanted = {
            "_address_candidates",
            "_function_contains_signature",
            "_intersected_candidates",
            "_signature_candidates",
        }
        function_nodes = [node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name in wanted]
        contained = {0x1000: True, 0x2000: False}
        namespace = {
            "SIGNATURE_XREF_PROBE_MAX_CANDIDATES": 256,
            "ida_bytes": SimpleNamespace(
                BIN_SEARCH_FORWARD=1,
                BIN_SEARCH_NOSHOW=2,
                find_bytes=lambda _signature, start, range_end=None, flags=0, radix=16: (
                    start if contained.get(start) else -1
                ),
            ),
            "ida_funcs": SimpleNamespace(
                get_func=lambda start: (
                    SimpleNamespace(start_ea=start, end_ea=start + 0x40) if start in contained else None
                )
            ),
            "idaapi": SimpleNamespace(BADADDR=-1),
            "_function_start": lambda ea: {0x401010: 0x401000, 0x402010: 0x402000}.get(int(ea), int(ea)),
        }
        exec(  # noqa: S102 - executes only selected generated helper definitions.
            compile(ast.Module(body=function_nodes, type_ignores=[]), "<func-xref-signatures>", "exec"),
            namespace,
        )
        select = namespace["_signature_candidates"]
        intersect = namespace["_intersected_candidates"]

        self.assertEqual({0x1000}, select({0x1000, 0x2000}, "AA BB", [0x401010]))
        self.assertEqual({0x401000}, select(set(), "AA BB", [0x401010]))
        self.assertEqual({0x401000}, select(set(range(300)), "AA BB", [0x401010]))
        self.assertEqual({0x1000}, intersect([{0x1000, 0x2000}, {0x1000, 0x3000}]))

    def test_gsvibe_string_min_length_config_matches_cs2_rules(self):
        cases = ((None, None), ("", None), ("0", 4), ("invalid", 4), ("7", 7))
        for raw_value, expected in cases:
            with self.subTest(raw_value=raw_value), patch.dict(os.environ, {}, clear=True):
                if raw_value is not None:
                    os.environ["GSVIBE_STRING_MIN_LENGTH"] = raw_value
                self.assertEqual(expected, ida_analyze_util._resolve_ida_string_min_length_config())


class PreprocessorLoaderTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        ida_skill_preprocessor._SCRIPT_ENTRY_CACHE.clear()

    async def test_missing_script_and_unsafe_name_fail_closed(self):
        with (
            tempfile.TemporaryDirectory() as temporary,
            patch.object(ida_skill_preprocessor, "_SCRIPT_DIR", Path(temporary)),
        ):
            missing = await preprocess_single_skill_via_mcp(
                "127.0.0.1",
                13337,
                "find-missing",
                [],
                None,
                temporary,
                "windows",
            )
            unsafe = await preprocess_single_skill_via_mcp(
                "127.0.0.1",
                13337,
                "../escape",
                [],
                None,
                temporary,
                "windows",
            )
        self.assertIs(PREPROCESS_STATUS_NO_SCRIPT, missing)
        self.assertIs(PREPROCESS_STATUS_FAILED, unsafe)

    async def test_loader_caches_success_and_rejects_invalid_abi(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            counter = root / "imports.txt"
            script = root / "find-cache.py"
            script.write_text(
                "from pathlib import Path\n"
                f"p = Path({str(counter)!r})\n"
                "p.write_text((p.read_text() if p.exists() else '') + 'x')\n"
                "def preprocess_skill(session, skill_name, expected_outputs, old_yaml_map, "
                "new_binary_dir, platform, image_base, debug=False):\n"
                "    return True\n",
                encoding="utf-8",
            )
            invalid = root / "find-invalid.py"
            invalid.write_text("def preprocess_skill(session):\n    return True\n", encoding="utf-8")
            session = SimpleNamespace(call_tool=AsyncMock(return_value=_image_base_result()))
            with (
                patch.object(ida_skill_preprocessor, "_SCRIPT_DIR", root),
                patch.object(
                    ida_skill_preprocessor,
                    "open_ida_mcp_session",
                    side_effect=lambda *_args, **_kwargs: _bound_session(session),
                ),
            ):
                first = await preprocess_single_skill_via_mcp(
                    "127.0.0.1", 13337, "find-cache", [], None, temporary, "windows"
                )
                second = await preprocess_single_skill_via_mcp(
                    "127.0.0.1", 13337, "find-cache", [], None, temporary, "windows"
                )
                invalid_result = await preprocess_single_skill_via_mcp(
                    "127.0.0.1", 13337, "find-invalid", [], None, temporary, "windows"
                )
                import_count = counter.read_text(encoding="utf-8")
        self.assertIs(PREPROCESS_STATUS_SUCCESS, first)
        self.assertIs(PREPROCESS_STATUS_SUCCESS, second)
        self.assertEqual("x", import_count)
        self.assertIs(PREPROCESS_STATUS_FAILED, invalid_result)


class PreprocessorDispatchTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        ida_skill_preprocessor._SCRIPT_ENTRY_CACHE.clear()

    async def test_passes_bound_session_image_base_and_opt_in_llm_config(self):
        received = {}

        async def script(
            session,
            skill_name,
            expected_outputs,
            old_yaml_map,
            new_binary_dir,
            platform,
            image_base,
            llm_config,
            debug=False,
        ):
            received.update(locals())
            return "absent_ok"

        session = SimpleNamespace(call_tool=AsyncMock(return_value=_image_base_result("0x0")))
        with (
            patch.object(ida_skill_preprocessor, "_SCRIPT_DIR", Path(".")),
            patch.object(Path, "is_file", return_value=True),
            patch.object(ida_skill_preprocessor, "_get_preprocess_entry", return_value=script),
            patch.object(
                ida_skill_preprocessor,
                "open_ida_mcp_session",
                return_value=_bound_session(session),
            ) as open_session,
        ):
            result = await preprocess_single_skill_via_mcp(
                "127.0.0.1",
                13337,
                "find-symbol",
                [r"D:\out.yaml"],
                {r"D:\out.yaml": r"D:\old.yaml"},
                r"D:\new",
                "windows",
                expected_inputs=[r"D:\input.yaml"],
                optional_inputs=[r"D:\optional.yaml"],
                expected_binary=r"D:\game\hw.dll",
                explicit_database="database-1",
                llm_model="test-model",
                llm_apikey="secret",
                llm_baseurl="https://example.invalid/v1",
                llm_temperature=0.5,
                llm_effort="high",
                llm_fake_as="codex",
                llm_max_retries=4,
                symbol_aliases={"Symbol": ("Alias",)},
                debug=True,
            )
        self.assertIs(PREPROCESS_STATUS_ABSENT_OK, result)
        self.assertIs(session, received["session"])
        self.assertEqual(0, received["image_base"])
        self.assertEqual("secret", received["llm_config"]["api_key"])
        self.assertEqual(4, received["llm_config"]["max_retries"])
        self.assertEqual([r"D:\input.yaml"], received["llm_config"]["_expected_inputs"])
        self.assertEqual({"Symbol": ("Alias",)}, received["llm_config"]["symbol_aliases"])
        open_session.assert_called_once_with(
            "127.0.0.1",
            13337,
            expected_binary=r"D:\game\hw.dll",
            explicit_database="database-1",
        )

    async def test_invalid_image_base_returns_failed_without_running_script(self):
        script = AsyncMock(return_value=True)
        diagnostics = []
        session = SimpleNamespace(call_tool=AsyncMock(return_value=_image_base_result("not-hex")))
        with (
            patch.object(ida_skill_preprocessor, "_SCRIPT_DIR", Path(".")),
            patch.object(Path, "is_file", return_value=True),
            patch.object(ida_skill_preprocessor, "_get_preprocess_entry", return_value=script),
            patch.object(
                ida_skill_preprocessor,
                "open_ida_mcp_session",
                return_value=_bound_session(session),
            ),
        ):
            result = await preprocess_single_skill_via_mcp(
                "127.0.0.1",
                13337,
                "find-symbol",
                [],
                None,
                r"D:\new",
                "windows",
                diagnostic_callback=diagnostics.append,
            )
        self.assertIs(PREPROCESS_STATUS_FAILED, result)
        script.assert_not_awaited()
        self.assertEqual("mcp_failed", diagnostics[-1]["reason"])

    async def test_llm_requires_explicit_parameter_and_unhashable_status_is_rejected(self):
        received = {}

        def script(
            session,
            skill_name,
            expected_outputs,
            old_yaml_map,
            new_binary_dir,
            platform,
            image_base,
            debug=False,
        ):
            received.update(locals())
            return {"unsupported": True}

        diagnostics = []
        session = SimpleNamespace(call_tool=AsyncMock(return_value=_image_base_result()))
        with (
            patch.object(ida_skill_preprocessor, "_SCRIPT_DIR", Path(".")),
            patch.object(Path, "is_file", return_value=True),
            patch.object(ida_skill_preprocessor, "_get_preprocess_entry", return_value=script),
            patch.object(
                ida_skill_preprocessor,
                "open_ida_mcp_session",
                return_value=_bound_session(session),
            ),
        ):
            result = await preprocess_single_skill_via_mcp(
                "127.0.0.1",
                13337,
                "find-symbol",
                [],
                None,
                r"D:\new",
                "windows",
                llm_apikey="secret-key",
                diagnostic_callback=diagnostics.append,
            )
        self.assertIs(PREPROCESS_STATUS_FAILED, result)
        self.assertNotIn("llm_config", received)
        self.assertEqual("invalid_status", diagnostics[-1]["reason"])

    async def test_script_exception_is_diagnosed_without_exposing_api_key(self):
        async def script(**_kwargs):
            raise RuntimeError("request failed for secret-key")

        diagnostics = []
        stderr = io.StringIO()
        session = SimpleNamespace(call_tool=AsyncMock(return_value=_image_base_result()))
        with (
            redirect_stderr(stderr),
            patch.object(ida_skill_preprocessor, "_SCRIPT_DIR", Path(".")),
            patch.object(Path, "is_file", return_value=True),
            patch.object(ida_skill_preprocessor, "_get_preprocess_entry", return_value=script),
            patch.object(
                ida_skill_preprocessor,
                "open_ida_mcp_session",
                return_value=_bound_session(session),
            ),
        ):
            result = await preprocess_single_skill_via_mcp(
                "127.0.0.1",
                13337,
                "find-symbol",
                [],
                None,
                r"D:\new",
                "windows",
                llm_apikey="secret-key",
                debug=True,
                diagnostic_callback=diagnostics.append,
            )
        self.assertIs(PREPROCESS_STATUS_FAILED, result)
        self.assertEqual("script_failed", diagnostics[-1]["reason"])
        self.assertNotIn("secret-key", diagnostics[-1]["message"])
        self.assertNotIn("secret-key", stderr.getvalue())


class CommonPreprocessorContractTests(unittest.IsolatedAsyncioTestCase):
    async def test_engine_callback_rejects_forwarding_cycles(self):
        from ida_preprocessor_scripts import _engine_public_callback_common as callback

        instructions = {
            0x401000: SimpleNamespace(ops=[SimpleNamespace(type=1, addr=0x402000)]),
            0x402000: SimpleNamespace(ops=[SimpleNamespace(type=1, addr=0x401000)]),
        }
        modules = {
            "ida_bytes": SimpleNamespace(get_dword=lambda _ea: 0x401000),
            "ida_funcs": SimpleNamespace(get_func=lambda ea: SimpleNamespace(start_ea=ea)),
            "ida_segment": SimpleNamespace(getseg=lambda _ea: SimpleNamespace(perm=4), SEGPERM_EXEC=4),
            "ida_ua": SimpleNamespace(o_near=1),
            "idaapi": SimpleNamespace(inf_is_64bit=lambda: False),
            "idautils": SimpleNamespace(FuncItems=lambda ea: [ea], DecodeInstruction=instructions.get),
            "idc": SimpleNamespace(print_insn_mnem=lambda _ea: "jmp"),
        }

        async def evaluate(_tool, args):
            namespace = {}
            with patch.dict("sys.modules", modules):
                exec(args["code"], namespace)
            return json.loads(namespace["result"])

        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            (directory / "cl_enginefuncs.windows.yaml").write_text("gv_va: '0x500000'\n")
            inspected = AsyncMock(return_value=None)
            with patch.object(callback, "_inspect_function_via_mcp", inspected):
                result = await callback.preprocess_engine_callback(
                    SimpleNamespace(call_tool=evaluate),
                    [str(directory / "Target.windows.yaml")],
                    directory,
                    "windows",
                    0x400000,
                    name="Target",
                    slot=0,
                )
            self.assertFalse(result)
            inspected.assert_not_awaited()

    def test_global_targets_use_decoded_absolute_operand_over_offset_base_xref(self):
        detail = {
            "data_refs": ["0x2000"],
            "operand_targets": ["0x3800"],
            "operand_dwords": [None, "0x3800"],
            "operand_pic": [False, False],
        }
        self.assertEqual(["0x3800"], ida_analyze_util._llm_global_targets(detail))

    def test_global_targets_keep_two_encoded_operands_ambiguous(self):
        detail = {
            "data_refs": ["0x2000", "0x3800"],
            "operand_targets": ["0x2000", "0x3800"],
            "operand_dwords": ["0x2000", "0x3800"],
            "operand_pic": [False, False],
        }
        self.assertEqual(["0x2000", "0x3800"], ida_analyze_util._llm_global_targets(detail))

    def test_global_targets_preserve_pic_relocation_xrefs(self):
        detail = {
            "data_refs": ["0x3800"],
            "operand_targets": [],
            "operand_dwords": [None, "0xffffe010"],
            "operand_pic": [False, True],
        }
        self.assertEqual(["0x3800"], ida_analyze_util._llm_global_targets(detail))

    def test_global_targets_keep_mixed_pic_and_absolute_operands_ambiguous(self):
        detail = {
            "data_refs": ["0x3800", "0x4800"],
            "operand_targets": ["0x4800"],
            "operand_dwords": ["0xffffe010", "0x4800"],
            "operand_pic": [True, False],
        }
        self.assertEqual(["0x3800", "0x4800"], ida_analyze_util._llm_global_targets(detail))

    async def test_xref_string_function_uses_cs2_api_and_writes_canonical_yaml(self):
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "R_RenderView.windows.yaml"

            async def call_tool(name, arguments):
                if name == "find_bytes":
                    self.assertEqual(["55 8B EC ??"], arguments["patterns"])
                    return {"matches": ["0x401000"], "n": 1}
                self.assertEqual("py_eval", name)
                self.assertIn("R_RenderView: NULL worldmodel", arguments["code"])
                candidate = {
                    "func_name": "R_RenderView",
                    "func_va": "0x401000",
                    "func_rva": "0x1000",
                    "func_size": "0x80",
                    "func_sig": "55 8B EC ??",
                }
                return SimpleNamespace(
                    structuredContent={"result": json.dumps({"candidates": [candidate], "pointer_size": 4})},
                    content=[],
                    isError=False,
                )

            result = await preprocess_common_skill(
                session=SimpleNamespace(call_tool=call_tool),
                expected_outputs=[str(output)],
                old_yaml_map=None,
                new_binary_dir=temporary,
                platform="windows",
                image_base=0x400000,
                func_names=["R_RenderView"],
                func_xrefs=[
                    {
                        "func_name": "R_RenderView",
                        "xref_strings": ["R_RenderView: NULL worldmodel"],
                        "xref_gvs": [],
                        "xref_signatures": [],
                        "xref_funcs": [],
                        "exclude_funcs": [],
                        "exclude_strings": [],
                        "exclude_gvs": [],
                        "exclude_signatures": [],
                    }
                ],
                generate_yaml_desired_fields=[
                    ("R_RenderView", ["func_name", "func_sig", "func_va", "func_rva", "func_size"])
                ],
            )

            self.assertTrue(result)
            self.assertEqual(
                {
                    "func_name": "R_RenderView",
                    "func_va": "0x401000",
                    "func_rva": "0x1000",
                    "func_size": "0x80",
                    "func_sig": "55 8B EC ??",
                },
                yaml.safe_load(output.read_text(encoding="utf-8")),
            )

    async def test_func_xref_applies_signature_float_inline_alias_and_sibling_inputs(self):
        with tempfile.TemporaryDirectory() as temporary:
            game_root = Path(temporary)
            client_root = game_root / "client"
            engine_root = game_root / "engine"
            client_root.mkdir()
            engine_root.mkdir()
            (engine_root / "Alias.windows.yaml").write_text("func_name: Alias\nfunc_va: '0x401100'\n", encoding="utf-8")
            calls = []

            async def call_tool(name, arguments):
                calls.append((name, arguments))
                if name == "find_bytes":
                    pattern = arguments["patterns"][0]
                    address = {
                        "DE AD ?? EF": "0x401020",
                        "BA AD F0 0D": "0x401030",
                        "55 8B EC 83 EC ??": "0x401000",
                    }[pattern]
                    return {"matches": [address], "n": 1}
                self.assertIn("3735928559", arguments["code"])
                self.assertIn("3.5", arguments["code"])
                self.assertIn("4198656", arguments["code"])
                candidate = {
                    "func_name": "Target",
                    "func_va": "0x401000",
                    "func_rva": "0x1000",
                    "func_size": "0x40",
                    "func_sig": "55 8B EC 83 EC ??",
                }
                return {"pointer_size": 4, "candidates": [candidate]}

            result = await preprocess_func_xrefs_via_mcp(
                session=SimpleNamespace(call_tool=call_tool),
                func_name="Target",
                xref_strings=["anchor"],
                xref_gvs=["0xDEADBEEF"],
                xref_signatures=["DE AD ?? EF"],
                xref_funcs=[],
                exclude_funcs=[],
                exclude_strings=[],
                exclude_gvs=[],
                exclude_signatures=["BA AD F0 0D"],
                new_binary_dir=client_root,
                platform="windows",
                image_base=0x400000,
                xref_floats=["3.5"],
                exclude_floats=["4.5"],
                inline_alias="../engine/Alias",
            )
            self.assertEqual("Target", result["func_name"])
            self.assertEqual(["find_bytes", "find_bytes", "py_eval", "find_bytes"], [name for name, _ in calls])

    async def test_func_xref_intersects_each_signature_candidate_set(self):
        signatures = {
            "AA BB": ["0x401010", "0x402010"],
            "CC DD": ["0x401020"],
            "55 8B EC 83 EC ??": ["0x401000"],
        }

        async def call_tool(name, arguments):
            if name == "find_bytes":
                pattern = arguments["patterns"][0]
                matches = signatures[pattern]
                return {"matches": matches, "n": len(matches)}
            self.assertEqual("py_eval", name)
            code = arguments["code"]
            spec_line = next(line for line in code.splitlines() if line.startswith("spec = "))
            namespace = {"json": json}
            exec(spec_line, namespace)  # noqa: S102 - validates generated IDAPython source.
            self.assertEqual(["AA BB", "CC DD"], namespace["spec"]["xref_signatures"])
            self.assertEqual(
                [[0x401010, 0x402010], [0x401020]],
                namespace["spec"]["xref_signature_ea_sets"],
            )
            self.assertIn("def _signature_candidates(narrowed, signature, match_eas):", code)
            self.assertIn("for index, signature in enumerate(signature_texts):", code)
            candidate = {
                "func_name": "Target",
                "func_va": "0x401000",
                "func_rva": "0x1000",
                "func_size": "0x40",
                "func_sig": "55 8B EC 83 EC ??",
            }
            return {"pointer_size": 4, "candidates": [candidate]}

        result = await preprocess_func_xrefs_via_mcp(
            session=SimpleNamespace(call_tool=call_tool),
            func_name="Target",
            xref_strings=[],
            xref_gvs=[],
            xref_signatures=["AA BB", "CC DD"],
            xref_funcs=[],
            exclude_funcs=[],
            exclude_strings=[],
            exclude_gvs=[],
            exclude_signatures=[],
            new_binary_dir=None,
            platform="windows",
            image_base=0x400000,
        )

        self.assertEqual("Target", result["func_name"])

    async def test_func_xref_keeps_empty_global_signature_matches_for_narrowed_probe(self):
        captured_spec = {}

        async def call_tool(name, arguments):
            if name == "find_bytes":
                return {"matches": [], "n": 0}
            self.assertEqual("py_eval", name)
            spec_line = next(line for line in arguments["code"].splitlines() if line.startswith("spec = "))
            namespace = {"json": json}
            exec(spec_line, namespace)  # noqa: S102 - validates generated IDAPython source.
            captured_spec.update(namespace["spec"])
            return {
                "pointer_size": 4,
                "candidates": [
                    {
                        "func_name": "Target",
                        "func_va": "0x401000",
                        "func_rva": "0x1000",
                        "func_size": "0x40",
                    }
                ],
            }

        result = await preprocess_func_xrefs_via_mcp(
            session=SimpleNamespace(call_tool=call_tool),
            func_name="Target",
            xref_strings=["anchor"],
            xref_gvs=[],
            xref_signatures=["AA BB"],
            xref_funcs=[],
            exclude_funcs=[],
            exclude_strings=[],
            exclude_gvs=[],
            exclude_signatures=[],
            new_binary_dir=None,
            platform="windows",
            image_base=0x400000,
        )

        self.assertEqual("Target", result["func_name"])
        self.assertEqual(["AA BB"], captured_spec["xref_signatures"])
        self.assertEqual([[]], captured_spec["xref_signature_ea_sets"])

    async def test_func_xref_forwards_gsvibe_string_min_length(self):
        captured_spec = {}

        async def call_tool(name, arguments):
            self.assertEqual("py_eval", name)
            spec_line = next(line for line in arguments["code"].splitlines() if line.startswith("spec = "))
            namespace = {"json": json}
            exec(spec_line, namespace)  # noqa: S102 - validates generated IDAPython source.
            captured_spec.update(namespace["spec"])
            return {
                "pointer_size": 4,
                "candidates": [
                    {
                        "func_name": "Target",
                        "func_va": "0x401000",
                        "func_rva": "0x1000",
                        "func_size": "0x40",
                    }
                ],
            }

        with patch.dict(os.environ, {"GSVIBE_STRING_MIN_LENGTH": " 7 "}):
            result = await preprocess_func_xrefs_via_mcp(
                session=SimpleNamespace(call_tool=call_tool),
                func_name="Target",
                xref_strings=["anchor"],
                xref_gvs=[],
                xref_signatures=[],
                xref_funcs=[],
                exclude_funcs=[],
                exclude_strings=[],
                exclude_gvs=[],
                exclude_signatures=[],
                new_binary_dir=None,
                platform="windows",
                image_base=0x400000,
            )

        self.assertEqual(7, captured_spec["string_min_length"])
        self.assertEqual("Target", result["func_name"])

    async def test_func_xref_rejects_explicit_function_addresses_but_allows_gv_literals(self):
        with tempfile.TemporaryDirectory() as temporary:
            base_kwargs = {
                "session": None,
                "func_name": "Target",
                "xref_strings": ["anchor"],
                "xref_gvs": [],
                "xref_signatures": [],
                "xref_funcs": [],
                "exclude_funcs": [],
                "exclude_strings": [],
                "exclude_gvs": [],
                "exclude_signatures": [],
                "new_binary_dir": temporary,
                "platform": "windows",
                "image_base": 0x400000,
            }
            cases = (
                {"xref_strings": [], "xref_funcs": ["0x401000"]},
                {"exclude_funcs": ["0x401000"]},
                {"exclude_callees": ["0x401000"]},
                {"xref_strings": [], "inline_alias": "0x401000"},
            )
            for overrides in cases:
                with self.subTest(overrides=overrides):
                    session = SimpleNamespace(call_tool=AsyncMock())
                    result = await preprocess_func_xrefs_via_mcp(**{**base_kwargs, **overrides, "session": session})
                    self.assertIsNone(result)
                    session.call_tool.assert_not_awaited()

            async def call_tool(name, arguments):
                self.assertEqual("py_eval", name)
                self.assertIn("3735928559", arguments["code"])
                return {
                    "pointer_size": 4,
                    "candidates": [
                        {
                            "func_name": "Target",
                            "func_va": "0x401000",
                            "func_rva": "0x1000",
                            "func_size": "0x40",
                        }
                    ],
                }

            result = await preprocess_func_xrefs_via_mcp(
                **{
                    **base_kwargs,
                    "session": SimpleNamespace(call_tool=call_tool),
                    "xref_strings": [],
                    "xref_gvs": ["0xDEADBEEF"],
                }
            )

        self.assertEqual("Target", result["func_name"])

    async def test_func_xref_nonunique_signature_keeps_basic_function_metadata(self):
        async def call_tool(name, _arguments):
            if name == "py_eval":
                return {
                    "pointer_size": 4,
                    "candidates": [
                        {
                            "func_name": "Target",
                            "func_va": "0x401000",
                            "func_rva": "0x1000",
                            "func_size": "0x40",
                            "func_sig": "55 8B EC 83 EC ??",
                        }
                    ],
                }
            return {"matches": ["0x401000", "0x402000"], "n": 2}

        result = await preprocess_func_xrefs_via_mcp(
            session=SimpleNamespace(call_tool=call_tool),
            func_name="Target",
            xref_strings=["anchor"],
            xref_gvs=[],
            xref_signatures=[],
            xref_funcs=[],
            exclude_funcs=[],
            exclude_strings=[],
            exclude_gvs=[],
            exclude_signatures=[],
            new_binary_dir=None,
            platform="windows",
            image_base=0x400000,
        )

        self.assertEqual(
            {
                "func_name": "Target",
                "func_va": "0x401000",
                "func_rva": "0x1000",
                "func_size": "0x40",
                "_pointer_size": 4,
            },
            result,
        )

    async def test_pattern_d_llm_fallback_uses_dependency_contract_and_verified_call(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            prompt = root / "prompt.md"
            reference = root / "reference.yaml"
            current = root / "Predecessor.windows.yaml"
            output = root / "Target.windows.yaml"
            prompt.write_text("Compare reference and target.", encoding="utf-8")
            reference.write_text(
                "func_name: Predecessor\nfunc_va: '0x401000'\ndisasm_code: call Target\nprocedure: Target();\n",
                encoding="utf-8",
            )
            current.write_text("func_name: Predecessor\nfunc_va: '0x401000'\n", encoding="utf-8")

            async def call_tool(name, arguments):
                if name == "find_bytes":
                    return {"matches": ["0x402000"], "n": 1}
                self.assertEqual("py_eval", name)
                code = arguments["code"]
                if "format_name = 'json'" in code and "output_path = " in code:
                    output_path = None
                    for line in code.splitlines():
                        if line.startswith("output_path = "):
                            output_path = ast.literal_eval(line.split("=", 1)[1].strip())
                            break
                    self.assertIsInstance(output_path, str)
                    payload = {
                        "pointer_size": 4,
                        "func_start": "0x401000",
                        "func_end": "0x401100",
                        "disasm_code": "0x401020: call sub_402000",
                        "procedure": "sub_402000();",
                    }
                    Path(output_path).write_text(json.dumps(payload), encoding="utf-8")
                    return {
                        "ok": True,
                        "output_path": output_path,
                        "bytes_written": Path(output_path).stat().st_size,
                        "format": "json",
                    }
                if "operand_targets" in code:
                    return {
                        "pointer_size": 4,
                        "size": 5,
                        "func_start": "0x401000",
                        "func_end": "0x401100",
                        "line": "call sub_402000",
                        "mnemonic": "call",
                        "code_refs": ["0x402000"],
                        "data_refs": [],
                        "operand_targets": ["0x402000"],
                        "displacements": [],
                        "operand_offsets": [1],
                    }
                return {
                    "pointer_size": 4,
                    "function": {
                        "func_va": "0x402000",
                        "func_rva": "0x2000",
                        "func_size": "0x30",
                        "func_sig": "55 8B EC 83 EC ??",
                    },
                }

            llm_result = """\
found_vcall: []
found_call:
  - func_name: Target
    insn_va: '0x401020'
    insn_disasm: call sub_402000
found_funcptr: []
found_gv: []
found_struct_offset: []
"""
            with patch("ida_llm_decompile.request_text", return_value=llm_result):
                result = await preprocess_common_skill(
                    session=SimpleNamespace(call_tool=call_tool),
                    expected_outputs=[str(output)],
                    new_binary_dir=root,
                    platform="windows",
                    image_base=0x400000,
                    func_names=["Target"],
                    llm_decompile_specs=[
                        {
                            "symbol_name": "Target",
                            "prompt_path": str(prompt),
                            "reference_yaml_paths": [str(reference)],
                            "expected_result_sections": ["found_call"],
                            "dependency_policy": {"Predecessor.{platform}.yaml": "required"},
                        }
                    ],
                    llm_config={
                        "model": "test-model",
                        "api_key": "test-key",
                        "_expected_inputs": [str(current)],
                        "_optional_inputs": [],
                    },
                    generate_yaml_desired_fields=[
                        ("Target", ["func_name", "func_sig", "func_va", "func_rva", "func_size"])
                    ],
                )
            self.assertTrue(result)
            self.assertEqual("Target", yaml.safe_load(output.read_text(encoding="utf-8"))["func_name"])

    async def test_struct_member_llm_fallback_preserves_old_yaml_canonical_name(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            symbol_name = "CBaseEntity_m_modelState_m_simulationState"
            old_output = root / "old.yaml"
            output = root / f"{symbol_name}.windows.yaml"
            old_output.write_text(
                "struct_name: CBaseEntity\nmember_name: m_modelState.m_simulationState\noffset: '0x0'\n",
                encoding="utf-8",
            )
            llm_result = {
                "found_struct_offset": [
                    {
                        "struct_name": "CBaseEntity",
                        "member_name": "m_modelState_m_simulationState",
                        "insn_va": "0x401020",
                        "offset": "0x0",
                    }
                ]
            }
            instruction = {
                "size": 3,
                "func_start": "0x401000",
                "func_end": "0x401100",
                "line": "mov eax, [ecx]",
                "displacements": ["0x0"],
            }

            with (
                patch("ida_analyze_util.preprocess_struct_offset_sig_via_mcp", new=AsyncMock(return_value=None)),
                patch(
                    "ida_analyze_util._prepare_llm_context",
                    return_value={
                        "model": "test-model",
                        "prompt_path": "prompt.md",
                        "reference_yaml_paths": ["reference.yaml"],
                        "temperature": None,
                    },
                ),
                patch(
                    "ida_analyze_util._call_llm_for_targets",
                    new=AsyncMock(return_value=(llm_result, [(0x401000, 0x401100)])),
                ),
                patch("ida_analyze_util._inspect_llm_instruction", new=AsyncMock(return_value=instruction)),
                patch(
                    "ida_analyze_util._inspect_function_via_mcp",
                    new=AsyncMock(return_value={"func_va": "0x401000", "func_sig": "55 8B EC"}),
                ),
            ):
                result = await preprocess_common_skill(
                    session=SimpleNamespace(call_tool=AsyncMock()),
                    expected_outputs=[str(output)],
                    old_yaml_map={str(output): str(old_output)},
                    new_binary_dir=root,
                    platform="windows",
                    image_base=0x400000,
                    struct_member_names=[symbol_name],
                    llm_decompile_specs=[
                        {
                            "symbol_name": symbol_name,
                            "prompt_path": "prompt.md",
                            "reference_yaml_paths": ["reference.yaml"],
                            "expected_result_sections": ["found_struct_offset"],
                            "dependency_policy": {"dependency.yaml": "required"},
                        }
                    ],
                    llm_config={"model": "test-model"},
                    generate_yaml_desired_fields=[
                        (symbol_name, ["struct_name", "member_name", "offset", "offset_sig", "offset_sig_disp"])
                    ],
                )

            self.assertTrue(result)
            payload = yaml.safe_load(output.read_text(encoding="utf-8"))
            self.assertEqual("CBaseEntity", payload["struct_name"])
            self.assertEqual("m_modelState.m_simulationState", payload["member_name"])

    async def test_llm_batch_groups_two_unresolved_regular_functions(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            outputs = [root / "TargetA.windows.yaml", root / "TargetB.windows.yaml"]
            specs = [
                {
                    "symbol_name": name,
                    "prompt_path": "prompt.md",
                    "reference_yaml_paths": ["reference.windows.yaml"],
                    "expected_result_sections": ["found_call"],
                    "dependency_policy": {"Predecessor.windows.yaml": "required"},
                }
                for name in ("TargetA", "TargetB")
            ]
            llm_result = {
                "found_vcall": [],
                "found_call": [
                    {
                        "func_name": "TargetA",
                        "insn_va": "0x401020",
                        "insn_disasm": "call sub_402000",
                    },
                    {
                        "func_name": "TargetB",
                        "insn_va": "0x401030",
                        "insn_disasm": "call sub_403000",
                    },
                ],
                "found_funcptr": [],
                "found_gv": [],
                "found_struct_offset": [],
            }
            details = {
                0x401020: {
                    "func_start": "0x401000",
                    "line": "call sub_402000",
                    "code_refs": ["0x402000"],
                },
                0x401030: {
                    "func_start": "0x401000",
                    "line": "call sub_403000",
                    "code_refs": ["0x403000"],
                },
            }

            async def inspect_instruction(_session, ea):
                return details[int(ea, 0) if isinstance(ea, str) else ea]

            async def inspect_function(_session, ea, image_base, name):
                return {
                    "func_name": name,
                    "func_va": hex(ea),
                    "func_rva": hex(ea - image_base),
                    "func_size": "0x20",
                    "func_sig": "55 8B EC 83 EC ??",
                }

            context = {
                "model": "test-model",
                "prompt_path": "prompt.md",
                "reference_yaml_paths": ["reference.windows.yaml"],
                "temperature": None,
            }
            with (
                patch("ida_analyze_util.preprocess_func_sig_via_mcp", new=AsyncMock(return_value=None)),
                patch("ida_analyze_util._prepare_llm_context", return_value=context),
                patch(
                    "ida_analyze_util._call_llm_for_targets",
                    new=AsyncMock(return_value=(llm_result, [(0x401000, 0x401100)])),
                ) as call_llm,
                patch("ida_analyze_util._inspect_llm_instruction", new=inspect_instruction),
                patch("ida_analyze_util._inspect_function_via_mcp", new=inspect_function),
            ):
                result = await preprocess_common_skill(
                    session=SimpleNamespace(call_tool=AsyncMock()),
                    expected_outputs=[str(path) for path in outputs],
                    new_binary_dir=root,
                    platform="windows",
                    image_base=0x400000,
                    func_names=["TargetA", "TargetB"],
                    llm_decompile_specs=specs,
                    llm_config={"model": "test-model"},
                    generate_yaml_desired_fields=[
                        (name, ["func_name", "func_sig", "func_va", "func_rva", "func_size"])
                        for name in ("TargetA", "TargetB")
                    ],
                )

            self.assertTrue(result)
            call_llm.assert_awaited_once()
            self.assertEqual(["TargetA", "TargetB"], call_llm.await_args.kwargs["symbol_names"])
            self.assertEqual(
                ["TargetA", "TargetB"],
                [yaml.safe_load(path.read_text(encoding="utf-8"))["func_name"] for path in outputs],
            )

    async def test_llm_batch_excludes_function_resolved_by_fast_path(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            outputs = [root / "FastTarget.windows.yaml", root / "LlmTarget.windows.yaml"]
            specs = [
                {
                    "symbol_name": name,
                    "prompt_path": "prompt.md",
                    "reference_yaml_paths": ["reference.windows.yaml"],
                    "expected_result_sections": ["found_call"],
                    "dependency_policy": {"Predecessor.windows.yaml": "required"},
                }
                for name in ("FastTarget", "LlmTarget")
            ]
            fast_candidate = {
                "func_name": "FastTarget",
                "func_va": "0x402000",
                "func_rva": "0x2000",
                "func_size": "0x20",
                "func_sig": "55 8B EC 83 EC ??",
            }

            async def fast_path(*_args, func_name=None, **_kwargs):
                return fast_candidate if func_name == "FastTarget" else None

            llm_result = {
                "found_vcall": [],
                "found_call": [
                    {
                        "func_name": "LlmTarget",
                        "insn_va": "0x401020",
                        "insn_disasm": "call sub_403000",
                    }
                ],
                "found_funcptr": [],
                "found_gv": [],
                "found_struct_offset": [],
            }
            context = {
                "model": "test-model",
                "prompt_path": "prompt.md",
                "reference_yaml_paths": ["reference.windows.yaml"],
                "temperature": None,
            }
            with (
                patch("ida_analyze_util.preprocess_func_sig_via_mcp", new=fast_path),
                patch("ida_analyze_util._prepare_llm_context", return_value=context),
                patch(
                    "ida_analyze_util._call_llm_for_targets",
                    new=AsyncMock(return_value=(llm_result, [(0x401000, 0x401100)])),
                ) as call_llm,
                patch(
                    "ida_analyze_util._inspect_llm_instruction",
                    new=AsyncMock(
                        return_value={
                            "func_start": "0x401000",
                            "line": "call sub_403000",
                            "code_refs": ["0x403000"],
                        }
                    ),
                ),
                patch(
                    "ida_analyze_util._inspect_function_via_mcp",
                    new=AsyncMock(
                        return_value={
                            "func_name": "LlmTarget",
                            "func_va": "0x403000",
                            "func_rva": "0x3000",
                            "func_size": "0x20",
                            "func_sig": "55 8B EC 83 EC ??",
                        }
                    ),
                ),
            ):
                result = await preprocess_common_skill(
                    session=SimpleNamespace(call_tool=AsyncMock()),
                    expected_outputs=[str(path) for path in outputs],
                    new_binary_dir=root,
                    platform="windows",
                    image_base=0x400000,
                    func_names=["FastTarget", "LlmTarget"],
                    llm_decompile_specs=specs,
                    llm_config={"model": "test-model"},
                    generate_yaml_desired_fields=[
                        (name, ["func_name", "func_sig", "func_va", "func_rva", "func_size"])
                        for name in ("FastTarget", "LlmTarget")
                    ],
                )

            self.assertTrue(result)
            call_llm.assert_awaited_once()
            self.assertEqual(["LlmTarget"], call_llm.await_args.kwargs["symbol_names"])

    async def test_function_fast_path_waits_for_predecessor_output(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            dependency_output = root / "Dependency.windows.yaml"
            target_output = root / "Target.windows.yaml"
            fast_path_calls = []

            async def fast_path(*_args, func_name=None, **_kwargs):
                fast_path_calls.append(func_name)
                if func_name == "Dependency":
                    return {
                        "func_name": "Dependency",
                        "func_va": "0x401000",
                        "func_rva": "0x1000",
                        "func_size": "0x20",
                        "func_sig": "55 8B EC 90",
                    }
                self.assertTrue(dependency_output.is_file())
                return None

            async def xref_path(**kwargs):
                self.assertEqual("Target", kwargs["func_name"])
                self.assertTrue(dependency_output.is_file())
                return {
                    "func_name": "Target",
                    "func_va": "0x402000",
                    "func_rva": "0x2000",
                    "func_size": "0x20",
                    "func_sig": "55 8B EC 91",
                }

            with (
                patch("ida_analyze_util.preprocess_func_sig_via_mcp", new=fast_path),
                patch(
                    "ida_analyze_util.preprocess_func_xrefs_via_mcp",
                    new=AsyncMock(side_effect=xref_path),
                ) as xref_fast_path,
            ):
                result = await preprocess_common_skill(
                    session=SimpleNamespace(call_tool=AsyncMock()),
                    expected_outputs=[str(dependency_output), str(target_output)],
                    new_binary_dir=root,
                    platform="windows",
                    image_base=0x400000,
                    func_names=["Dependency", "Target"],
                    func_xrefs=[{"func_name": "Target", "xref_funcs": ["Dependency"]}],
                    generate_yaml_desired_fields=[
                        (name, ["func_name", "func_sig", "func_va", "func_rva", "func_size"])
                        for name in ("Dependency", "Target")
                    ],
                )

            self.assertTrue(result)
            self.assertEqual(["Dependency", "Target"], fast_path_calls)
            xref_fast_path.assert_awaited_once()
            self.assertEqual("Dependency", yaml.safe_load(dependency_output.read_text(encoding="utf-8"))["func_name"])
            self.assertEqual("Target", yaml.safe_load(target_output.read_text(encoding="utf-8"))["func_name"])

    async def test_vtable_output_is_emitted_before_related_function_fast_path(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            vtable_output = root / "TargetClass_vtable.windows.yaml"
            function_output = root / "VirtualTarget.windows.yaml"
            call_order = []
            vtable_candidate = {
                "vtable_class": "TargetClass",
                "vtable_symbol": "??_7TargetClass@@6B@",
                "vtable_va": "0x410000",
                "vtable_rva": "0x10000",
                "vtable_size": "0x4",
                "vtable_numvfunc": 1,
                "vtable_entries": {0: "0x402000"},
            }

            async def vtable_path(*_args, **_kwargs):
                call_order.append("vtable")
                return vtable_candidate

            async def function_path(*_args, **_kwargs):
                call_order.append("function")
                self.assertTrue(vtable_output.is_file())
                return {
                    "func_name": "VirtualTarget",
                    "func_va": "0x402000",
                    "func_rva": "0x2000",
                    "func_size": "0x20",
                    "vtable_name": "TargetClass",
                    "vfunc_offset": "0x0",
                    "vfunc_index": 0,
                }

            with (
                patch("ida_analyze_util.preprocess_vtable_via_mcp", new=vtable_path),
                patch("ida_analyze_util.preprocess_func_sig_via_mcp", new=function_path),
            ):
                result = await preprocess_common_skill(
                    session=SimpleNamespace(call_tool=AsyncMock()),
                    expected_outputs=[str(vtable_output), str(function_output)],
                    new_binary_dir=root,
                    platform="windows",
                    image_base=0x400000,
                    func_names=["VirtualTarget"],
                    vtable_class_names=["TargetClass"],
                    func_vtable_relations=[("VirtualTarget", "TargetClass")],
                    generate_yaml_desired_fields=[
                        (
                            "TargetClass",
                            [
                                "vtable_class",
                                "vtable_symbol",
                                "vtable_va",
                                "vtable_rva",
                                "vtable_size",
                                "vtable_numvfunc",
                                "vtable_entries",
                            ],
                        ),
                        (
                            "VirtualTarget",
                            [
                                "func_name",
                                "func_va",
                                "func_rva",
                                "func_size",
                                "vtable_name",
                                "vfunc_offset",
                                "vfunc_index",
                            ],
                        ),
                    ],
                )

            self.assertTrue(result)
            self.assertEqual(["vtable", "function"], call_order)
            self.assertEqual("TargetClass", yaml.safe_load(vtable_output.read_text(encoding="utf-8"))["vtable_class"])

    async def test_llm_batch_includes_unresolved_global_variable(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            func_output = root / "Target.windows.yaml"
            gv_output = root / "g_Target.windows.yaml"
            specs = [
                {
                    "symbol_name": "Target",
                    "prompt_path": "prompt.md",
                    "reference_yaml_paths": ["reference.windows.yaml"],
                    "expected_result_sections": ["found_call"],
                    "dependency_policy": {"Predecessor.windows.yaml": "required"},
                },
                {
                    "symbol_name": "g_Target",
                    "prompt_path": "prompt.md",
                    "reference_yaml_paths": ["reference.windows.yaml"],
                    "expected_result_sections": ["found_gv"],
                    "dependency_policy": {"Predecessor.windows.yaml": "required"},
                },
            ]
            llm_result = {
                "found_vcall": [],
                "found_call": [
                    {
                        "func_name": "Target",
                        "insn_va": "0x401020",
                        "insn_disasm": "call sub_402000",
                    }
                ],
                "found_funcptr": [],
                "found_gv": [
                    {
                        "gv_name": "g_Target",
                        "insn_va": "0x401040",
                        "insn_disasm": "mov eax, ds:dword_404000",
                    }
                ],
                "found_struct_offset": [],
            }
            details = {
                0x401020: {
                    "func_start": "0x401000",
                    "line": "call sub_402000",
                    "code_refs": ["0x402000"],
                },
                0x401040: {
                    "func_start": "0x401000",
                    "line": "mov eax, ds:dword_404000",
                    "size": 5,
                    "data_refs": ["0x404000"],
                    "operand_targets": [],
                    "operand_offsets": [1],
                },
            }

            async def inspect_instruction(_session, ea):
                return details[int(ea, 0) if isinstance(ea, str) else ea]

            async def inspect_function(_session, ea, image_base, name):
                if name == "__llm_anchor":
                    return {"func_va": "0x401000", "func_sig": "55 8B EC 83 EC ??"}
                return {
                    "func_name": name,
                    "func_va": hex(ea),
                    "func_rva": hex(ea - image_base),
                    "func_size": "0x20",
                    "func_sig": "55 8B EC 83 EC ??",
                }

            context = {
                "model": "test-model",
                "prompt_path": "prompt.md",
                "reference_yaml_paths": ["reference.windows.yaml"],
                "temperature": None,
            }
            with (
                patch("ida_analyze_util.preprocess_func_sig_via_mcp", new=AsyncMock(return_value=None)),
                patch("ida_analyze_util.preprocess_gv_sig_via_mcp", new=AsyncMock(return_value=None)),
                patch("ida_analyze_util._prepare_llm_context", return_value=context),
                patch(
                    "ida_analyze_util._call_llm_for_targets",
                    new=AsyncMock(return_value=(llm_result, [(0x401000, 0x401100)])),
                ) as call_llm,
                patch("ida_analyze_util._inspect_llm_instruction", new=inspect_instruction),
                patch("ida_analyze_util._inspect_function_via_mcp", new=inspect_function),
            ):
                result = await preprocess_common_skill(
                    session=SimpleNamespace(call_tool=AsyncMock()),
                    expected_outputs=[str(func_output), str(gv_output)],
                    new_binary_dir=root,
                    platform="windows",
                    image_base=0x400000,
                    func_names=["Target"],
                    gv_names=["g_Target"],
                    llm_decompile_specs=specs,
                    llm_config={"model": "test-model"},
                    generate_yaml_desired_fields=[
                        ("Target", ["func_name", "func_sig", "func_va", "func_rva", "func_size"]),
                        (
                            "g_Target",
                            [
                                "gv_name",
                                "gv_va",
                                "gv_rva",
                                "gv_sig",
                                "gv_sig_va",
                                "gv_inst_offset",
                                "gv_inst_length",
                                "gv_inst_disp",
                            ],
                        ),
                    ],
                )

            self.assertTrue(result)
            call_llm.assert_awaited_once()
            self.assertEqual(["Target", "g_Target"], call_llm.await_args.kwargs["symbol_names"])
            self.assertEqual("g_Target", yaml.safe_load(gv_output.read_text(encoding="utf-8"))["gv_name"])

    async def test_llm_global_can_retry_with_across_boundary_signature_budget(self):
        llm_result = {
            "found_vcall": [],
            "found_call": [],
            "found_funcptr": [],
            "found_gv": [
                {
                    "gv_name": "g_Target",
                    "insn_va": "0x401040",
                    "insn_disasm": "mov eax, ds:dword_404000",
                }
            ],
            "found_struct_offset": [],
        }
        extended_function = {
            "func_va": "0x401000",
            "func_sig": "55 8B EC 83 EC ?? 53 56 57 8B F9",
        }
        inspect_function = AsyncMock(side_effect=[None, extended_function])
        with (
            patch(
                "ida_analyze_util._inspect_llm_instruction",
                new=AsyncMock(
                    return_value={
                        "func_start": "0x401000",
                        "line": "mov eax, ds:dword_404000",
                        "size": 5,
                        "data_refs": ["0x404000"],
                        "operand_targets": [],
                        "operand_offsets": [1],
                    }
                ),
            ),
            patch("ida_analyze_util._inspect_function_via_mcp", new=inspect_function),
        ):
            candidate = await _preprocess_llm_target(
                session=SimpleNamespace(call_tool=AsyncMock()),
                symbol_name="g_Target",
                category="gv",
                spec={"expected_result_sections": ["found_gv"]},
                llm_config={"model": "test-model"},
                new_binary_dir=Path("D:/game/engine"),
                platform="windows",
                image_base=0x400000,
                desired_fields=[
                    "gv_name",
                    "gv_va",
                    "gv_rva",
                    "gv_sig",
                    "gv_sig_va",
                    "gv_inst_offset",
                    "gv_inst_length",
                    "gv_inst_disp",
                    "gv_sig_allow_across_function_boundary",
                ],
                llm_result=llm_result,
                target_ranges=[(0x401000, 0x401100)],
            )

        self.assertEqual(extended_function["func_sig"], candidate["gv_sig"])
        self.assertTrue(candidate["gv_sig_allow_across_function_boundary"])
        self.assertEqual(
            [
                call(ANY, 0x401000, 0x400000, "__llm_anchor"),
                call(
                    ANY,
                    0x401000,
                    0x400000,
                    "__llm_anchor",
                    allow_across_function_boundary=True,
                ),
            ],
            inspect_function.await_args_list,
        )

    def test_optional_global_across_boundary_marker_is_a_desired_output_field(self):
        desired = ida_analyze_util._desired_fields_map(
            [
                (
                    "g_Target",
                    [
                        "gv_name",
                        "gv_sig",
                        "gv_sig_allow_across_function_boundary?",
                    ],
                )
            ]
        )

        self.assertIsNotNone(desired)
        field_spec = desired["g_Target"]
        self.assertIn("gv_sig_allow_across_function_boundary", field_spec["fields"])
        self.assertIn("gv_sig_allow_across_function_boundary", field_spec["optional_fields"])
        self.assertNotIn("gv_sig_allow_across_function_boundary", field_spec["generation_options"])

    async def test_llm_global_emits_pic_addend_for_register_relative_displacement(self):
        llm_result = {
            "found_vcall": [],
            "found_call": [],
            "found_funcptr": [],
            "found_gv": [
                {
                    "gv_name": "g_Target",
                    "insn_va": "0x401040",
                    "insn_disasm": "mov [eax+0x4A388D4], edx",
                }
            ],
            "found_struct_offset": [],
        }
        function = {
            "func_va": "0x401000",
            "func_sig": "8B 54 24 ?? 89 90 ?? ?? ?? ?? C3",
        }
        desired_fields = [
            "gv_name",
            "gv_va",
            "gv_rva",
            "gv_sig",
            "gv_sig_va",
            "gv_inst_offset",
            "gv_inst_length",
            "gv_inst_disp",
            "gv_pic_addend?",
        ]

        async def run(operand_pic, operand_dwords):
            with (
                patch(
                    "ida_analyze_util._inspect_llm_instruction",
                    new=AsyncMock(
                        return_value={
                            "func_start": "0x401000",
                            "line": "mov [eax+0x4A388D4], edx",
                            "size": 6,
                            "data_refs": ["0x4d268d4"],
                            "operand_targets": [],
                            "operand_offsets": [2],
                            "operand_pic": operand_pic,
                            "operand_dwords": operand_dwords,
                        }
                    ),
                ),
                patch("ida_analyze_util._inspect_function_via_mcp", new=AsyncMock(return_value=function)),
            ):
                return await _preprocess_llm_target(
                    session=SimpleNamespace(call_tool=AsyncMock()),
                    symbol_name="g_Target",
                    category="gv",
                    spec={"expected_result_sections": ["found_gv"]},
                    llm_config={"model": "test-model"},
                    new_binary_dir=Path("D:/game/engine"),
                    platform="linux",
                    image_base=0x400000,
                    desired_fields=desired_fields,
                    llm_result=llm_result,
                    target_ranges=[(0x401000, 0x401100)],
                )

        pic_candidate = await run([True], ["0x4a388d4"])
        self.assertIsNotNone(pic_candidate)
        # The addend recovers an RVA even when the IDB image base is nonzero.
        self.assertEqual("0xffeee000", pic_candidate["gv_pic_addend"])

        absolute_candidate = await run([False], ["0x4d268d4"])
        self.assertIsNotNone(absolute_candidate)
        # Absolute form: the embedded dword already is the address.
        self.assertNotIn("gv_pic_addend", absolute_candidate)

    def test_gv_resolution_rebases_pic_and_adjusts_absolute_members(self):
        # MSVC indexed absolute operands may also decode as o_displ.
        self.assertEqual(
            {},
            _gv_resolution_fields(
                {"operand_offsets": [2], "operand_pic": [True], "operand_dwords": ["0x2345678"]},
                0x2345678,
                0x1D00000,
                platform="windows",
            ),
        )
        for embedded, target_rva, pic in (
            (0xA388D4, 0xD268D4, True),
            (0x602A14, 0x1BDA774, True),
            (0xFFFF4044, 0x2E2040, True),
            (0x2579C4, 0x2579C0, False),
        ):
            for image_base in (0, 0x400000):
                with self.subTest(embedded=embedded, image_base=image_base):
                    operand = embedded if pic else embedded + image_base
                    detail = {"operand_offsets": [2], "operand_pic": [pic], "operand_dwords": [hex(operand)]}
                    fields = _gv_resolution_fields(detail, target_rva + image_base, image_base)
                    load_base = 0x50000000
                    if pic:
                        actual = load_base + ((operand + int(fields["gv_pic_addend"], 0)) & 0xFFFFFFFF)
                    else:
                        actual = load_base + embedded + int(fields.get("gv_address_offset", "0"), 0)
                    self.assertEqual(load_base + target_rva, actual & 0xFFFFFFFF)

    def test_unindexed_address_load_decoder_preserves_the_memory_address(self):
        namespace = {}
        exec(ida_analyze_util._ADDRESS_FLOW_RESOLVER, namespace)
        decode = namespace["decode_address_load"]
        self.assertEqual((6, 0x242324), decode(bytes.fromhex("8B 96 24 23 24 00")))
        self.assertEqual((1, 0x242324), decode(bytes.fromhex("8B 89 24 23 24 00")))
        self.assertEqual((6, 0xFFFFFFFC), decode(bytes.fromhex("8D 86 FC FF FF FF")))
        self.assertEqual((2, 0x6020), decode(bytes.fromhex("89 82 20 60 00 00")))
        for unsupported in (
            "89 04 B5 24 23 24 00",
            "8B 04 B5 24 23 24 00",
            "66 8B 86 24 23 24 00",
            "8B 46 04",
            "8B 05 24 23 24 00",
        ):
            self.assertIsNone(decode(bytes.fromhex(unsupported)))

    def test_relative_store_resolution_overrides_mapped_displacement(self):
        detail = {
            "data_refs": ["0x6020"],
            "operand_targets": [],
            "operand_pic": [True, False],
            "relative_store_address": {"target": "0x806020"},
        }
        self.assertEqual(["0x806020"], ida_analyze_util._llm_global_targets(detail))
        detail["relative_store_address"] = {"target": None, "issue": "Unknown EDX base"}
        self.assertEqual([], ida_analyze_util._llm_global_targets(detail))
        self.assertEqual(["0x6020"], ida_analyze_util._llm_global_targets(detail, platform="windows"))

    def test_relative_store_inspection_checks_effective_address(self):
        for base, mapped, clobbered, width, permission, unknown_lea in (
            (0x8000, True, False, 4, 6, False),
            (0xA000, True, False, 4, 6, False),
            (0x8000, False, False, 4, 6, False),
            (0x8000, True, True, 4, 6, False),
            (0x8000, True, False, 3, 6, False),
            (0x8000, True, False, 4, 7, False),
            (0x8000, True, False, 4, 6, True),
        ):
            with self.subTest(
                base=base,
                mapped=mapped,
                clobbered=clobbered,
                width=width,
                permission=permission,
                unknown_lea=unknown_lea,
            ):
                ea, displacement = 0x1010, 0x2000
                register = SimpleNamespace(type=1, reg=2, dtype=2, offb=0)
                source = SimpleNamespace(type=1, reg=0, dtype=2, offb=0)
                memory = SimpleNamespace(type=4, addr=displacement, offb=2, dtype=2)
                void = SimpleNamespace(type=0)
                store = SimpleNamespace(ops=[memory, source, void])
                definition = SimpleNamespace(
                    ops=[register, memory if unknown_lea else SimpleNamespace(type=5, value=base), void], size=6
                )
                segment = SimpleNamespace(perm=permission, end_ea=base + displacement + width)

                def getseg(address):
                    if address in (base, displacement) or (mapped and address == base + displacement):
                        return segment
                    return None

                block = SimpleNamespace(id=0, start_ea=0x1000, end_ea=0x1016, preds=lambda: [])
                modules = {
                    "ida_bytes": SimpleNamespace(
                        get_dword=lambda address: displacement,
                        get_bytes=lambda address, size: bytes.fromhex(
                            "8D 91 00 20 00 00" if address == 0x1000 else "89 82 00 20 00 00"
                        ),
                    ),
                    "ida_fixup": SimpleNamespace(fixup_data_t=lambda: None, get_fixup=lambda *args: False),
                    "ida_funcs": SimpleNamespace(get_func=lambda address: block),
                    "ida_lines": SimpleNamespace(tag_remove=lambda text: text),
                    "ida_segment": SimpleNamespace(getseg=getseg, SEGPERM_EXEC=1),
                    "idaapi": SimpleNamespace(inf_is_64bit=lambda: False, BADADDR=0xFFFFFFFF),
                    "ida_ua": SimpleNamespace(
                        o_void=0,
                        o_reg=1,
                        o_mem=2,
                        o_phrase=3,
                        o_displ=4,
                        o_imm=5,
                        o_near=6,
                        o_far=7,
                        dt_byte=0,
                        dt_dword=2,
                        insn_t=lambda: store,
                        decode_insn=lambda *args: 6,
                    ),
                    "ida_gdl": SimpleNamespace(FlowChart=lambda func: [block]),
                    "idautils": SimpleNamespace(
                        DataRefsFrom=lambda address: [base] if address == 0x1000 else [displacement],
                        CodeRefsFrom=lambda *args: [],
                        Heads=lambda *args: [0x1000, 0x1006, ea] if clobbered else [0x1000, ea],
                        DecodeInstruction=lambda address: definition if address != ea else store,
                    ),
                    "idc": SimpleNamespace(
                        generate_disasm_line=lambda *args: "mov [edx+2000h], eax",
                        print_insn_mnem=lambda address: (
                            "lea" if unknown_lea and address == 0x1000 else "xor" if address == 0x1006 else "mov"
                        ),
                    ),
                }
                namespace = {}
                with patch.dict("sys.modules", modules):
                    exec(
                        ida_analyze_util._INSPECT_LLM_INSTRUCTION_PY_EVAL.replace("EA_PLACEHOLDER", str(ea)), namespace
                    )
                detail = json.loads(namespace["result"])
                self.assertEqual([hex(displacement)], detail["data_refs"])
                if mapped and not clobbered and width >= 4 and permission == 6 and not unknown_lea:
                    self.assertEqual([hex(base + displacement)], ida_analyze_util._llm_global_targets(detail))
                    self.assertEqual(hex(base), _gv_resolution_fields(detail, base + displacement, 0)["gv_pic_addend"])
                else:
                    self.assertEqual([], ida_analyze_util._llm_global_targets(detail))
                    self.assertTrue(detail["relative_store_address"]["issue"])

    def test_address_flow_requires_agreement_on_every_incoming_path(self):
        namespace = {}
        exec(ida_analyze_util._ADDRESS_FLOW_RESOLVER, namespace)
        resolve = namespace["resolve_address_flow"]
        graph = {
            0: {"preds": [], "writes": [{6: ("constant", 0x2000)}]},
            1: {"preds": [0], "writes": [{0: None, 1: None, 2: None}]},
            2: {"preds": [0], "writes": []},
            3: {"preds": [1, 2], "writes": []},
        }
        self.assertEqual(0x2000, resolve(graph, 3, 0, 6))
        graph[2]["writes"] = [{6: ("constant", 0x3000)}]
        self.assertIsNone(resolve(graph, 3, 0, 6))
        graph[2]["writes"] = [{6: None}]
        self.assertIsNone(resolve(graph, 3, 0, 6))
        graph[2]["writes"] = []
        graph[3]["writes"] = [{7: ("register", 6)}]
        self.assertEqual(0x2000, resolve(graph, 3, 1, 7))
        graph[4] = {"preds": [], "writes": []}
        graph[3]["preds"].append(4)
        reachable = namespace["reachable_address_graph"](graph, 0)
        self.assertEqual(0x2000, resolve(reachable, 3, 1, 7))
        graph[3]["preds"].remove(4)
        graph[0]["preds"] = [3]
        graph[0]["writes"] = []
        self.assertIsNone(resolve(graph, 3, 1, 7))

    def test_address_flow_preserves_pic_base_arithmetic_and_rejects_clobbers(self):
        namespace = {}
        exec(ida_analyze_util._ADDRESS_FLOW_RESOLVER, namespace)
        graph = {
            0: {
                "preds": [],
                "writes": [
                    {3: ("constant", 0x1005)},
                    {3: ("offset", 0x6FFB)},
                    {2: ("register", 3)},
                    {2: ("offset", -4)},
                ],
            }
        }
        resolve = namespace["resolve_address_flow"]
        self.assertEqual(0x7FFC, resolve(graph, 0, 4, 2))
        graph[0]["writes"][0] = {3: None}
        self.assertIsNone(resolve(graph, 0, 4, 2))

    def test_address_flow_high_byte_write_invalidates_its_parent_register(self):
        namespace = {}
        exec(ida_analyze_util._ADDRESS_FLOW_RESOLVER, namespace)
        register = namespace["address_write_register"]
        self.assertEqual(0, register(4, True))  # AH writes EAX, not ESP.
        self.assertEqual(3, register(7, True))  # BH writes EBX, not EDI.
        self.assertEqual(4, register(4, False))
        graph = {0: {"preds": [], "writes": [{0: ("constant", 0x2000)}, {register(4, True): None}]}}
        self.assertIsNone(namespace["resolve_address_flow"](graph, 0, 2, 0))

    def test_instruction_inspection_distinguishes_relocated_indexed_operands(self):
        class Fixup:
            pass

        for relocated in (False, True):

            def get_fixup(fixup, address):
                self.assertIsInstance(fixup, Fixup)
                self.assertEqual(0x1002, address)
                return relocated

            modules = {
                "ida_bytes": SimpleNamespace(
                    get_dword=lambda ea: 0x2004, get_bytes=lambda ea, size: bytes.fromhex("8B 83 04 20 00 00")
                ),
                "ida_fixup": SimpleNamespace(fixup_data_t=Fixup, get_fixup=get_fixup),
                "ida_funcs": SimpleNamespace(get_func=lambda ea: SimpleNamespace(start_ea=0x1000, end_ea=0x1010)),
                "ida_lines": SimpleNamespace(tag_remove=lambda text: text),
                "ida_segment": SimpleNamespace(getseg=lambda ea: object() if ea in (0x2004, 0x3004) else None),
                "idaapi": SimpleNamespace(inf_is_64bit=lambda: False, BADADDR=0xFFFFFFFF),
                "ida_ua": SimpleNamespace(
                    o_void=0,
                    o_mem=2,
                    o_far=7,
                    o_near=6,
                    o_imm=5,
                    o_displ=4,
                    o_phrase=3,
                    insn_t=lambda: SimpleNamespace(
                        ops=[SimpleNamespace(type=4, offb=2, addr=0x2004), SimpleNamespace(type=0)]
                    ),
                    decode_insn=lambda insn, ea: 6,
                ),
                # IDA can return UDT/member IDs as data xrefs. They are not
                # runtime addresses; two genuine mapped refs must still survive.
                "idautils": SimpleNamespace(
                    DataRefsFrom=lambda ea: [0x2004, 0xFF0000000000346B, 0xDEAD0000, 0x3004],
                    CodeRefsFrom=lambda ea, flow: [],
                ),
                "idc": SimpleNamespace(
                    generate_disasm_line=lambda ea, flags: "mov eax, [ebx+2004h]", print_insn_mnem=lambda ea: "mov"
                ),
            }
            namespace = {}
            with patch.dict("sys.modules", modules):
                exec(ida_analyze_util._INSPECT_LLM_INSTRUCTION_PY_EVAL.replace("EA_PLACEHOLDER", "4096"), namespace)
            self.assertEqual([not relocated], json.loads(namespace["result"])["operand_pic"])
            self.assertEqual(["0x2004", "0x3004"], json.loads(namespace["result"])["data_refs"])

    async def test_gv_emission_preserves_resolution_metadata_without_desired_fields(self):
        for metadata in ({"gv_pic_addend": "0x2ee000"}, {"gv_address_offset": "0xfffffffc"}):
            with tempfile.TemporaryDirectory() as temporary:
                output = Path(temporary) / "g_Target.linux.yaml"
                candidate = {
                    "gv_name": "g_Target",
                    "gv_va": "0xd268d4",
                    "gv_rva": "0xd268d4",
                    "gv_sig": "89 90 ?? ?? ?? ??",
                    "gv_sig_va": "0x9fe7e",
                    "gv_inst_offset": 0,
                    "gv_inst_length": 6,
                    "gv_inst_disp": 2,
                }
                fields = list(candidate)
                candidate.update(metadata)
                with (
                    patch("ida_analyze_util.preprocess_gv_sig_via_mcp", new=AsyncMock(return_value=candidate)),
                ):
                    ok = await preprocess_common_skill(
                        session=SimpleNamespace(call_tool=AsyncMock()),
                        expected_outputs=[str(output)],
                        new_binary_dir=temporary,
                        platform="linux",
                        image_base=0,
                        gv_names=["g_Target"],
                        generate_yaml_desired_fields=[("g_Target", fields)],
                    )
                self.assertTrue(ok)
                emitted = yaml.safe_load(output.read_text())
                for key, value in metadata.items():
                    self.assertEqual(value, emitted[key])

    def test_canonical_gv_yaml_orders_pic_addend_after_inst_disp(self):
        payload = {
            "gv_sig_allow_across_function_boundary": True,
            "gv_pic_addend": 0x2EE000,
            "gv_inst_disp": 2,
            "gv_inst_length": 6,
            "gv_inst_offset": 0,
            "gv_sig_va": "0x401000",
            "gv_sig": "8b 54 ??",
            "gv_rva": 0x9268D4,
            "gv_va": 0x4D268D4,
            "gv_name": "g_Target",
        }
        raw = canonical_symbol_yaml_bytes(payload, category="gv").decode("utf-8")
        lines = [line.split(":")[0] for line in raw.splitlines() if ":" in line]
        self.assertEqual(
            [
                "gv_name",
                "gv_va",
                "gv_rva",
                "gv_sig",
                "gv_sig_va",
                "gv_inst_offset",
                "gv_inst_length",
                "gv_inst_disp",
                "gv_pic_addend",
                "gv_sig_allow_across_function_boundary",
            ],
            lines,
        )
        self.assertIn("gv_pic_addend: '0x2ee000'", raw)

    async def test_llm_found_funcptr_generates_regular_function(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            output = root / "Callback.windows.yaml"
            llm_result = {
                "found_vcall": [],
                "found_call": [],
                "found_funcptr": [
                    {
                        "funcptr_name": "Callback",
                        "insn_va": "0x401030",
                        "insn_disasm": "lea eax, sub_403000",
                    }
                ],
                "found_gv": [],
                "found_struct_offset": [],
            }
            context = {
                "model": "test-model",
                "prompt_path": "prompt.md",
                "reference_yaml_paths": ["reference.windows.yaml"],
                "temperature": None,
            }
            with (
                patch("ida_analyze_util.preprocess_func_sig_via_mcp", new=AsyncMock(return_value=None)),
                patch("ida_analyze_util._prepare_llm_context", return_value=context),
                patch(
                    "ida_analyze_util._call_llm_for_targets",
                    new=AsyncMock(return_value=(llm_result, [(0x401000, 0x401100)])),
                ),
                patch(
                    "ida_analyze_util._inspect_llm_instruction",
                    new=AsyncMock(
                        return_value={
                            "func_start": "0x401000",
                            "line": "lea eax, sub_403000",
                            "operand_targets": ["0x403000"],
                        }
                    ),
                ),
                patch(
                    "ida_analyze_util._inspect_function_via_mcp",
                    new=AsyncMock(
                        return_value={
                            "func_name": "Callback",
                            "func_va": "0x403000",
                            "func_rva": "0x3000",
                            "func_size": "0x20",
                            "func_sig": "55 8B EC 83 EC ??",
                        }
                    ),
                ),
            ):
                result = await preprocess_common_skill(
                    session=SimpleNamespace(call_tool=AsyncMock()),
                    expected_outputs=[str(output)],
                    new_binary_dir=root,
                    platform="windows",
                    image_base=0x400000,
                    func_names=["Callback"],
                    llm_decompile_specs=[
                        {
                            "symbol_name": "Callback",
                            "prompt_path": "prompt.md",
                            "reference_yaml_paths": ["reference.windows.yaml"],
                            "expected_result_sections": ["found_funcptr"],
                            "dependency_policy": {"Predecessor.windows.yaml": "required"},
                        }
                    ],
                    llm_config={"model": "test-model"},
                    generate_yaml_desired_fields=[
                        ("Callback", ["func_name", "func_sig", "func_va", "func_rva", "func_size"])
                    ],
                )

            self.assertTrue(result)
            self.assertEqual("Callback", yaml.safe_load(output.read_text(encoding="utf-8"))["func_name"])

    async def test_llm_found_vcall_uses_four_byte_slot(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            output = root / "VirtualTarget.windows.yaml"
            (root / "TargetClass_vtable.windows.yaml").write_text(
                "vtable_entries:\n  5: '0x402000'\n",
                encoding="utf-8",
            )
            llm_result = {
                "found_vcall": [
                    {
                        "func_name": "VirtualTarget",
                        "insn_va": "0x401010",
                        "insn_disasm": "call dword ptr [eax+14h]",
                        "vfunc_offset": "0x14",
                    }
                ],
                "found_call": [],
                "found_funcptr": [],
                "found_gv": [],
                "found_struct_offset": [],
            }
            context = {
                "model": "test-model",
                "prompt_path": "prompt.md",
                "reference_yaml_paths": ["reference.windows.yaml"],
                "temperature": None,
            }
            with (
                patch("ida_analyze_util.preprocess_func_sig_via_mcp", new=AsyncMock(return_value=None)),
                patch("ida_analyze_util._prepare_llm_context", return_value=context),
                patch(
                    "ida_analyze_util._call_llm_for_targets",
                    new=AsyncMock(return_value=(llm_result, [(0x401000, 0x401100)])),
                ),
                patch(
                    "ida_analyze_util._inspect_llm_instruction",
                    new=AsyncMock(
                        return_value={
                            "func_start": "0x401000",
                            "line": "call dword ptr [eax+14h]",
                            "displacements": ["0x14"],
                        }
                    ),
                ),
                patch(
                    "ida_analyze_util._inspect_function_via_mcp",
                    new=AsyncMock(
                        return_value={
                            "func_name": "VirtualTarget",
                            "func_va": "0x402000",
                            "func_rva": "0x2000",
                            "func_size": "0x20",
                            "func_sig": "55 8B EC 83 EC ??",
                        }
                    ),
                ),
            ):
                result = await preprocess_common_skill(
                    session=SimpleNamespace(call_tool=AsyncMock()),
                    expected_outputs=[str(output)],
                    new_binary_dir=root,
                    platform="windows",
                    image_base=0x400000,
                    func_names=["VirtualTarget"],
                    func_vtable_relations=[("VirtualTarget", "TargetClass")],
                    llm_decompile_specs=[
                        {
                            "symbol_name": "VirtualTarget",
                            "prompt_path": "prompt.md",
                            "reference_yaml_paths": ["reference.windows.yaml"],
                            "expected_result_sections": ["found_vcall"],
                            "dependency_policy": {"Predecessor.windows.yaml": "required"},
                        }
                    ],
                    llm_config={"model": "test-model"},
                    generate_yaml_desired_fields=[
                        (
                            "VirtualTarget",
                            ["func_name", "vfunc_sig", "vfunc_offset", "vfunc_index", "vtable_name"],
                        )
                    ],
                )

            self.assertTrue(result)
            payload = yaml.safe_load(output.read_text(encoding="utf-8"))
            self.assertEqual("0x14", payload["vfunc_offset"])
            self.assertEqual(5, payload["vfunc_index"])

    async def test_llm_found_vcall_accepts_zero_slot(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "TargetClass_vtable.windows.yaml").write_text(
                "vtable_entries:\n  0: '0x402000'\n",
                encoding="utf-8",
            )
            llm_result = {
                "found_vcall": [
                    {
                        "func_name": "VirtualTarget",
                        "insn_va": "0x401010",
                        "insn_disasm": "call dword ptr [eax]",
                        "vfunc_offset": "0x0",
                    }
                ],
                "found_call": [],
                "found_funcptr": [],
                "found_gv": [],
                "found_struct_offset": [],
            }
            with (
                patch(
                    "ida_analyze_util._inspect_llm_instruction",
                    new=AsyncMock(
                        return_value={
                            "func_start": "0x401000",
                            "line": "call dword ptr [eax]",
                            "displacements": ["0x0"],
                        }
                    ),
                ),
                patch(
                    "ida_analyze_util._inspect_function_via_mcp",
                    new=AsyncMock(
                        return_value={
                            "func_name": "VirtualTarget",
                            "func_va": "0x402000",
                            "func_rva": "0x2000",
                            "func_size": "0x20",
                            "func_sig": "55 8B EC 83 EC ??",
                        }
                    ),
                ),
            ):
                candidate = await _preprocess_llm_target(
                    session=SimpleNamespace(call_tool=AsyncMock()),
                    symbol_name="VirtualTarget",
                    category="vfunc",
                    spec={"expected_result_sections": ["found_vcall"]},
                    llm_config={"model": "test-model"},
                    new_binary_dir=root,
                    platform="windows",
                    image_base=0x400000,
                    desired_fields=["func_name", "vfunc_sig", "vfunc_offset", "vfunc_index", "vtable_name"],
                    vtable_name="TargetClass",
                    llm_result=llm_result,
                    target_ranges=[(0x401000, 0x401100)],
                )

            self.assertEqual("0x0", candidate["vfunc_offset"])
            self.assertEqual(0, candidate["vfunc_index"])

    async def test_llm_vcall_retries_requested_signature_budget(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "TargetClass_vtable.windows.yaml").write_text("vtable_entries:\n  0: '0x402000'\n")
            inspected = AsyncMock(
                side_effect=[
                    None,
                    {
                        "func_name": "VirtualTarget",
                        "func_va": "0x402000",
                        "func_rva": "0x2000",
                        "func_size": "0x200",
                        "func_sig": "55 8B EC",
                    },
                ]
            )
            with (
                patch(
                    "ida_analyze_util._inspect_llm_instruction",
                    new=AsyncMock(
                        return_value={
                            "func_start": "0x401000",
                            "line": "call dword ptr [eax]",
                            "displacements": ["0x0"],
                        }
                    ),
                ),
                patch("ida_analyze_util._inspect_function_via_mcp", new=inspected),
            ):
                candidate = await _preprocess_llm_target(
                    session=None,
                    symbol_name="VirtualTarget",
                    category="vfunc",
                    spec={"expected_result_sections": ["found_vcall"]},
                    llm_config={},
                    new_binary_dir=root,
                    platform="windows",
                    image_base=0x400000,
                    desired_fields=["vfunc_sig", "vfunc_sig_allow_across_function_boundary"],
                    vtable_name="TargetClass",
                    target_ranges=[(0x401000, 0x401100)],
                    llm_result={
                        "found_vcall": [{"func_name": "VirtualTarget", "insn_va": "0x401010", "vfunc_offset": "0x0"}]
                    },
                )
            self.assertIsNotNone(candidate)
            self.assertTrue(candidate["vfunc_sig_allow_across_function_boundary"])
            self.assertEqual(2, inspected.await_count)
            self.assertEqual({"allow_across_function_boundary": True}, inspected.await_args.kwargs)

    async def test_incomplete_vfunc_fast_path_still_enters_llm_batch(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            output = root / "VirtualTarget.windows.yaml"
            (root / "TargetClass_vtable.windows.yaml").write_text(
                "vtable_entries:\n  0: '0x403000'\n",
                encoding="utf-8",
            )
            fast_candidate = {
                "func_name": "VirtualTarget",
                "func_va": "0x402000",
                "func_rva": "0x2000",
                "func_size": "0x20",
                "func_sig": "55 8B EC 83 EC ??",
            }
            llm_result = {
                "found_vcall": [
                    {
                        "func_name": "VirtualTarget",
                        "insn_va": "0x401010",
                        "insn_disasm": "call dword ptr [eax]",
                        "vfunc_offset": "0x0",
                    }
                ],
                "found_call": [],
                "found_funcptr": [],
                "found_gv": [],
                "found_struct_offset": [],
            }
            context = {
                "model": "test-model",
                "prompt_path": "prompt.md",
                "reference_yaml_paths": ["reference.windows.yaml"],
                "temperature": None,
            }
            with (
                patch("ida_analyze_util.preprocess_func_sig_via_mcp", new=AsyncMock(return_value=fast_candidate)),
                patch("ida_analyze_util.preprocess_vtable_via_mcp", new=AsyncMock(return_value=None)),
                patch("ida_analyze_util._prepare_llm_context", return_value=context),
                patch(
                    "ida_analyze_util._call_llm_for_targets",
                    new=AsyncMock(return_value=(llm_result, [(0x401000, 0x401100)])),
                ) as call_llm,
                patch(
                    "ida_analyze_util._inspect_llm_instruction",
                    new=AsyncMock(
                        return_value={
                            "func_start": "0x401000",
                            "line": "call dword ptr [eax]",
                            "displacements": ["0x0"],
                        }
                    ),
                ),
                patch(
                    "ida_analyze_util._inspect_function_via_mcp",
                    new=AsyncMock(
                        return_value={
                            "func_name": "VirtualTarget",
                            "func_va": "0x403000",
                            "func_rva": "0x3000",
                            "func_size": "0x20",
                            "func_sig": "55 8B EC 83 EC ??",
                        }
                    ),
                ),
            ):
                result = await preprocess_common_skill(
                    session=SimpleNamespace(call_tool=AsyncMock()),
                    expected_outputs=[str(output)],
                    new_binary_dir=root,
                    platform="windows",
                    image_base=0x400000,
                    func_names=["VirtualTarget"],
                    func_vtable_relations=[("VirtualTarget", "TargetClass")],
                    llm_decompile_specs=[
                        {
                            "symbol_name": "VirtualTarget",
                            "prompt_path": "prompt.md",
                            "reference_yaml_paths": ["reference.windows.yaml"],
                            "expected_result_sections": ["found_vcall"],
                            "dependency_policy": {"Predecessor.windows.yaml": "required"},
                        }
                    ],
                    llm_config={"model": "test-model"},
                    generate_yaml_desired_fields=[
                        (
                            "VirtualTarget",
                            ["func_name", "vfunc_sig", "vfunc_offset", "vfunc_index", "vtable_name"],
                        )
                    ],
                )

            self.assertTrue(result)
            call_llm.assert_awaited_once()
            self.assertEqual(["VirtualTarget"], call_llm.await_args.kwargs["symbol_names"])

    async def test_generated_function_signature_must_be_unique(self):
        function_payload = {
            "pointer_size": 4,
            "function": {
                "func_va": "0x402000",
                "func_rva": "0x2000",
                "func_size": "0x20",
                "func_sig": "55 8B EC 83 EC ??",
            },
        }

        async def ambiguous_call_tool(name, _arguments):
            if name == "py_eval":
                return function_payload
            return {"matches": ["0x402000", "0x403000"], "n": 2}

        async def unique_call_tool(name, _arguments):
            if name == "py_eval":
                return function_payload
            return {"matches": ["0x402000"], "n": 1}

        self.assertIsNone(
            await _inspect_function_via_mcp(
                SimpleNamespace(call_tool=ambiguous_call_tool),
                0x402000,
                0x400000,
                "Target",
            )
        )
        self.assertEqual(
            "Target",
            (
                await _inspect_function_via_mcp(
                    SimpleNamespace(call_tool=unique_call_tool),
                    0x402000,
                    0x400000,
                    "Target",
                )
            )["func_name"],
        )

    async def test_llm_direct_call_resolves_requested_jmp_thunk(self):
        llm_result = {
            "found_vcall": [],
            "found_call": [
                {
                    "func_name": "Target",
                    "insn_va": "0x401010",
                    "insn_disasm": "call j_Target",
                }
            ],
            "found_funcptr": [],
            "found_gv": [],
            "found_struct_offset": [],
        }
        inspected_function = {
            "func_name": "Target",
            "func_va": "0x403000",
            "func_rva": "0x3000",
            "func_size": "0x20",
            "func_sig": "55 8B EC 83 EC ??",
        }
        with (
            patch(
                "ida_analyze_util._inspect_llm_instruction",
                new=AsyncMock(
                    return_value={
                        "func_start": "0x401000",
                        "line": "call j_Target",
                        "code_refs": ["0x402000"],
                    }
                ),
            ),
            patch(
                "ida_analyze_util._resolve_jmp_thunk_target_via_mcp",
                new=AsyncMock(return_value=0x403000),
            ) as resolve_thunk,
            patch(
                "ida_analyze_util._inspect_function_via_mcp",
                new=AsyncMock(return_value=inspected_function),
            ) as inspect_function,
        ):
            candidate = await _preprocess_llm_target(
                session=SimpleNamespace(call_tool=AsyncMock()),
                symbol_name="Target",
                category="func",
                spec={"expected_result_sections": ["found_call"]},
                llm_config={"model": "test-model"},
                new_binary_dir=Path("D:/game/engine"),
                platform="windows",
                image_base=0x400000,
                desired_fields=[
                    "func_name",
                    "func_sig",
                    "func_va",
                    "func_rva",
                    "func_size",
                    "func_sig_resolve_jmp_thunk",
                ],
                llm_result=llm_result,
                target_ranges=[(0x401000, 0x401100)],
            )

        self.assertEqual(inspected_function, candidate)
        resolve_thunk.assert_awaited_once()
        inspect_function.assert_awaited_once_with(ANY, 0x403000, 0x400000, "Target")

    def test_llm_function_export_builder_writes_json_via_remote_ack(self):
        code = _build_llm_function_export_py_eval(0x1AEBF0, "D:/tmp/export.json")
        compile(code, "<llm-function-export>", "exec")
        self.assertIn("tmp_path = output_path + '.tmp'", code)
        self.assertIn("os.replace(tmp_path, output_path)", code)
        self.assertIn("payload_text = json.dumps(payload)", code)
        self.assertLess(
            code.index("payload_text = json.dumps(payload)"), code.index("os.replace(tmp_path, output_path)")
        )

    async def test_export_llm_function_reads_remote_json_payload(self):
        exported = {
            "pointer_size": 4,
            "func_name": "ClientDLL_Init",
            "func_va": "0x1aebf0",
            "func_start": "0x1aebf0",
            "func_end": "0x1af71d",
            "disasm_code": "call FreeBlob",
            "procedure": "FreeBlob(&g_blobfootprintClient);",
            "chunk_ranges": [["0x1aebf0", "0x1af71d"]],
        }

        async def fake_call_tool(name, arguments=None, **_kwargs):
            self.assertEqual("py_eval", name)
            code = arguments["code"]
            output_path = None
            for line in code.splitlines():
                if line.startswith("output_path = "):
                    output_path = ast.literal_eval(line.split("=", 1)[1].strip())
                    break
            self.assertIsInstance(output_path, str)
            Path(output_path).write_text(json.dumps(exported), encoding="utf-8")
            return {
                "ok": True,
                "output_path": output_path,
                "bytes_written": Path(output_path).stat().st_size,
                "format": "json",
            }

        payload = await _export_llm_function(SimpleNamespace(call_tool=fake_call_tool), 0x1AEBF0)
        self.assertEqual(exported, payload)

    async def test_llm_global_address_feedback_retries_unknown_base(self):
        exported = {
            "func_name": "Owner",
            "func_start": "0x1000",
            "func_end": "0x1020",
            "disasm_code": "0x1000: mov [edx+2000h], eax\n0x1010: mov [ecx+3000h], eax",
            "procedure": "",
            "func_va": "0x1000",
        }
        context = {
            "targets": [({}, 0x1000)],
            "reference_items": [exported],
            "model": "test-model",
            "prompt_template": "{target_blocks}",
            "max_retries": 2,
        }
        for unknown_base, exhausted in ((False, False), (True, False), (True, True)):
            with self.subTest(unknown_base=unknown_base, exhausted=exhausted):
                requests = []

                def transport(**kwargs):
                    requests.append(kwargs["messages"])
                    use_first = len(requests) == 1 or exhausted
                    address, instruction = (
                        ("0x1000", "mov [edx+2000h], eax") if use_first else ("0x1010", "mov [ecx+3000h], eax")
                    )
                    return (
                        f"found_gv:\n  - insn_va: '{address}'\n    insn_disasm: '{instruction}'\n    gv_name: Target\n"
                    )

                async def inspect_instruction(session, address):
                    if unknown_base and address == "0x1000":
                        return {
                            "relative_store_address": {
                                "target": None,
                                "issue": "Cannot determine EDX base. 0x2000 is a displacement, not a complete global address.",
                            }
                        }
                    return {"relative_store_address": {"target": "0x9000"}}

                with (
                    patch("ida_analyze_util._export_llm_function", new=AsyncMock(return_value=exported)),
                    patch("ida_analyze_util._inspect_llm_instruction", side_effect=inspect_instruction),
                    patch("ida_llm_decompile._default_transport", side_effect=transport),
                ):
                    result, _ranges = await _call_llm_for_targets(
                        session=SimpleNamespace(),
                        symbol_names=["Target"],
                        specs={"Target": {"expected_result_sections": ["found_gv"]}},
                        context=context,
                        platform="linux",
                        new_binary_dir=Path("engine"),
                    )
                self.assertEqual(2 if unknown_base else 1, len(requests))
                if unknown_base:
                    feedback = requests[1][-1]["content"]
                    self.assertIn("EDX", feedback)
                    self.assertIn("displacement", feedback)
                    self.assertIn("same global", feedback)
                if exhausted:
                    self.assertEqual([], result["found_gv"])
                else:
                    self.assertEqual("0x1010" if unknown_base else "0x1000", result["found_gv"][0]["insn_va"])

    async def test_call_llm_for_targets_preserves_tail_chunk_ranges(self):
        keepalive_called = asyncio.Event()
        session = SimpleNamespace(call_tool=AsyncMock(side_effect=lambda **kwargs: keepalive_called.set()))

        async def call_llm_with_keepalive(**kwargs):
            await asyncio.wait_for(keepalive_called.wait(), timeout=1)
            return {
                "found_vcall": [],
                "found_call": [],
                "found_funcptr": [],
                "found_gv": [],
                "found_struct_offset": [],
            }

        exported = {
            "func_name": "Predecessor",
            "func_start": "0x401000",
            "func_end": "0x401050",
            "chunk_ranges": [["0x401000", "0x401050"], ["0x402000", "0x402020"]],
            "disasm_code": "0x402010: call sub_403000",
            "procedure": "sub_403000();",
        }
        context = {
            "targets": [({}, 0x401000)],
            "reference_items": [
                {
                    "func_name": "Predecessor",
                    "func_va": "0x401000",
                    "disasm_code": "call Target",
                    "procedure": "Target();",
                }
            ],
            "model": "test-model",
            "prompt_template": "{reference_blocks}\n{target_blocks}\n{symbol_name_list}",
        }
        with (
            patch("ida_analyze_util._export_llm_function", new=AsyncMock(return_value=exported)),
            patch(
                "ida_analyze_util.call_llm_decompile",
                new=AsyncMock(side_effect=call_llm_with_keepalive),
            ),
            patch("ida_mcp_keepalive.WORKER_KEEPALIVE_INTERVAL_SECONDS", 0.001),
        ):
            _result, target_ranges = await _call_llm_for_targets(
                session=session,
                symbol_names=["Target"],
                specs={"Target": {"expected_result_sections": ["found_call"]}},
                context=context,
                platform="windows",
                new_binary_dir=Path("D:/game/engine"),
            )

        session.call_tool.assert_awaited_with(name="py_eval", arguments={"code": "1"})
        self.assertEqual([(0x401000, 0x401050), (0x402000, 0x402020)], target_ranges)
        self.assertTrue(
            _llm_entry_instruction_is_valid(
                {"insn_va": "0x402010"},
                {"func_start": "0x401000", "line": "call sub_403000 ; tail chunk"},
                target_ranges,
                [
                    {"regex": r"jmp .+"},
                    {"regex": r"call sub_403000"},
                ],
            )
        )

    def test_prepare_llm_context_skips_missing_optional_predecessor(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            prompt = root / "prompt.md"
            required_reference = root / "Required.yaml"
            optional_reference = root / "Optional.yaml"
            required_current = root / "Required.windows.yaml"
            missing_optional = root / "Optional.windows.yaml"
            prompt.write_text("{reference_blocks}\n{target_blocks}\n{symbol_name_list}", encoding="utf-8")
            required_reference.write_text(
                "func_name: Required\nfunc_va: '0x401000'\ndisasm_code: call Target\nprocedure: Target();\n",
                encoding="utf-8",
            )
            optional_reference.write_text(
                "func_name: Optional\nfunc_va: '0x402000'\ndisasm_code: call Target\nprocedure: Target();\n",
                encoding="utf-8",
            )
            required_current.write_text("func_name: Required\nfunc_va: '0x411000'\n", encoding="utf-8")
            context = _prepare_llm_context(
                {
                    "symbol_name": "Target",
                    "prompt_path": str(prompt),
                    "reference_yaml_paths": [str(required_reference), str(optional_reference)],
                    "expected_result_sections": ["found_call"],
                    "dependency_policy": {
                        "Required.{platform}.yaml": "required",
                        "Optional.{platform}.yaml": "optional",
                    },
                },
                {
                    "model": "test-model",
                    "_expected_inputs": [str(required_current)],
                    "_optional_inputs": [str(missing_optional)],
                },
                root,
                "windows",
            )

            self.assertEqual(1, len(context["targets"]))
            self.assertEqual(0x411000, context["targets"][0][1])
            self.assertEqual([str(required_reference.resolve())], context["reference_yaml_paths"])

    async def test_dependency_contract_is_validated_before_fast_path(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            output = root / "Target.windows.yaml"
            fast_path = AsyncMock(
                return_value={
                    "func_name": "Target",
                    "func_va": "0x402000",
                    "func_rva": "0x2000",
                    "func_size": "0x20",
                    "func_sig": "55 8B EC",
                }
            )
            with (
                patch("ida_analyze_util._prepare_llm_context", return_value=None) as prepare_context,
                patch("ida_analyze_util.preprocess_func_sig_via_mcp", new=fast_path),
            ):
                result = await preprocess_common_skill(
                    session=SimpleNamespace(call_tool=AsyncMock()),
                    expected_outputs=[str(output)],
                    new_binary_dir=root,
                    platform="windows",
                    image_base=0x400000,
                    func_names=["Target"],
                    llm_decompile_specs=[
                        {
                            "symbol_name": "Target",
                            "prompt_path": "prompt.md",
                            "reference_yaml_paths": ["reference.windows.yaml"],
                            "expected_result_sections": ["found_call"],
                            "dependency_policy": {"Predecessor.windows.yaml": "required"},
                        }
                    ],
                    llm_config={"model": "test-model"},
                    generate_yaml_desired_fields=[
                        ("Target", ["func_name", "func_sig", "func_va", "func_rva", "func_size"])
                    ],
                )

            self.assertFalse(result)
            prepare_context.assert_called_once()
            fast_path.assert_not_awaited()

    def test_llm_spec_rejects_casefold_duplicate_dependency_policy(self):
        self.assertIsNone(
            _normalize_llm_decompile_specs(
                [
                    {
                        "symbol_name": "Target",
                        "prompt_path": "prompt.md",
                        "reference_yaml_paths": ["reference.windows.yaml"],
                        "expected_result_sections": ["found_call"],
                        "dependency_policy": {
                            "Predecessor.windows.yaml": "required",
                            "predecessor.windows.yaml": "required",
                        },
                    }
                ]
            )
        )

    def test_llm_templates_support_module_and_module_name(self):
        rendered = _resolve_llm_template(
            "references/{module}/{module_name}/Target.{platform}.yaml",
            Path("D:/game/engine"),
            "linux",
        )
        self.assertEqual("references/engine/engine/Target.linux.yaml", rendered)

    def test_llm_template_supports_gamever(self):
        rendered = _resolve_llm_template(
            "references/{gamever}/{module}/Target.{platform}.yaml",
            Path("D:/game/hl-10210/engine"),
            "linux",
        )
        self.assertEqual("references/hl-10210/engine/Target.linux.yaml", rendered)

    def test_resolve_reference_resource_prefers_current_gamever(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            new_binary_dir = root / "svencoop-10257" / "engine"
            current = (
                root
                / "ida_preprocessor_scripts"
                / "references"
                / "svencoop-10257"
                / "engine"
                / "SV_SendServerinfo.windows.yaml"
            )
            current.parent.mkdir(parents=True)
            current.write_text("func_name: SV_SendServerinfo\n", encoding="utf-8")

            def _fake_resolve(value, new_binary_dir, platform):
                gamever = Path(new_binary_dir).resolve().parent.name
                resolved = str(value).replace("{platform}", platform).replace("{gamever}", gamever)
                return (root / "ida_preprocessor_scripts" / resolved).resolve()

            with (
                patch.object(ida_analyze_util, "_resolve_preprocessor_resource", side_effect=_fake_resolve),
                patch.object(
                    ida_analyze_util,
                    "REFERENCE_RESOURCE_ROOT",
                    root / "ida_preprocessor_scripts" / "references",
                ),
            ):
                resolved = _resolve_reference_resource(
                    "references/{gamever}/engine/SV_SendServerinfo.{platform}.yaml",
                    new_binary_dir,
                    "windows",
                )
        self.assertEqual(current.resolve(), resolved)

    def test_resolve_reference_resource_falls_back_to_canonical_gamever(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            new_binary_dir = root / "svencoop-10257" / "engine"
            canonical = (
                root
                / "ida_preprocessor_scripts"
                / "references"
                / "hl-10210"
                / "engine"
                / "SV_SendServerinfo.windows.yaml"
            )
            canonical.parent.mkdir(parents=True)
            canonical.write_text("func_name: SV_SendServerinfo\n", encoding="utf-8")

            def _fake_resolve(value, new_binary_dir, platform):
                gamever = Path(new_binary_dir).resolve().parent.name
                resolved = str(value).replace("{platform}", platform).replace("{gamever}", gamever)
                return (root / "ida_preprocessor_scripts" / resolved).resolve()

            with (
                patch.object(ida_analyze_util, "_resolve_preprocessor_resource", side_effect=_fake_resolve),
                patch.object(
                    ida_analyze_util,
                    "REFERENCE_RESOURCE_ROOT",
                    root / "ida_preprocessor_scripts" / "references",
                ),
                patch.dict("os.environ", {"GSVIBE_REFERENCE_GAMEVER": "hl-10210"}, clear=True),
            ):
                resolved = _resolve_reference_resource(
                    "references/{gamever}/engine/SV_SendServerinfo.{platform}.yaml",
                    new_binary_dir,
                    "windows",
                )
        self.assertEqual(canonical.resolve(), resolved)

    def test_resolve_reference_resource_without_gamever_placeholder_has_no_fallback(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            new_binary_dir = root / "svencoop-10257" / "engine"
            calls = []

            def _fake_resolve(value, new_binary_dir, platform):
                calls.append(value)
                return (root / "ida_preprocessor_scripts" / str(value).replace("{platform}", platform)).resolve()

            with (
                patch.object(ida_analyze_util, "_resolve_preprocessor_resource", side_effect=_fake_resolve),
                patch.object(
                    ida_analyze_util,
                    "REFERENCE_RESOURCE_ROOT",
                    root / "ida_preprocessor_scripts" / "references",
                ),
                patch.dict("os.environ", {"GSVIBE_REFERENCE_GAMEVER": "hl-10210"}, clear=True),
            ):
                resolved = _resolve_reference_resource(
                    "references/engine/SV_SendServerinfo.{platform}.yaml",
                    new_binary_dir,
                    "windows",
                )
        self.assertEqual(1, len(calls))
        self.assertNotIn("hl-10210", resolved.parts)

    def test_resolve_reference_resource_rejects_invalid_canonical_gamever(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)

            def _fake_resolve(value, new_binary_dir, platform):
                gamever = Path(new_binary_dir).resolve().parent.name
                resolved = str(value).replace("{platform}", platform).replace("{gamever}", gamever)
                return (root / "ida_preprocessor_scripts" / resolved).resolve()

            for gamever in ("", "../../..", "HL-10210"):
                with (
                    self.subTest(gamever=gamever),
                    patch.object(ida_analyze_util, "_resolve_preprocessor_resource", side_effect=_fake_resolve),
                    patch.object(
                        ida_analyze_util,
                        "REFERENCE_RESOURCE_ROOT",
                        root / "ida_preprocessor_scripts" / "references",
                    ),
                    patch.dict("os.environ", {"GSVIBE_REFERENCE_GAMEVER": gamever}, clear=True),
                    self.assertRaises(AnalysisConfigError),
                ):
                    _resolve_reference_resource(
                        "references/{gamever}/engine/SV_SendServerinfo.windows.yaml",
                        root / "missing-12345" / "engine",
                        "windows",
                    )

    def test_resolve_reference_resource_rejects_path_outside_reference_root(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            reference_root = root / "ida_preprocessor_scripts" / "references"
            outside = root / "outside" / "{gamever}" / "SV_SendServerinfo.windows.yaml"
            with (
                patch.object(ida_analyze_util, "REFERENCE_RESOURCE_ROOT", reference_root),
                self.assertRaisesRegex(ValueError, "outside reference root"),
            ):
                _resolve_reference_resource(outside, root / "hl-10210" / "engine", "windows")

    def test_resolve_reference_resource_uses_repository_svencoop_override(self):
        root = Path(__file__).parents[1]
        expected = (
            root
            / "ida_preprocessor_scripts"
            / "references"
            / "svencoop-10257"
            / "engine"
            / "SV_SendServerinfo.windows.yaml"
        ).resolve()
        with patch.dict("os.environ", {"GSVIBE_REFERENCE_GAMEVER": "hl-10210"}, clear=True):
            resolved = _resolve_reference_resource(
                "references/{gamever}/engine/SV_SendServerinfo.{platform}.yaml",
                root / "bin" / "svencoop-10257" / "engine",
                "windows",
            )
        self.assertEqual(expected, resolved)

    async def test_common_preprocessor_rejects_non_x86_pointer_size(self):
        async def call_tool(_name, _arguments):
            return SimpleNamespace(
                structuredContent={"result": json.dumps({"candidates": [], "pointer_size": 8})},
                content=[],
                isError=False,
            )

        result = await preprocess_common_skill(
            session=SimpleNamespace(call_tool=call_tool),
            expected_outputs=[],
            platform="windows",
            image_base=0x400000,
            func_names=["R_RenderView"],
            func_xrefs=[{"func_name": "R_RenderView", "xref_strings": ["anchor"]}],
            generate_yaml_desired_fields=[("R_RenderView", ["func_name"])],
        )
        self.assertFalse(result)

    async def test_inherited_slot_only_vfunc_uses_four_byte_slots(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "Base_Run.windows.yaml").write_text(
                "func_name: Base_Run\nvtable_name: Base\nvfunc_offset: '0x14'\nvfunc_index: 5\n",
                encoding="utf-8",
            )
            result = await preprocess_index_based_vfunc_via_mcp(
                session=SimpleNamespace(call_tool=AsyncMock()),
                target_func_name="Derived_Run",
                target_output=root / "Derived_Run.windows.yaml",
                old_yaml_map=None,
                new_binary_dir=root,
                platform="windows",
                image_base=0x400000,
                base_vfunc_name="Base_Run",
                inherit_vtable_class="Derived",
                generate_func_sig=False,
                slot_only=True,
            )
            self.assertEqual(5, result["vfunc_index"])
            self.assertEqual("0x14", result["vfunc_offset"])

    async def test_indirect_vcall_helper_merges_pattern_i_and_l_on_x86(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "Thunk.windows.yaml").write_text(
                "func_name: Thunk\nfunc_va: '0x401000'\n",
                encoding="utf-8",
            )

            async def call_tool(_name, _arguments):
                return SimpleNamespace(
                    structuredContent={
                        "result": json.dumps(
                            {
                                "pointer_size": 4,
                                "targets": [
                                    {
                                        "source_ea": "0x401010",
                                        "source_mnemonic": "jmp",
                                        "vfunc_offset": "0x14",
                                        "vfunc_index": 5,
                                    }
                                ],
                            }
                        )
                    },
                    content=[],
                    isError=False,
                )

            output = root / "IThing_Run.windows.yaml"
            result = await preprocess_indirect_vcall_target_skill(
                session=SimpleNamespace(call_tool=call_tool),
                expected_outputs=[str(output)],
                new_binary_dir=root,
                platform="windows",
                source_yaml_stem="Thunk",
                target_name="IThing_Run",
                vtable_name="IThing",
                generate_yaml_desired_fields=[
                    ("IThing_Run", ["func_name", "vtable_name", "vfunc_offset", "vfunc_index"])
                ],
            )
            self.assertTrue(result)
            self.assertEqual(5, yaml.safe_load(output.read_text(encoding="utf-8"))["vfunc_index"])

    async def test_ordinal_vtable_helper_rejects_x64_and_normalizes_x86(self):
        async def call_tool(_name, _arguments):
            return SimpleNamespace(
                structuredContent={
                    "result": json.dumps(
                        {
                            "pointer_size": 4,
                            "selected": {
                                "vtable_class": "Thing",
                                "vtable_symbol": "??_7Thing@@6B@",
                                "vtable_va": "0x402000",
                                "vtable_size": "0x8",
                                "vtable_numvfunc": 2,
                                "vtable_entries": {"0": "0x401000", "1": "0x401100"},
                            },
                        }
                    )
                },
                content=[],
                isError=False,
            )

        result = await preprocess_ordinal_vtable_via_mcp(
            session=SimpleNamespace(call_tool=call_tool),
            class_name="Thing",
            ordinal=0,
            image_base=0x400000,
            platform="windows",
        )
        self.assertEqual("0x2000", result["vtable_rva"])
        self.assertEqual({0: "0x401000", 1: "0x401100"}, result["vtable_entries"])


class PreprocessFuncSigViaMcpTests(unittest.IsolatedAsyncioTestCase):
    IMAGE_BASE = 0x400000
    FUNC_VA = 0x402000
    OTHER_VA = 0x403000
    CURRENT_SIG = "55 8B EC 83 EC ??"
    STALE_SIG = "90 90 90 90"
    OLD_SIG_RAW = "55 8b ec 90"
    OLD_SIG_NORMALIZED = "55 8B EC 90"

    def _write_old_yaml(self, root, *, func_sig=None, allow_across=False):
        payload = {"func_name": "Target"}
        if func_sig is not None:
            payload["func_sig"] = func_sig
        if allow_across:
            payload["func_sig_allow_across_function_boundary"] = True
        path = Path(root) / "Target.windows.yaml"
        path.write_text(yaml.safe_dump(payload), encoding="utf-8")
        return path

    def _inspect_payload(self, *, function=True):
        if not function:
            return {"pointer_size": 4, "function": None}
        return {
            "pointer_size": 4,
            "function": {
                "func_va": hex(self.FUNC_VA),
                "func_rva": hex(self.FUNC_VA - self.IMAGE_BASE),
                "func_size": "0x20",
                "func_sig": self.CURRENT_SIG,
            },
        }

    def _session(self, *, extra_matches=None, inspect_function=True, inspect_error=False):
        matches_by_pattern = {self.CURRENT_SIG: [self.FUNC_VA]}
        if extra_matches:
            matches_by_pattern.update(extra_matches)
        lookups = []
        py_eval_codes = []

        async def call_tool(name, arguments):
            if name == "find_bytes":
                pattern = arguments["patterns"][0]
                lookups.append(pattern)
                matches = matches_by_pattern.get(pattern, [])
                return {
                    "matches": [hex(match) if isinstance(match, int) else match for match in matches],
                    "n": len(matches),
                }
            if name == "py_eval":
                py_eval_codes.append(arguments["code"])
                if inspect_error:
                    raise RuntimeError("inspect failed")
                return self._inspect_payload(function=inspect_function)
            raise AssertionError(f"unexpected tool {name}")

        return SimpleNamespace(call_tool=call_tool, lookups=lookups, py_eval_codes=py_eval_codes)

    async def _preprocess(self, session, old_path, **kwargs):
        return await preprocess_func_sig_via_mcp(
            session,
            "Target.windows.yaml",
            old_path,
            self.IMAGE_BASE,
            "unused",
            "windows",
            func_name="Target",
            **kwargs,
        )

    async def test_direct_va_keeps_current_sig_when_old_sig_matches_nothing(self):
        with tempfile.TemporaryDirectory() as temporary:
            old_path = self._write_old_yaml(temporary, func_sig=self.STALE_SIG)
            session = self._session(extra_matches={self.STALE_SIG: []})
            result = await self._preprocess(session, old_path, direct_func_va=self.FUNC_VA)

        self.assertEqual(self.CURRENT_SIG, result["func_sig"])
        self.assertEqual(hex(self.FUNC_VA), result["func_va"])
        self.assertNotIn(self.STALE_SIG, session.lookups)
        self.assertEqual([self.CURRENT_SIG], session.lookups)

    async def test_direct_va_never_returns_old_sig_matching_other_or_multiple_locations(self):
        cases = (
            {self.STALE_SIG: [self.OTHER_VA]},
            {self.STALE_SIG: [self.FUNC_VA, self.OTHER_VA]},
        )
        for extra_matches in cases:
            with self.subTest(extra_matches=extra_matches), tempfile.TemporaryDirectory() as temporary:
                old_path = self._write_old_yaml(temporary, func_sig=self.STALE_SIG)
                session = self._session(extra_matches=extra_matches)
                result = await self._preprocess(session, old_path, direct_func_va=hex(self.FUNC_VA))

                self.assertEqual(self.CURRENT_SIG, result["func_sig"])
                self.assertNotEqual(self.STALE_SIG, result["func_sig"])
                self.assertNotIn(self.STALE_SIG, session.lookups)

    async def test_direct_va_without_old_sig_keeps_current_sig(self):
        with tempfile.TemporaryDirectory() as temporary:
            old_path = self._write_old_yaml(temporary)
            session = self._session()
            result = await self._preprocess(session, old_path, direct_func_va=self.FUNC_VA)

        self.assertEqual(self.CURRENT_SIG, result["func_sig"])
        self.assertEqual([self.CURRENT_SIG], session.lookups)

    async def test_direct_va_inspection_failure_returns_none_even_with_old_sig(self):
        with tempfile.TemporaryDirectory() as temporary:
            old_path = self._write_old_yaml(temporary, func_sig=self.STALE_SIG)
            missing_function = self._session(extra_matches={self.STALE_SIG: [self.FUNC_VA]}, inspect_function=False)
            self.assertIsNone(await self._preprocess(missing_function, old_path, direct_func_va=self.FUNC_VA))
            self.assertEqual([], missing_function.lookups)

            inspect_error = self._session(extra_matches={self.STALE_SIG: [self.FUNC_VA]}, inspect_error=True)
            self.assertIsNone(await self._preprocess(inspect_error, old_path, direct_func_va=self.FUNC_VA))
            self.assertEqual([], inspect_error.lookups)

    async def test_ordinary_path_reuses_validated_unique_old_sig(self):
        with tempfile.TemporaryDirectory() as temporary:
            old_path = self._write_old_yaml(temporary, func_sig=self.OLD_SIG_RAW)
            session = self._session(extra_matches={self.OLD_SIG_RAW: [self.FUNC_VA]})
            result = await self._preprocess(session, old_path)

        self.assertEqual(self.OLD_SIG_NORMALIZED, result["func_sig"])
        self.assertEqual(hex(self.FUNC_VA), result["func_va"])
        self.assertEqual([self.OLD_SIG_RAW, self.CURRENT_SIG], session.lookups)

    async def test_ordinary_path_missing_or_nonunique_old_sig_returns_none(self):
        with tempfile.TemporaryDirectory() as temporary:
            missing_sig_path = self._write_old_yaml(temporary)
            session = self._session()
            self.assertIsNone(await self._preprocess(session, missing_sig_path))
            self.assertEqual([], session.lookups)
            self.assertEqual([], session.py_eval_codes)

            self.assertIsNone(await self._preprocess(session, None))
            self.assertEqual([], session.lookups)

            stale_path = self._write_old_yaml(temporary, func_sig=self.STALE_SIG)
            for extra_matches in ({self.STALE_SIG: []}, {self.STALE_SIG: [self.FUNC_VA, self.OTHER_VA]}):
                with self.subTest(extra_matches=extra_matches):
                    session = self._session(extra_matches=extra_matches)
                    self.assertIsNone(await self._preprocess(session, stale_path))
                    self.assertEqual([self.STALE_SIG], session.lookups)
                    self.assertEqual([], session.py_eval_codes)

    async def test_across_function_boundary_flag_is_forwarded_and_recorded(self):
        with tempfile.TemporaryDirectory() as temporary:
            old_path = self._write_old_yaml(temporary, func_sig=self.OLD_SIG_RAW)
            session = self._session(extra_matches={self.OLD_SIG_RAW: [self.FUNC_VA]})
            result = await self._preprocess(
                session,
                old_path,
                allow_func_sig_across_function_boundary=True,
            )
            self.assertTrue(result["func_sig_allow_across_function_boundary"])
            self.assertIn("allow_across_function_boundary = True", session.py_eval_codes[0])

            old_flag_path = self._write_old_yaml(temporary, func_sig=self.OLD_SIG_RAW, allow_across=True)
            session = self._session(extra_matches={self.OLD_SIG_RAW: [self.FUNC_VA]})
            result = await self._preprocess(session, old_flag_path)
            self.assertTrue(result["func_sig_allow_across_function_boundary"])
            self.assertIn("allow_across_function_boundary = True", session.py_eval_codes[0])

            session = self._session()
            result = await self._preprocess(session, None, direct_func_va=self.FUNC_VA)
            self.assertNotIn("func_sig_allow_across_function_boundary", result)
            self.assertIn("allow_across_function_boundary = False", session.py_eval_codes[0])


if __name__ == "__main__":
    unittest.main()
