from __future__ import annotations

import ast
import io
import json
import os
import tempfile
import unittest
from contextlib import asynccontextmanager, redirect_stderr
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import ANY, AsyncMock, patch

import yaml

import ida_analyze_util
import ida_skill_preprocessor
from analysis_config import AnalysisConfigError
from ida_analyze_util import (
    _build_func_xref_py_eval,
    _call_llm_for_targets,
    _inspect_function_via_mcp,
    _llm_entry_instruction_is_valid,
    _normalize_llm_decompile_specs,
    _prepare_llm_context,
    _preprocess_llm_target,
    _resolve_llm_template,
    _resolve_reference_resource,
    parse_mcp_result,
    preprocess_common_skill,
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
        self.assertIn("UNDEFINED_FUNC_RECOVERY_BACKTRACK_LIMIT", code)
        self.assertIn("return {start for start, count in counts.items() if count == 1}", code)
        self.assertIn("Strings(default_setup=False)", code)
        self.assertIn("strings.setup(strtypes=[ida_nalt.STRTYPE_C]", code)
        self.assertIn("name == '.rdata' or name.startswith('.rodata')", code)
        self.assertIn("return any(abs(value - expected) < epsilon", code)
        self.assertIn("if not callers and dep_start is not None and dep_start in vtable_candidates", code)
        self.assertIn("excluded.update(_named_candidates(value))", code)
        self.assertIn("if spec.get('vtable_entries'):", code)
        self.assertIn("def _try_decode_padding_nop", code)
        self.assertIn("not ida_bytes.is_head(flags)", code)
        self.assertNotIn("if len(tokens) >= max_tokens:\n                break", code)
        self.assertIn("ida_ua.o_displ", ida_analyze_util._INSPECT_FUNCTION_PY_EVAL)
        self.assertIn("def _try_decode_padding_nop", ida_analyze_util._INSPECT_FUNCTION_PY_EVAL)

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
            self.assertEqual(
                [[0x401010, 0x402010], [0x401020]],
                namespace["spec"]["xref_signature_ea_sets"],
            )
            self.assertIn("for values in spec.get('xref_signature_ea_sets') or []", code)
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
                if "ida_hexrays" in code:
                    return {
                        "pointer_size": 4,
                        "function": {
                            "func_start": "0x401000",
                            "func_end": "0x401100",
                            "disasm_code": "0x401020: call sub_402000",
                            "procedure": "sub_402000();",
                        },
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

    async def test_call_llm_for_targets_preserves_tail_chunk_ranges(self):
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
                new=AsyncMock(
                    return_value={
                        "found_vcall": [],
                        "found_call": [],
                        "found_funcptr": [],
                        "found_gv": [],
                        "found_struct_offset": [],
                    }
                ),
            ),
        ):
            _result, target_ranges = await _call_llm_for_targets(
                session=SimpleNamespace(call_tool=AsyncMock()),
                symbol_names=["Target"],
                specs={"Target": {"expected_result_sections": ["found_call"]}},
                context=context,
                platform="windows",
                new_binary_dir=Path("D:/game/engine"),
            )

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


if __name__ == "__main__":
    unittest.main()
