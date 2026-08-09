from __future__ import annotations

import io
import tempfile
import unittest
from contextlib import asynccontextmanager, redirect_stderr
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

import ida_skill_preprocessor
from ida_skill_preprocessor import (
    PREPROCESS_STATUS_ABSENT_OK,
    PREPROCESS_STATUS_FAILED,
    PREPROCESS_STATUS_NO_SCRIPT,
    PREPROCESS_STATUS_SUCCESS,
    _normalize_preprocess_status,
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


if __name__ == "__main__":
    unittest.main()
