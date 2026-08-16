from __future__ import annotations

import argparse
import asyncio
import json
import tempfile
import threading
import unittest
from contextlib import asynccontextmanager
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock, patch

import yaml

import generate_reference_yaml
from tests.test_support import write_elf32, write_pe32


class _FakeTextContent:
    def __init__(self, text: str) -> None:
        self.text = text


class _FakeCallToolResult:
    def __init__(self, payload) -> None:
        self.content = [_FakeTextContent(json.dumps(payload))]


class _FakeStructuredCallToolResult:
    def __init__(self, payload) -> None:
        self.structuredContent = {"result": json.dumps(payload), "stderr": ""}
        self.content = []


def _py_eval_result(payload, *, stderr: str = "") -> _FakeCallToolResult:
    return _FakeCallToolResult({"result": json.dumps(payload), "stderr": stderr})


def _base_args(**overrides) -> argparse.Namespace:
    values = {
        "gamever": "hl-10210",
        "configyaml": None,
        "module": "engine",
        "platform": "windows",
        "func_name": "R_RenderView",
        "output_filename": None,
        "mcp_host": "127.0.0.1",
        "mcp_port": 13337,
        "mcp_database": None,
        "ida_args": "",
        "debug": False,
        "binary": None,
        "auto_start_mcp": False,
    }
    values.update(overrides)
    return argparse.Namespace(**values)


class ReferenceYamlPureHelperTests(unittest.TestCase):
    def test_validate_reference_payload_keeps_only_generation_contract_fields(self) -> None:
        payload = generate_reference_yaml._validate_reference_yaml_payload(
            {
                "func_name": "R_RenderView",
                "func_va": 0x10244610,
                "disasm_code": "seg001:10244610 push ebp",
                "procedure": None,
                "unexpected": "discarded",
            }
        )
        self.assertEqual(
            {
                "func_name": "R_RenderView",
                "func_va": "0x10244610",
                "disasm_code": "seg001:10244610 push ebp",
                "procedure": "",
            },
            payload,
        )

    def test_validate_reference_payload_rejects_non_x86_address(self) -> None:
        for invalid_address in ("0x100000000", -1, True, False):
            with (
                self.subTest(func_va=invalid_address),
                self.assertRaisesRegex(
                    generate_reference_yaml.ReferenceGenerationError,
                    "invalid reference YAML payload",
                ),
            ):
                generate_reference_yaml._validate_reference_yaml_payload(
                    {
                        "func_name": "R_RenderView",
                        "func_va": invalid_address,
                        "disasm_code": "push ebp",
                        "procedure": "",
                    }
                )

    def test_parse_args_defaults_gamever_from_reference_environment(self) -> None:
        with patch.dict(
            "os.environ",
            {
                "GSVIBE_GAMEVER": "cstrike-10210",
                "GSVIBE_REFERENCE_GAMEVER": "hl-10210",
            },
            clear=True,
        ):
            args = generate_reference_yaml.parse_args(["-func_name", "R_RenderView"])
        self.assertEqual("hl-10210", args.gamever)
        self.assertIsNone(args.platform)
        self.assertFalse(args.auto_start_mcp)

    def test_parse_args_explicit_gamever_overrides_reference_environment(self) -> None:
        with patch.dict(
            "os.environ",
            {"GSVIBE_REFERENCE_GAMEVER": "hl-10210"},
            clear=True,
        ):
            args = generate_reference_yaml.parse_args(["-gamever", "cstrike-10210", "-func_name", "R_RenderView"])
        self.assertEqual("cstrike-10210", args.gamever)

    def test_parse_args_requires_binary_and_auto_start_as_a_pair(self) -> None:
        with self.assertRaises(SystemExit):
            generate_reference_yaml.parse_args(["-func_name", "R_RenderView", "-auto_start_mcp"])
        with self.assertRaises(SystemExit):
            generate_reference_yaml.parse_args(["-func_name", "R_RenderView", "-binary", "hw.dll"])

    def test_infer_target_from_goldsrc_binary_paths(self) -> None:
        self.assertEqual(
            {"gamever": "hl-10210", "module": "engine", "platform": "windows"},
            generate_reference_yaml.infer_target_from_binary_path(
                r"D:\GoldSrc_VibeSignatures\bin\hl-10210\engine\hw.dll.idb"
            ),
        )
        self.assertEqual(
            {"gamever": "svencoop-10257", "module": "server", "platform": "linux"},
            generate_reference_yaml.infer_target_from_binary_path("/work/bin/svencoop-10257/server/server.so"),
        )

    def test_infer_target_rejects_invalid_tag_and_layout(self) -> None:
        for path in ("/tmp/hw.dll", "/repo/bin/14141/engine/hw.dll"):
            with self.subTest(path=path), self.assertRaises(generate_reference_yaml.ReferenceGenerationError):
                generate_reference_yaml.infer_target_from_binary_path(path)

    def test_reference_output_path_is_confined_to_gamever_module_directory(self) -> None:
        self.assertEqual(
            Path("/repo/ida_preprocessor_scripts/references/hl-10210/engine/R_RenderView.windows.yaml"),
            generate_reference_yaml.build_reference_output_path(
                "/repo", "hl-10210", "engine", "R_RenderView", "windows"
            ),
        )
        for module, func_name, output_filename in (
            ("../engine", "R_RenderView", None),
            ("engine", "../R_RenderView", None),
            ("engine", "R_RenderView", "../escape.yaml"),
            ("engine", "R_RenderView", "reference.txt"),
            ("engine", "R_RenderView", "stream:ads.yaml"),
            ("engine", "R_RenderView", "CON.yaml"),
            ("engine", "R_RenderView", "reference.yaml."),
        ):
            with (
                self.subTest(
                    module=module,
                    func_name=func_name,
                    output_filename=output_filename,
                ),
                self.assertRaises(generate_reference_yaml.ReferenceGenerationError),
            ):
                generate_reference_yaml.build_reference_output_path(
                    "/repo", "hl-10210", module, func_name, "windows", output_filename
                )

    def test_reference_output_path_rejects_invalid_gamever(self) -> None:
        with self.assertRaises(generate_reference_yaml.ReferenceGenerationError):
            generate_reference_yaml.build_reference_output_path(
                "/repo", "../escape", "engine", "R_RenderView", "windows"
            )

    def test_load_existing_func_va_and_symbol_aliases(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            artifact = root / "bin" / "hl-10210" / "engine" / "R_RenderView.windows.yaml"
            artifact.parent.mkdir(parents=True)
            artifact.write_text("func_va: '0x10244610'\n", encoding="utf-8")
            self.assertEqual(
                "0x10244610",
                generate_reference_yaml.load_existing_func_va(root, "hl-10210", "engine", "R_RenderView", "windows"),
            )

            config = root / "configs" / "hl-10210.yaml"
            config.parent.mkdir()
            config.write_text(
                yaml.safe_dump(
                    {
                        "modules": [
                            {
                                "name": "engine",
                                "module_windows": "hw.dll",
                                "symbols": [
                                    {
                                        "name": "R_RenderView",
                                        "category": "func",
                                        "alias": ["R_RenderView", "Renderer::RenderView"],
                                    }
                                ],
                            }
                        ]
                    },
                    sort_keys=False,
                ),
                encoding="utf-8",
            )
            self.assertEqual(
                ["R_RenderView", "Renderer::RenderView"],
                generate_reference_yaml.load_symbol_aliases(config, "engine", "R_RenderView"),
            )
            self.assertEqual(
                root / "bin" / "hl-10210" / "engine" / "hw.dll",
                generate_reference_yaml.resolve_configured_binary_path(root, "hl-10210", "engine", "windows", config),
            )

    def test_validate_autostart_binary_accepts_only_matching_i386_binary(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            windows = write_pe32(root / "hw.dll")
            linux = write_elf32(root / "hw.so")
            self.assertEqual(
                "windows",
                generate_reference_yaml.validate_autostart_binary(windows, "windows"),
            )
            self.assertEqual(
                "linux",
                generate_reference_yaml.validate_autostart_binary(linux, None),
            )
            with self.assertRaisesRegex(
                generate_reference_yaml.ReferenceGenerationError,
                "Binary/platform mismatch",
            ):
                generate_reference_yaml.validate_autostart_binary(windows, "linux")

    def test_write_reference_yaml_uses_literal_blocks_and_minimal_schema(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "reference.yaml"
            generate_reference_yaml.write_reference_yaml(
                path,
                {
                    "func_name": "R_RenderView",
                    "func_va": "0x10244610",
                    "disasm_code": "line 1\nline 2",
                    "procedure": "void f()\n{}",
                    "extra": 1,
                },
            )
            document = yaml.safe_load(path.read_text(encoding="utf-8"))
            self.assertEqual(
                ["func_name", "func_va", "disasm_code", "procedure"],
                list(document),
            )
            self.assertNotIn("extra", document)
            self.assertIn("disasm_code: |", path.read_text(encoding="utf-8"))

    def test_remote_export_builder_is_atomic_and_requires_absolute_path(self) -> None:
        code = generate_reference_yaml.build_remote_text_export_py_eval(
            output_path="D:/repo/reference.yaml",
            producer_code="payload_text = 'ok'",
        )
        self.assertIn("tmp_path = output_path + '.tmp'", code)
        self.assertIn("os.replace(tmp_path, output_path)", code)
        with self.assertRaisesRegex(ValueError, "must be absolute"):
            generate_reference_yaml.build_remote_text_export_py_eval(
                output_path="relative/reference.yaml",
                producer_code="payload_text = 'ok'",
            )

    def test_reference_export_builder_is_self_contained_and_valid_python(self) -> None:
        code = generate_reference_yaml.build_reference_yaml_export_py_eval(
            0x10244610,
            output_path="D:/repo/reference.yaml",
            func_name="R_RenderView",
        )
        compile(code, "<reference-export>", "exec")
        self.assertNotIn("import yaml", code)
        self.assertLess(code.index("reference disassembly is empty"), code.index("os.replace(tmp_path, output_path)"))

    def test_function_detail_builder_exports_comments_chunks_and_pseudocode(self) -> None:
        code = generate_reference_yaml.build_function_detail_export_py_eval(0x10244610)
        for marker in (
            "func_ea = 270812688",
            "idautils.Chunks",
            "idc.get_cmt",
            "ida_hexrays.decompile",
            "{ea:08X}",
            '"disasm_code"',
            '"procedure"',
        ):
            self.assertIn(marker, code)


class ReferenceYamlMcpTests(unittest.IsolatedAsyncioTestCase):
    async def test_find_function_addr_by_names_requires_one_unique_address(self) -> None:
        session = SimpleNamespace(
            call_tool=AsyncMock(
                return_value=_py_eval_result(
                    [
                        {"name": "R_RenderView", "func_va": "0x10244610"},
                        {"name": "Renderer::RenderView", "func_va": "0x10244610"},
                    ]
                )
            )
        )
        self.assertEqual(
            "0x10244610",
            await generate_reference_yaml.find_function_addr_by_names(
                session, ["R_RenderView", "Renderer::RenderView"]
            ),
        )
        session.call_tool.return_value = _py_eval_result(
            [
                {"name": "R_RenderView", "func_va": "0x10244610"},
                {"name": "Renderer::RenderView", "func_va": "0x10245610"},
            ]
        )
        with self.assertRaisesRegex(generate_reference_yaml.ReferenceGenerationError, "ambiguous"):
            await generate_reference_yaml.find_function_addr_by_names(session, ["R_RenderView", "Renderer::RenderView"])

    async def test_py_eval_parser_accepts_goldsrc_structured_content(self) -> None:
        self.assertEqual(
            {"ok": True},
            generate_reference_yaml._parse_py_eval_json_result(_FakeStructuredCallToolResult({"ok": True})),
        )

    async def test_validate_bound_binary_uses_repository_identity_contract(self) -> None:
        session = object()
        survey_payload = {"metadata": {"path": "/repo/bin/hl-10210/engine/hw.dll"}}
        ida_helpers = SimpleNamespace(validate_opened_binary_identity=Mock(return_value=(True, [])))
        with (
            patch.object(
                generate_reference_yaml,
                "survey_binary_via_session",
                AsyncMock(return_value=survey_payload),
            ),
            patch.object(generate_reference_yaml, "_load_ida_analyze_bin", return_value=ida_helpers),
        ):
            await generate_reference_yaml.validate_bound_binary_via_session(
                session, "/repo/bin/hl-10210/engine/hw.dll", "windows"
            )
        ida_helpers.validate_opened_binary_identity.assert_called_once_with(
            "/repo/bin/hl-10210/engine/hw.dll", "windows", survey_payload
        )

    async def test_resolve_func_va_prefers_existing_artifact(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            artifact = root / "bin" / "hl-10210" / "engine" / "R_RenderView.windows.yaml"
            artifact.parent.mkdir(parents=True)
            artifact.write_text("func_va: '0x10244610'\n", encoding="utf-8")
            session = SimpleNamespace(call_tool=AsyncMock())
            value = await generate_reference_yaml.resolve_func_va(
                session,
                repo_root=root,
                gamever="hl-10210",
                module="engine",
                platform="windows",
                func_name="R_RenderView",
                config_path=root / "unused.yaml",
                debug=False,
            )
            self.assertEqual("0x10244610", value)
            session.call_tool.assert_not_awaited()

    async def test_export_reference_payload_uses_shared_function_detail_builder(self) -> None:
        session = SimpleNamespace(
            call_tool=AsyncMock(
                return_value=_py_eval_result(
                    {
                        "func_name": "sub_10244610",
                        "func_va": "0x10244610",
                        "disasm_code": "push ebp",
                        "procedure": "void f() {}",
                    }
                )
            )
        )
        with patch.object(
            generate_reference_yaml,
            "build_function_detail_export_py_eval",
            return_value="export-code",
        ) as builder:
            payload = await generate_reference_yaml.export_reference_payload_via_mcp(
                session,
                func_name="R_RenderView",
                func_va="0x10244610",
            )
        self.assertEqual("R_RenderView", payload["func_name"])
        builder.assert_called_once_with(0x10244610)
        session.call_tool.assert_awaited_once_with(name="py_eval", arguments={"code": "export-code"})

    async def test_export_reference_yaml_validates_remote_ack_and_written_payload(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            output_path = Path(temp_dir) / "reference.yaml"

            async def _write_valid_payload(*, name, arguments):
                self.assertEqual("py_eval", name)
                self.assertEqual({"code": "export-code"}, arguments)
                output_path.write_text(
                    yaml.safe_dump(
                        {
                            "func_name": "R_RenderView",
                            "func_va": "0x10244610",
                            "disasm_code": "push ebp",
                            "procedure": "void f() {}",
                        },
                        sort_keys=False,
                    ),
                    encoding="utf-8",
                )
                return _py_eval_result(
                    {
                        "ok": True,
                        "output_path": str(output_path.resolve()),
                        "bytes_written": output_path.stat().st_size,
                        "format": "yaml",
                    }
                )

            session = SimpleNamespace(call_tool=AsyncMock(side_effect=_write_valid_payload))
            with patch.object(
                generate_reference_yaml,
                "build_reference_yaml_export_py_eval",
                return_value="export-code",
            ):
                result = await generate_reference_yaml.export_reference_yaml_via_mcp(
                    session,
                    func_name="R_RenderView",
                    func_va="0x10244610",
                    output_path=output_path,
                )
            self.assertEqual(output_path.resolve(), result)

    async def test_export_reference_yaml_reports_remote_error(self) -> None:
        session = SimpleNamespace(
            call_tool=AsyncMock(
                return_value=_py_eval_result(
                    {
                        "ok": False,
                        "output_path": "D:/repo/reference.yaml",
                        "error": "reference disassembly is empty",
                    }
                )
            )
        )
        with self.assertRaisesRegex(
            generate_reference_yaml.ReferenceGenerationError,
            "reference disassembly is empty",
        ):
            await generate_reference_yaml.export_reference_yaml_via_mcp(
                session,
                func_name="R_RenderView",
                func_va="0x10244610",
                output_path="D:/repo/reference.yaml",
            )

    async def test_export_reference_yaml_rejects_invalid_written_yaml(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            output_path = Path(temp_dir) / "reference.yaml"

            async def _write_invalid_payload(**_kwargs):
                output_path.write_text("func_name: R_RenderView\n", encoding="utf-8")
                return _py_eval_result(
                    {
                        "ok": True,
                        "output_path": str(output_path.resolve()),
                        "bytes_written": output_path.stat().st_size,
                        "format": "yaml",
                    }
                )

            session = SimpleNamespace(call_tool=AsyncMock(side_effect=_write_invalid_payload))
            with self.assertRaisesRegex(
                generate_reference_yaml.ReferenceGenerationError,
                "unable to export reference YAML via IDA",
            ):
                await generate_reference_yaml.export_reference_yaml_via_mcp(
                    session,
                    func_name="R_RenderView",
                    func_va="0x10244610",
                    output_path=output_path,
                )

    async def test_export_reference_yaml_rejects_wrong_written_identity(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            output_path = Path(temp_dir) / "reference.yaml"

            async def _write_wrong_identity(**_kwargs):
                output_path.write_text(
                    yaml.safe_dump(
                        {
                            "func_name": "OtherFunction",
                            "func_va": "0x10245610",
                            "disasm_code": "push ebp",
                            "procedure": "",
                        },
                        sort_keys=False,
                    ),
                    encoding="utf-8",
                )
                return _py_eval_result(
                    {
                        "ok": True,
                        "output_path": str(output_path.resolve()),
                        "bytes_written": output_path.stat().st_size,
                        "format": "yaml",
                    }
                )

            session = SimpleNamespace(call_tool=AsyncMock(side_effect=_write_wrong_identity))
            with self.assertRaisesRegex(
                generate_reference_yaml.ReferenceGenerationError,
                "unable to export reference YAML via IDA",
            ):
                await generate_reference_yaml.export_reference_yaml_via_mcp(
                    session,
                    func_name="R_RenderView",
                    func_va="0x10244610",
                    output_path=output_path,
                )

    async def test_attach_session_passes_explicit_database(self) -> None:
        session = object()

        @asynccontextmanager
        async def _fake_open(host, port, **kwargs):
            self.assertEqual(("127.0.0.1", 13337), (host, port))
            self.assertEqual({"explicit_database": "db-1"}, kwargs)
            yield session

        with patch.object(generate_reference_yaml, "open_ida_mcp_session", _fake_open):
            async with generate_reference_yaml.attach_existing_mcp_session(
                "127.0.0.1", 13337, False, explicit_database="db-1"
            ) as opened:
                self.assertIs(session, opened)

    async def test_autostart_session_uses_owned_goldsrc_lifecycle(self) -> None:
        session = object()
        lifecycle = Mock()
        lifecycle.__enter__ = Mock(return_value=lifecycle)
        lifecycle.__exit__ = Mock(return_value=False)

        @asynccontextmanager
        async def _fake_open(host, port, **kwargs):
            self.assertEqual(("127.0.0.1", 13337), (host, port))
            self.assertEqual(
                {
                    "expected_binary": "/tmp/hw.dll",
                    "auto_started": True,
                },
                kwargs,
            )
            yield session

        with (
            patch.object(
                generate_reference_yaml,
                "create_ida_mcp_lifecycle",
                return_value=lifecycle,
            ) as create_lifecycle,
            patch.object(generate_reference_yaml, "open_ida_mcp_session", _fake_open),
        ):
            async with generate_reference_yaml.autostart_mcp_session(
                binary_path="/tmp/hw.dll",
                platform="windows",
                host="127.0.0.1",
                port=13337,
                ida_args="",
                debug=False,
            ) as opened:
                self.assertIs(session, opened)

        create_lifecycle.assert_called_once_with("/tmp/hw.dll", "windows", "127.0.0.1", 13337, "", False)
        lifecycle.__enter__.assert_called_once_with()
        lifecycle.__exit__.assert_called_once_with(None, None, None)

    async def test_autostart_session_closes_lifecycle_when_cancelled_during_startup(self) -> None:
        enter_started = threading.Event()
        allow_enter = threading.Event()
        lifecycle = Mock()

        def _enter():
            enter_started.set()
            allow_enter.wait(timeout=5)
            return lifecycle

        lifecycle.__enter__ = Mock(side_effect=_enter)
        lifecycle.__exit__ = Mock(return_value=False)

        async def _open_session() -> None:
            async with generate_reference_yaml.autostart_mcp_session(
                binary_path="/tmp/hw.dll",
                platform="windows",
                host="127.0.0.1",
                port=13337,
                ida_args="",
                debug=False,
            ):
                self.fail("cancelled startup must not yield a session")

        with patch.object(
            generate_reference_yaml,
            "create_ida_mcp_lifecycle",
            return_value=lifecycle,
        ):
            task = asyncio.create_task(_open_session())
            self.assertTrue(await asyncio.to_thread(enter_started.wait, 5))
            task.cancel()
            allow_enter.set()
            with self.assertRaises(asyncio.CancelledError):
                await task

        lifecycle.__enter__.assert_called_once_with()
        lifecycle.__exit__.assert_called_once_with(None, None, None)

    async def test_resolve_generation_target_surveys_only_missing_fields(self) -> None:
        session = object()
        with patch.object(
            generate_reference_yaml,
            "survey_binary_via_session",
            AsyncMock(return_value={"metadata": {"path": "D:/repo/bin/hl-10210/engine/hw.dll.idb"}}),
        ) as survey:
            target = await generate_reference_yaml.resolve_generation_target(
                session=session,
                gamever=None,
                module="engine",
                platform=None,
            )
        self.assertEqual(
            {"gamever": "hl-10210", "module": "engine", "platform": "windows"},
            target,
        )
        survey.assert_awaited_once_with(session)

    async def test_run_reference_generation_orchestrates_attach_mode(self) -> None:
        session = object()
        expected_path = Path("/repo/ida_preprocessor_scripts/references/hl-10210/engine/R_RenderView.windows.yaml")

        @asynccontextmanager
        async def _fake_attach(**kwargs):
            self.assertEqual(
                {
                    "host": "127.0.0.1",
                    "port": 13337,
                    "debug": False,
                    "expected_binary": str(Path("/repo/bin/hl-10210/engine/hw.dll")),
                },
                kwargs,
            )
            yield session

        with (
            patch.object(generate_reference_yaml, "attach_existing_mcp_session", _fake_attach),
            patch.object(
                generate_reference_yaml,
                "resolve_analysis_config",
                return_value=Path("/repo/configs/hl-10210.yaml"),
            ),
            patch.object(
                generate_reference_yaml,
                "resolve_func_va",
                AsyncMock(return_value="0x10244610"),
            ) as resolve_va,
            patch.object(
                generate_reference_yaml,
                "resolve_configured_binary_path",
                return_value=Path("/repo/bin/hl-10210/engine/hw.dll"),
            ),
            patch.object(generate_reference_yaml, "validate_autostart_binary"),
            patch.object(
                generate_reference_yaml,
                "validate_bound_binary_via_session",
                AsyncMock(),
            ),
            patch.object(
                generate_reference_yaml,
                "export_reference_yaml_via_mcp",
                AsyncMock(return_value=expected_path),
            ) as export_yaml,
        ):
            result = await generate_reference_yaml.run_reference_generation(_base_args(), repo_root="/repo")

        self.assertEqual(expected_path, result)
        resolve_va.assert_awaited_once()
        export_yaml.assert_awaited_once_with(
            session,
            func_name="R_RenderView",
            func_va="0x10244610",
            output_path=expected_path,
            debug=False,
        )

    async def test_run_reference_generation_validates_autostart_binary(self) -> None:
        args = _base_args(
            gamever=None,
            module=None,
            binary="/repo/bin/hl-10210/engine/hw.dll",
            auto_start_mcp=True,
        )
        with (
            patch.object(
                generate_reference_yaml,
                "validate_autostart_binary",
                side_effect=generate_reference_yaml.ReferenceGenerationError("bad binary"),
            ) as validate,
            self.assertRaisesRegex(generate_reference_yaml.ReferenceGenerationError, "bad binary"),
        ):
            await generate_reference_yaml.run_reference_generation(args, repo_root="/repo")
        validate.assert_called_once_with(args.binary, "windows")

    async def test_run_reference_generation_rejects_binary_not_declared_by_config(self) -> None:
        args = _base_args(
            binary="/repo/bin/hl-10210/engine/other.dll",
            auto_start_mcp=True,
        )
        with (
            patch.object(
                generate_reference_yaml,
                "resolve_analysis_config",
                return_value=Path("/repo/configs/hl-10210.yaml"),
            ),
            patch.object(
                generate_reference_yaml,
                "resolve_configured_binary_path",
                return_value=Path("/repo/bin/hl-10210/engine/hw.dll"),
            ),
            patch.object(
                generate_reference_yaml,
                "validate_autostart_binary",
                return_value="windows",
            ),
            self.assertRaisesRegex(
                generate_reference_yaml.ReferenceGenerationError,
                "must match the configured target binary",
            ),
        ):
            await generate_reference_yaml.run_reference_generation(args, repo_root="/repo")

    async def test_run_reference_generation_rejects_misbound_explicit_database(self) -> None:
        session = object()
        args = _base_args(
            binary="/repo/bin/hl-10210/engine/hw.dll",
            auto_start_mcp=True,
            mcp_database="db-wrong",
        )

        @asynccontextmanager
        async def _fake_autostart(**kwargs):
            self.assertEqual("db-wrong", kwargs["explicit_database"])
            yield session

        with (
            patch.object(generate_reference_yaml, "autostart_mcp_session", _fake_autostart),
            patch.object(
                generate_reference_yaml,
                "resolve_analysis_config",
                return_value=Path("/repo/configs/hl-10210.yaml"),
            ),
            patch.object(
                generate_reference_yaml,
                "resolve_configured_binary_path",
                return_value=Path("/repo/bin/hl-10210/engine/hw.dll"),
            ),
            patch.object(
                generate_reference_yaml,
                "validate_autostart_binary",
                return_value="windows",
            ),
            patch.object(
                generate_reference_yaml,
                "validate_bound_binary_via_session",
                AsyncMock(
                    side_effect=generate_reference_yaml.ReferenceGenerationError(
                        "bound IDA database does not match configured binary"
                    )
                ),
            ),
            self.assertRaisesRegex(
                generate_reference_yaml.ReferenceGenerationError,
                "bound IDA database does not match",
            ),
        ):
            await generate_reference_yaml.run_reference_generation(args, repo_root="/repo")


class ReferenceYamlMainTests(unittest.TestCase):
    def test_main_loads_repository_env_before_parsing_args(self) -> None:
        def load_reference_gamever(_path: Path) -> None:
            generate_reference_yaml.os.environ["GSVIBE_REFERENCE_GAMEVER"] = "hl-10210"

        with (
            patch.dict("os.environ", {}, clear=True),
            patch.object(
                generate_reference_yaml,
                "load_dotenv",
                side_effect=load_reference_gamever,
            ) as load_dotenv_mock,
            patch.object(
                generate_reference_yaml,
                "run_reference_generation",
                AsyncMock(return_value=Path("/tmp/reference.yaml")),
            ) as run_mock,
            patch("builtins.print"),
        ):
            self.assertEqual(0, generate_reference_yaml.main(["-func_name", "R_RenderView"]))

        load_dotenv_mock.assert_called_once_with(Path(generate_reference_yaml.__file__).with_name(".env"))
        run_mock.assert_awaited_once()
        run_args = run_mock.await_args
        self.assertIsNotNone(run_args)
        assert run_args is not None
        self.assertEqual("hl-10210", run_args.args[0].gamever)

    def test_main_reports_success_and_controlled_failure(self) -> None:
        with (
            patch.object(generate_reference_yaml, "load_dotenv"),
            patch.object(
                generate_reference_yaml,
                "run_reference_generation",
                AsyncMock(return_value=Path("/tmp/reference.yaml")),
            ),
            patch("builtins.print") as print_mock,
        ):
            self.assertEqual(0, generate_reference_yaml.main(["-func_name", "R_RenderView"]))
        print_mock.assert_any_call(f"Generated reference YAML: {Path('/tmp/reference.yaml')}")

        with (
            patch.object(generate_reference_yaml, "load_dotenv"),
            patch.object(
                generate_reference_yaml,
                "run_reference_generation",
                AsyncMock(side_effect=generate_reference_yaml.ReferenceGenerationError("failed")),
            ),
            patch("builtins.print") as print_mock,
        ):
            self.assertEqual(1, generate_reference_yaml.main(["-func_name", "R_RenderView"]))
        print_mock.assert_any_call("ERROR: failed")


if __name__ == "__main__":
    unittest.main()
