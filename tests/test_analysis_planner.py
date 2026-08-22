from __future__ import annotations

import hashlib
import io
import os
import tempfile
import unittest
from contextlib import asynccontextmanager, redirect_stderr, redirect_stdout
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

from agent_runner import build_agent_command
from analysis_planner import (
    AnalysisPlanError,
    build_execution_plan,
    build_process_execution_plan,
    expected_symbol_artifacts,
    parse_config_document,
)
from ida_analyze_bin import (
    ANALYSIS_STAGES,
    DEFAULT_HOST,
    DEFAULT_PORT,
    SURVEY_CURRENT_IDB_PATH_PY_EVAL,
    AnalysisRunError,
    AnalysisSummary,
    IdaMcpLifecycle,
    McpLifecycleError,
    McpRecoveryBudget,
    McpRuntime,
    PipelineFailure,
    PipelineResult,
    _allgamever_module_filter_matches,
    _invalidate_ida_database,
    _is_major_update_gamever,
    _merge_survey_path,
    _parse_mcp_tool_json,
    _select_requested_nodes,
    _validate_selected_inputs,
    analyze,
    ensure_mcp_available,
    main,
    parse_args,
    quit_ida_via_mcp,
    resolve_oldgamever,
    run_analysis_pipeline,
    save_ida_database_via_mcp,
    start_idalib_mcp,
    validate_opened_binary_identity,
)
from ida_mcp_session import McpDatabaseBinding
from ida_skill_preprocessor import (
    PREPROCESS_STATUS_ABSENT_OK,
    PREPROCESS_STATUS_FAILED,
    PREPROCESS_STATUS_NO_SCRIPT,
    PREPROCESS_STATUS_SUCCESS,
)
from process_reporter import RunStatus, TaskStatus
from tests.test_decrypt_blob import make_blob
from tests.test_support import write_pe32


def skill(name, *, output=(), optional_output=(), required_input=(), optional_input=(), prerequisite=()):
    return {
        "name": name,
        "expected_output": list(output),
        "expected_output_windows": [],
        "expected_output_linux": [],
        "optional_output": list(optional_output),
        "expected_input": list(required_input),
        "expected_input_windows": [],
        "expected_input_linux": [],
        "optional_input": list(optional_input),
        "optional_input_windows": [],
        "optional_input_linux": [],
        "prerequisite": list(prerequisite),
        "skip_if_exists": [],
        "max_retries": 2,
        "aliases": [],
        "platform": None,
    }


def module(skills):
    return [
        {
            "stage_index": 0,
            "name": "engine",
            "path_windows": "Game/hw.dll",
            "module_windows": "hw.dll",
            "path_linux": None,
            "skills": skills,
            "symbols": [],
        }
    ]


class RecordingAnalysisReporting:
    def __init__(self) -> None:
        self.events = []

    def emit_task_status(self, task_id, status, phase, **details) -> None:
        self.events.append(
            {"event_type": "task.status_changed", "task_id": task_id, "status": status, "phase": phase, **details}
        )

    def emit_progress(self, task_id, phase, **payload) -> None:
        self.events.append({"event_type": "skill.progress", "task_id": task_id, "phase": phase, "payload": payload})


class RecordingProcessReporter:
    def __init__(self) -> None:
        self.plan = None
        self.events = []
        self.finalized = None
        self.flushed = False
        self.closed = False

    def initialize_run(self, plan, run_id=None):
        self.plan = plan
        return run_id or "recorded-run"

    def emit(self, event) -> None:
        self.events.append(event)

    def heartbeat(self, run_id) -> None:
        self.heartbeat_run_id = run_id

    def finalize_run(self, run_id, status, summary) -> None:
        self.finalized = (run_id, status, summary)

    def flush(self) -> None:
        self.flushed = True

    def close(self) -> None:
        self.closed = True


@asynccontextmanager
async def bound_session_context(binding, call_tool):
    yield SimpleNamespace(binding=binding, call_tool=call_tool)


class ConfigValidationTests(unittest.TestCase):
    def test_parses_alias_retry_and_struct_member_metadata(self):
        modules = parse_config_document(
            {
                "modules": [
                    {
                        "name": "engine",
                        "path_windows": "Game/hw.dll",
                        "module_windows": "hw.dll",
                        "skills": [
                            {
                                "name": "find",
                                "alias": "old",
                                "retry": 4,
                                "optional_output_windows": ["optional.windows.yaml"],
                            }
                        ],
                        "symbols": [
                            {"name": "A", "category": "struct"},
                            {"name": "A::b", "category": "structmember", "struct": "A", "member": "b"},
                        ],
                    }
                ]
            }
        )
        self.assertEqual(["old"], modules[0]["skills"][0]["aliases"])
        self.assertEqual(4, modules[0]["skills"][0]["max_retries"])
        self.assertEqual(["optional.windows.yaml"], modules[0]["skills"][0]["optional_output_windows"])
        self.assertEqual("A", modules[0]["symbols"][1]["struct"])
        required, optional = expected_symbol_artifacts(modules)
        self.assertIn("engine/A_b.windows.yaml", required)
        self.assertIn("engine/optional.windows.yaml", optional)

    def test_accepts_windows_only_and_linux_only_modules(self):
        modules = parse_config_document(
            {
                "modules": [
                    {
                        "name": "windows-engine",
                        "path_windows": "Game/hw.dll",
                        "module_windows": "hw.dll",
                        "skills": [{"name": "find"}],
                    },
                    {
                        "name": "linux-engine",
                        "path_linux": "Game/hw.so",
                        "module_linux": "hw.so",
                        "skills": [{"name": "find"}],
                    },
                ]
            }
        )
        self.assertEqual("Game/hw.dll", modules[0]["path_windows"])
        self.assertIsNone(modules[0]["path_linux"])
        self.assertIsNone(modules[1]["path_windows"])
        self.assertEqual("Game/hw.so", modules[1]["path_linux"])

        plan = build_execution_plan(modules, platforms=["windows", "linux"], bin_dir="bin", tag="game-1")
        self.assertEqual(
            ["windows-engine:windows:find", "linux-engine:linux:find"],
            [node.id for node in plan.nodes],
        )

    def test_rejects_module_without_any_platform_declaration(self):
        with self.assertRaises(AnalysisPlanError):
            parse_config_document({"modules": [{"name": "engine"}]})

    def test_accepts_path_only_and_module_only_platform_declarations(self):
        modules = parse_config_document(
            {
                "modules": [
                    {
                        "name": "path-engine",
                        "path_windows": "Game/hw.dll",
                        "skills": [{"name": "find"}],
                    },
                    {
                        "name": "module-engine",
                        "module_linux": "hw.so",
                        "skills": [{"name": "find"}],
                    },
                ]
            }
        )
        self.assertEqual("Game/hw.dll", modules[0]["path_windows"])
        self.assertEqual("hw.dll", modules[0]["module_windows"])
        self.assertIsNone(modules[0]["module_linux"])
        self.assertIsNone(modules[1]["path_linux"])
        self.assertEqual("hw.so", modules[1]["module_linux"])

        plan = build_execution_plan(modules, platforms=["windows", "linux"], bin_dir="bin", tag="game-1")
        self.assertEqual(
            ["path-engine:windows:find", "module-engine:linux:find"],
            [node.id for node in plan.nodes],
        )

    def test_rejects_cross_directory_outputs_and_absolute_artifacts(self):
        for path in ("../other/a.yaml", "other/a.yaml", "C:/a.yaml", "/a.yaml"):
            with self.subTest(path=path), self.assertRaises(AnalysisPlanError):
                parse_config_document(
                    {
                        "modules": [
                            {
                                "name": "engine",
                                "path_windows": "Game/hw.dll",
                                "module_windows": "hw.dll",
                                "skills": [{"name": "find", "expected_output": [path]}],
                            }
                        ]
                    }
                )

    def test_accepts_sibling_module_inputs_but_rejects_game_root_escape(self):
        modules = parse_config_document(
            {
                "modules": [
                    {"name": "engine", "path_windows": "Game/hw.dll", "module_windows": "hw.dll"},
                    {
                        "name": "client",
                        "path_windows": "Game/client.dll",
                        "module_windows": "client.dll",
                        "skills": [
                            {
                                "name": "consume",
                                "expected_input": ["../engine/a.{platform}.yaml"],
                            }
                        ],
                    },
                ]
            }
        )
        self.assertEqual(
            ["../engine/a.{platform}.yaml"],
            modules[1]["skills"][0]["expected_input"],
        )
        with self.assertRaises(AnalysisPlanError):
            parse_config_document(
                {
                    "modules": [
                        {
                            "name": "engine",
                            "path_windows": "Game/hw.dll",
                            "module_windows": "hw.dll",
                            "skills": [{"name": "escape", "expected_input": ["../../outside.yaml"]}],
                        }
                    ]
                }
            )

    def test_requires_category_and_rejects_legacy_symbol_classification(self):
        for legacy_key in ("type", "kind"):
            with self.subTest(legacy_key=legacy_key), self.assertRaises(AnalysisPlanError):
                parse_config_document(
                    {
                        "modules": [
                            {
                                "name": "engine",
                                "path_windows": "Game/hw.dll",
                                "module_windows": "hw.dll",
                                "symbols": [{"name": "R_RenderView", legacy_key: "func"}],
                            }
                        ]
                    }
                )

    def test_rejects_duplicate_and_case_colliding_names(self):
        with self.assertRaises(AnalysisPlanError):
            parse_config_document(
                {
                    "modules": [
                        {
                            "name": "engine",
                            "path_windows": "Game/hw.dll",
                            "module_windows": "hw.dll",
                            "skills": [{"name": "Find"}, {"name": "find"}],
                        }
                    ]
                }
            )

    def test_unspecified_skill_retry_inherits_plan_default(self):
        modules = parse_config_document(
            {
                "modules": [
                    {
                        "name": "engine",
                        "path_windows": "Game/hw.dll",
                        "module_windows": "hw.dll",
                        "skills": [
                            {"name": "inherited"},
                            {"name": "explicit", "max_retries": 2},
                        ],
                    }
                ]
            }
        )
        self.assertIsNone(modules[0]["skills"][0]["max_retries"])
        plan = build_execution_plan(
            modules,
            platforms=["windows"],
            bin_dir="bin",
            tag="game-1",
            default_max_retries=5,
        )
        self.assertEqual([5, 2], [node.max_retries for node in plan.nodes])


class CliContractTests(unittest.TestCase):
    def parse_args(self, argv=(), env=None):
        with patch.dict(os.environ, env or {}, clear=True):
            return parse_args(list(argv))

    def assert_parse_error(self, argv, env=None):
        with (
            patch.dict(os.environ, env or {}, clear=True),
            redirect_stderr(io.StringIO()),
            self.assertRaises(SystemExit) as raised,
        ):
            parse_args(list(argv))
        self.assertEqual(2, raised.exception.code)

    def test_cs2_style_defaults_use_gsvibe_namespace(self):
        args = self.parse_args(["-gamever", "cstrike-10210"])
        self.assertEqual("cstrike-10210", args.gamever)
        self.assertEqual(["windows", "linux"], args.platforms)
        self.assertIsNone(args.module_filter)
        self.assertEqual("claude", args.agent)
        self.assertEqual("", args.agent_model)
        self.assertEqual("gpt-4o", args.llm_model)
        self.assertIsNone(args.llm_apikey)
        self.assertIsNone(args.llm_baseurl)
        self.assertIsNone(args.llm_temperature)
        self.assertIsNone(args.llm_fake_as)
        self.assertEqual("medium", args.llm_effort)
        self.assertEqual(3, args.maxretry)
        self.assertEqual("", args.ida_args)
        self.assertEqual("none", args.process_reporter)
        self.assertEqual("redis://127.0.0.1:6379/0", args.redis_url)
        self.assertEqual("gsvibe:analysis:v1", args.redis_prefix)
        self.assertIsNone(args.run_id)

    def test_blank_agent_environment_values_use_defaults(self):
        args = self.parse_args(
            ["-gamever", "cstrike-10210"],
            env={
                "GSVIBE_AGENT": "",
                "GSVIBE_AGENT_MODEL": "",
                "GSVIBE_LLM_MODEL": "",
                "GSVIBE_LLM_EFFORT": "",
            },
        )
        self.assertEqual("claude", args.agent)
        self.assertEqual("", args.agent_model)
        self.assertEqual("gpt-4o", args.llm_model)
        self.assertEqual("medium", args.llm_effort)

    def test_selected_nodes_are_repeatable_and_reject_legacy_filters(self):
        args = self.parse_args(
            [
                "-gamever",
                "hl-10210",
                "-oldgamever",
                "none",
                "-node",
                "engine:windows:produce",
                "-node",
                "client:linux:consume",
            ]
        )
        self.assertEqual(["engine:windows:produce", "client:linux:consume"], args.node)
        self.assertEqual(["windows", "linux"], args.platforms)
        self.assertIsNone(args.module_filter)
        for conflict in ("-skill", "-modules", "-platform", "-allgamever"):
            value = "find" if conflict == "-skill" else "engine" if conflict == "-modules" else "windows"
            argv = ["-gamever", "hl-10210", "-node", "engine:windows:produce", conflict]
            if conflict != "-allgamever":
                argv.append(value)
            self.assert_parse_error(argv)
        self.assert_parse_error(
            ["-gamever", "hl-10210", "-node", "engine:windows:produce", "-node", "engine:windows:produce"]
        )

    def test_cli_values_override_gsvibe_environment(self):
        args = self.parse_args(
            [
                "-gamever",
                "cstrike-10121",
                "-platform",
                "linux",
                "-agent",
                "codex",
                "-agent_model",
                "gpt-5",
                "-llm_model",
                "cli-model",
                "-llm_apikey",
                "cli-key",
                "-llm_baseurl",
                "https://example.invalid/v1",
                "-llm_temperature",
                "0.5",
                "-llm_fake_as",
                "codex",
                "-llm_effort",
                "high",
                "-maxretry",
                "4",
                "-ida_args",
                "quiet",
                "-process_reporter",
                "console",
                "-redis_url",
                "redis://cli.invalid:6379/2",
                "-redis_prefix",
                "cli:prefix",
                "-run_id",
                "cli-run",
            ],
            env={
                "GSVIBE_AGENT": "claude",
                "GSVIBE_AGENT_MODEL": "env-agent-model",
                "GSVIBE_LLM_MODEL": "env-model",
                "GSVIBE_LLM_APIKEY": "env-key",
                "GSVIBE_LLM_BASEURL": "https://env.invalid/v1",
                "GSVIBE_LLM_TEMPERATURE": "1.0",
                "GSVIBE_LLM_FAKE_AS": "codex",
                "GSVIBE_LLM_EFFORT": "low",
                "GSVIBE_PROCESS_REPORTER": "redis",
                "GSVIBE_REDIS_URL": "redis://env.invalid:6379/1",
                "GSVIBE_REDIS_PREFIX": "env:prefix",
                "GSVIBE_RUN_ID": "env-run",
            },
        )
        self.assertEqual("cstrike-10121", args.gamever)
        self.assertEqual(["linux"], args.platforms)
        self.assertEqual("codex", args.agent)
        self.assertEqual("gpt-5", args.agent_model)
        self.assertEqual("cli-model", args.llm_model)
        self.assertEqual("cli-key", args.llm_apikey)
        self.assertEqual("https://example.invalid/v1", args.llm_baseurl)
        self.assertEqual(0.5, args.llm_temperature)
        self.assertEqual("codex", args.llm_fake_as)
        self.assertEqual("high", args.llm_effort)
        self.assertEqual(4, args.maxretry)
        self.assertEqual("quiet", args.ida_args)
        self.assertEqual("console", args.process_reporter)
        self.assertEqual("redis://cli.invalid:6379/2", args.redis_url)
        self.assertEqual("cli:prefix", args.redis_prefix)
        self.assertEqual("cli-run", args.run_id)

    def test_removed_and_deferred_options_are_rejected(self):
        for option in (
            "-config",
            "-plan-only",
            "-vcall_finder",
            "-rename",
        ):
            with self.subTest(option=option):
                self.assert_parse_error(["-gamever", "cstrike-10210", option, "value"])
        self.assert_parse_error(["-gamever", "cstrike-10210", "-console-events"])
        self.assert_parse_error(["-gamever", "cstrike-10210", "-platform", "all-platform"])

    def test_invalid_lists_retry_llm_and_agent_fail_fast(self):
        invalid_argv = (
            ["-gamever", "cstrike-10210", "-platform", ""],
            ["-gamever", "cstrike-10210", "-platform", "windows,windows"],
            ["-gamever", "cstrike-10210", "-modules", "engine,,client"],
            ["-gamever", "cstrike-10210", "-modules", "engine,engine"],
            ["-gamever", "cstrike-10210", "-maxretry", "0"],
            ["-gamever", "cstrike-10210", "-llm_temperature", "3"],
            ["-gamever", "cstrike-10210", "-agent", ""],
            ["-gamever", "cstrike-10210", "-llm_fake_as", "codex"],
            ["-gamever", "cstrike-10210", "-redis_prefix", ":"],
            ["-gamever", "cstrike-10210", "-run_id", "unsafe/run"],
        )
        for argv in invalid_argv:
            with self.subTest(argv=argv):
                self.assert_parse_error(argv)

    def test_gamever_is_required_without_env_fallback(self):
        # GSVIBE_GAMEVER is no longer honored: -gamever or -allgamever must be explicit.
        self.assert_parse_error([])
        self.assert_parse_error([], env={"GSVIBE_GAMEVER": "cstrike-10210"})

    def test_oldgamever_auto_resolution_is_family_aware(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for tag in ("cstrike-10118", "cstrike-10119", "svencoop-99999", "cstrike-10121"):
                (root / tag).mkdir()
            self.assertEqual("cstrike-10121", resolve_oldgamever("cstrike-10210", root))
            args = self.parse_args(
                ["-gamever", "cstrike-10210", "-bindir", str(root)],
            )
            self.assertEqual("cstrike-10121", args.oldgamever)
            self.assert_parse_error(
                [
                    "-gamever",
                    "cstrike-10210",
                    "-bindir",
                    str(root),
                    "-oldgamever",
                    "svencoop-10257",
                ]
            )

    def test_major_update_flag_disables_auto_history_selection(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "download.yaml"
            path.write_text(
                "downloads:\n  - tag: cstrike-10210\n    major_update: true\n",
                encoding="utf-8",
            )
            self.assertTrue(_is_major_update_gamever("cstrike-10210", path))
            self.assertFalse(_is_major_update_gamever("cstrike-10119", path))

    def test_allgamever_rejects_conflicting_single_tag_options(self):
        conflicting = (
            ["-allgamever", "-gamever", "cstrike-10210"],
            ["-allgamever", "-configyaml", "config.yaml"],
            ["-allgamever", "-oldgamever", "cstrike-10119"],
            ["-allgamever", "-oldgamever", "none"],
            ["-allgamever", "-run_id", "cli-run"],
        )
        for argv in conflicting:
            with self.subTest(argv=argv):
                self.assert_parse_error(argv)

    def test_allgamever_accepts_no_gamever_and_disables_oldgamever(self):
        args = self.parse_args(["-allgamever", "-bindir", "bin"])
        self.assertTrue(args.allgamever)
        self.assertIsNone(args.gamever)
        self.assertIsNone(args.oldgamever)

    def test_allgamever_rejects_env_run_id(self):
        with (
            patch.dict(os.environ, {"GSVIBE_RUN_ID": "env-run"}, clear=True),
            redirect_stderr(io.StringIO()),
            self.assertRaises(SystemExit) as raised,
        ):
            parse_args(["-allgamever", "-bindir", "bin"])
        self.assertEqual(2, raised.exception.code)

    def test_run_all_batches_each_tag_and_aggregates(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "configs").mkdir()
            (root / "download.yaml").write_text(
                "downloads:\n  - tag: hl-10210\n  - tag: hl-8684\n",
                encoding="utf-8",
            )
            for tag in ("hl-8684", "hl-10210"):
                (root / "configs" / f"{tag}.yaml").write_text("modules: []\n", encoding="utf-8")

            def record_success(gamever, args, summary=None):
                del gamever, args
                summary.successful = 1
                return 0

            with (
                patch.dict(os.environ, {}, clear=True),
                patch("ida_analyze_bin.iter_analysis_config_tags", return_value=["hl-10210", "hl-8684"]),
                patch("ida_analyze_bin._run_single_tag", side_effect=record_success),
                redirect_stdout(io.StringIO()),
            ):
                result = main(["-allgamever", "-bindir", str(root / "bin")])
            self.assertEqual(0, result)

    def test_allgamever_module_filter_matches_configured_modules(self):
        modules = [{"name": "engine"}, {"name": "client"}]
        with (
            patch("ida_analyze_bin.resolve_analysis_config", return_value=Path("configs/hl-10210.yaml")),
            patch("ida_analyze_bin.load_config", return_value=({}, modules)),
        ):
            self.assertTrue(_allgamever_module_filter_matches("hl-10210", ["engine"]))
            self.assertFalse(_allgamever_module_filter_matches("hl-10210", ["server"]))

    def test_run_all_skips_tags_without_requested_modules(self):
        calls = []
        output = io.StringIO()

        def record_success(gamever, args, summary=None):
            del args
            calls.append(gamever)
            summary.successful = 1
            return 0

        with (
            patch.dict(os.environ, {}, clear=True),
            patch("ida_analyze_bin.iter_analysis_config_tags", return_value=["hl-10210", "cstrike-8684"]),
            patch("ida_analyze_bin._allgamever_module_filter_matches", side_effect=[True, False]),
            patch("ida_analyze_bin._run_single_tag", side_effect=record_success),
            redirect_stdout(output),
        ):
            result = main(["-allgamever", "-modules", "engine", "-bindir", "bin"])
        self.assertEqual(0, result)
        self.assertEqual(["hl-10210"], calls)
        self.assertIn("Skipping gamever: no requested modules found (engine)", output.getvalue())

    def test_run_all_stops_on_first_failure_without_skip_error(self):
        calls = []

        def fail_then_succeed(gamever, args, summary=None):
            del args
            calls.append(gamever)
            if gamever == "hl-10210":
                summary.failed = 1
                return 1
            summary.successful = 1
            return 0

        with (
            patch.dict(os.environ, {}, clear=True),
            patch("ida_analyze_bin.iter_analysis_config_tags", return_value=["hl-10210", "hl-8684"]),
            patch("ida_analyze_bin._run_single_tag", side_effect=fail_then_succeed),
            redirect_stdout(io.StringIO()),
        ):
            result = main(["-allgamever", "-bindir", "bin"])
        self.assertEqual(1, result)
        self.assertEqual(["hl-10210"], calls)

    def test_run_all_continues_with_skip_error(self):
        calls = []

        def fail_then_succeed(gamever, args, summary=None):
            del args
            calls.append(gamever)
            if gamever == "hl-10210":
                summary.failed = 1
                return 1
            summary.successful = 1
            return 0

        with (
            patch.dict(os.environ, {}, clear=True),
            patch("ida_analyze_bin.iter_analysis_config_tags", return_value=["hl-10210", "hl-8684"]),
            patch("ida_analyze_bin._run_single_tag", side_effect=fail_then_succeed),
            redirect_stdout(io.StringIO()),
        ):
            result = main(["-allgamever", "-bindir", "bin", "-skip_error"])
        self.assertEqual(1, result)
        self.assertEqual(["hl-10210", "hl-8684"], calls)

    def test_main_prints_configuration_and_summary(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            config = root / "config.yaml"
            config.write_text("modules: []\n", encoding="utf-8")
            output = io.StringIO()
            with patch.dict(os.environ, {}, clear=True), redirect_stdout(output):
                result = main(
                    [
                        "-gamever",
                        "game-1",
                        "-configyaml",
                        str(config),
                        "-bindir",
                        str(root / "bin"),
                    ]
                )
            self.assertEqual(0, result)
            self.assertIn(f"Config file: {config.resolve()}", output.getvalue())
            self.assertIn("Successful: 0", output.getvalue())
            self.assertIn("Failed: 0", output.getvalue())
            self.assertIn("Skipped: 0", output.getvalue())

    def test_main_returns_nonzero_when_skip_error_records_failures(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            config = root / "config.yaml"
            config.write_text("modules: []\n", encoding="utf-8")

            def record_failure(**kwargs):
                kwargs["summary"].failed = 1

            with (
                patch.dict(os.environ, {}, clear=True),
                patch("ida_analyze_bin.analyze", side_effect=record_failure),
                redirect_stdout(io.StringIO()),
            ):
                result = main(
                    [
                        "-gamever",
                        "game-1",
                        "-configyaml",
                        str(config),
                        "-bindir",
                        str(root / "bin"),
                        "-skip_error",
                    ]
                )
            self.assertEqual(1, result)


class DagTests(unittest.TestCase):
    def test_orders_artifact_and_prerequisite_dependencies(self):
        modules = module(
            [
                skill("consume", output=["c.yaml"], required_input=["a.yaml"]),
                skill("produce", output=["a.yaml"]),
                skill("finish", prerequisite=["consume"]),
            ]
        )
        plan = build_execution_plan(modules, platforms=["windows"], bin_dir="bin", tag="game-1")
        self.assertEqual(["produce", "consume", "finish"], [node.skill for node in plan.nodes])
        self.assertEqual({"artifact", "prerequisite"}, {edge.kind for edge in plan.edges})

    def test_orders_cross_module_artifact_dependencies_by_resolved_owner_path(self):
        modules = [
            {
                "stage_index": 0,
                "name": "client",
                "path_windows": "Game/client.dll",
                "module_windows": "client.dll",
                "path_linux": None,
                "skills": [skill("consume", output=["client.yaml"], required_input=["../engine/shared.yaml"])],
                "symbols": [],
            },
            {
                "stage_index": 1,
                "name": "engine",
                "path_windows": "Game/hw.dll",
                "module_windows": "hw.dll",
                "path_linux": None,
                "skills": [skill("produce", output=["shared.yaml"])],
                "symbols": [],
            },
        ]
        plan = build_execution_plan(modules, platforms=["windows"], bin_dir="bin", tag="game-1")
        self.assertEqual(["produce", "consume"], [node.skill for node in plan.nodes])
        self.assertEqual(("engine/shared.yaml",), plan.nodes[1].required_inputs)
        self.assertEqual("engine/shared.yaml", plan.edges[0].artifact)

    def test_projects_validated_dag_to_stable_process_plan(self):
        modules = [
            {
                "stage_index": 3,
                "name": "engine",
                "description": "Engine stage",
                "path_windows": "Game/hw.dll",
                "module_windows": "hw.dll",
                "path_linux": None,
                "skills": [skill("produce", output=["shared.yaml"])],
                "symbols": [],
            },
            {
                "stage_index": 7,
                "name": "client",
                "path_windows": "Game/client.dll",
                "module_windows": "client.dll",
                "path_linux": None,
                "skills": [skill("consume", output=["client.yaml"], required_input=["../engine/shared.yaml"])],
                "symbols": [],
            },
        ]
        plan = build_execution_plan(modules, platforms=["windows"], bin_dir="bin", tag="game-1")

        process_plan = build_process_execution_plan(plan, modules, platforms=["windows"], bin_dir="bin")

        self.assertEqual([3, 7], [stage.stage_index for stage in process_plan.stages])
        self.assertEqual(
            ["stage-0003-engine-windows/produce", "stage-0007-client-windows/consume"],
            [node.id for node in process_plan.nodes],
        )
        dependency = next(edge for edge in process_plan.edges if edge.artifact == "engine/shared.yaml")
        self.assertEqual("cross_stage_artifact", dependency.edge_type.value)
        self.assertEqual(plan.nodes[0].id, process_plan.nodes[0].data["planner_node_id"])

    def test_selected_node_projection_keeps_full_dag_layer_but_only_selected_tasks(self):
        modules = module(
            [
                skill("produce", output=["a.yaml"]),
                skill("consume", output=["b.yaml"], required_input=["a.yaml"]),
            ]
        )
        plan = build_execution_plan(modules, platforms=["windows"], bin_dir="bin", tag="game-1")
        selected = _select_requested_nodes(plan, ["engine:windows:consume"])
        self.assertEqual(("engine:windows:consume",), tuple(node.id for node in selected))
        projected = build_process_execution_plan(
            plan,
            modules,
            platforms=["windows"],
            bin_dir="bin",
            selected_node_ids=["engine:windows:consume"],
        )
        self.assertEqual(1, len(projected.nodes))
        self.assertEqual(1, projected.nodes[0].layer)
        self.assertFalse(
            any(edge.source.startswith("task:") and edge.target.startswith("task:") for edge in projected.edges)
        )

    def test_selected_nodes_follow_topology_and_require_unselected_inputs_to_be_materialized(self):
        modules = module(
            [
                skill("consume", output=["b.yaml"], required_input=["a.yaml"]),
                skill("produce", output=["a.yaml"]),
            ]
        )
        with tempfile.TemporaryDirectory() as temporary:
            plan = build_execution_plan(modules, platforms=["windows"], bin_dir=temporary, tag="game-1")
            selected = _select_requested_nodes(
                plan,
                ["engine:windows:consume", "engine:windows:produce"],
            )
            self.assertEqual(["produce", "consume"], [node.skill for node in selected])
            _validate_selected_inputs(plan, selected, Path(temporary) / "game-1")
            consumer = _select_requested_nodes(plan, ["engine:windows:consume"])
            with self.assertRaisesRegex(AnalysisRunError, "materialized inputs"):
                _validate_selected_inputs(plan, consumer, Path(temporary) / "game-1")
            artifact = Path(temporary) / "game-1" / "engine" / "a.yaml"
            artifact.parent.mkdir(parents=True)
            artifact.write_text("value: present\n", encoding="utf-8")
            _validate_selected_inputs(plan, consumer, Path(temporary) / "game-1")
            with self.assertRaisesRegex(AnalysisRunError, "not found"):
                _select_requested_nodes(plan, ["engine:windows:missing"])

    def test_rejects_cycle(self):
        modules = module(
            [
                skill("a", output=["a.yaml"], required_input=["b.yaml"]),
                skill("b", output=["b.yaml"], required_input=["a.yaml"]),
            ]
        )
        with self.assertRaises(AnalysisPlanError):
            build_execution_plan(modules, platforms=["windows"], bin_dir="bin", tag="game-1")

    def test_rejects_duplicate_output_and_missing_input(self):
        with self.assertRaises(AnalysisPlanError):
            build_execution_plan(
                module([skill("a", output=["A.yaml"]), skill("b", output=["a.yaml"])]),
                platforms=["windows"],
                bin_dir="bin",
                tag="game-1",
            )
        with self.assertRaises(AnalysisPlanError):
            build_execution_plan(
                module([skill("a", required_input=["missing.yaml"])]),
                platforms=["windows"],
                bin_dir="bin",
                tag="game-1",
            )

    def test_analysis_stage_order_is_contractual(self):
        self.assertEqual(("preprocessor", "agent"), ANALYSIS_STAGES)

    def test_codex_agent_command_uses_one_prompt(self):
        initial = build_agent_command("codex", "find-symbol")
        retry = build_agent_command("codex", "find-symbol", retry=True)
        self.assertEqual(["codex", "--profile", "skill_runner", "-c"], initial[:4])
        self.assertTrue(initial[4].startswith("developer_instructions="))
        self.assertEqual(["exec", "-"], initial[-2:])
        self.assertEqual(["exec", "resume", "--last", "-"], retry[-4:])

    def test_pipeline_stops_after_preprocessor_success(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "game-1"
            binary = root / "engine" / "hw.dll"
            binary.parent.mkdir(parents=True)
            binary.write_bytes(b"binary")
            node = build_execution_plan(
                module([skill("find", output=["result.yaml"])]),
                platforms=["windows"],
                bin_dir=Path(temporary),
                tag="game-1",
            ).nodes[0]
            calls = []

            def preprocessor(**kwargs):
                calls.append("preprocessor")
                Path(kwargs["expected_outputs"][0]).write_text("ok: true\n", encoding="utf-8")
                return PREPROCESS_STATUS_SUCCESS

            result = run_analysis_pipeline(
                node,
                binary_path=binary,
                game_root=root,
                old_game_root=None,
                agent="codex",
                preprocessor_runner=preprocessor,
                agent_skill_runner=lambda *_args, **_kwargs: calls.append("agent"),
            )
            self.assertEqual(PipelineResult("succeeded", "preprocessor"), result)
            self.assertEqual(["preprocessor"], calls)

    def test_skip_pp_bypasses_preprocessor_and_runs_agent(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "game-2"
            old_root = Path(temporary) / "game-1"
            binary = root / "engine" / "hw.dll"
            binary.parent.mkdir(parents=True)
            binary.write_bytes(b"\xaa\xbb\xcc")
            old_output = old_root / "engine" / "result.yaml"
            old_output.parent.mkdir(parents=True)
            old_output.write_text(
                "func_name: old\nfunc_sig: AA BB\nfunc_va: '0x10'\n",
                encoding="utf-8",
            )
            node = build_execution_plan(
                module([skill("find", output=["result.yaml"])]),
                platforms=["windows"],
                bin_dir=Path(temporary),
                tag="game-2",
            ).nodes[0]
            calls = []
            reporting = RecordingAnalysisReporting()

            def agent(_name, **kwargs):
                calls.append(("agent", kwargs["model"], kwargs["debug"]))
                kwargs["progress_callback"](
                    event="attempt_started",
                    attempt=1,
                    max_attempts=2,
                )
                Path(kwargs["expected_yaml_paths"][0]).write_text("ok: true\n", encoding="utf-8")
                kwargs["progress_callback"](
                    event="succeeded",
                    attempt=1,
                    max_attempts=2,
                )
                return True

            result = run_analysis_pipeline(
                node,
                binary_path=binary,
                game_root=root,
                old_game_root=old_root,
                agent="codex",
                agent_model="gpt-5",
                debug=True,
                skip_preprocessors=True,
                reporting=reporting,
                task_id="stage-0000-engine-windows/find",
                preprocessor_runner=lambda **_kwargs: calls.append("preprocessor"),
                agent_skill_runner=agent,
            )
            self.assertEqual(PipelineResult("succeeded", "agent"), result)
            self.assertEqual([("agent", "gpt-5", True)], calls)
            self.assertEqual("ok: true\n", (root / "engine" / "result.yaml").read_text(encoding="utf-8"))
            agent_events = [event for event in reporting.events if event["event_type"] == "skill.progress"]
            self.assertEqual(["attempt_started", "succeeded"], [event["payload"]["event"] for event in agent_events])
            self.assertEqual(1, agent_events[0]["payload"]["attempt"])

    def test_pipeline_forwards_flat_llm_and_symbol_alias_arguments(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "game-1"
            binary = root / "engine" / "hw.dll"
            binary.parent.mkdir(parents=True)
            binary.write_bytes(b"binary")
            node = build_execution_plan(
                module([skill("find", output=["result.yaml"])]),
                platforms=["windows"],
                bin_dir=Path(temporary),
                tag="game-1",
            ).nodes[0]
            seen = {}

            def preprocessor(**kwargs):
                seen.update(kwargs)
                Path(kwargs["expected_outputs"][0]).write_text("ok: true\n", encoding="utf-8")
                return PREPROCESS_STATUS_SUCCESS

            result = run_analysis_pipeline(
                node,
                binary_path=binary,
                game_root=root,
                old_game_root=None,
                agent="codex",
                llm_config={
                    "model": "test-model",
                    "api_key": "secret",
                    "base_url": "https://example.invalid/v1",
                    "temperature": 0.5,
                    "effort": "high",
                    "fake_as": None,
                    "max_retries": 9,
                },
                symbol_aliases={"Symbol": ("Alias",)},
                preprocessor_runner=preprocessor,
                agent_skill_runner=lambda *_args, **_kwargs: False,
            )
            self.assertEqual(PipelineResult("succeeded", "preprocessor"), result)
            self.assertEqual("test-model", seen["llm_model"])
            self.assertEqual("secret", seen["llm_apikey"])
            self.assertEqual(node.max_retries, seen["llm_max_retries"])
            self.assertEqual({"Symbol": ("Alias",)}, seen["symbol_aliases"])

    def test_missing_and_invalid_required_inputs_fail_before_dispatch(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "game-1"
            binary = root / "engine" / "hw.dll"
            binary.parent.mkdir(parents=True)
            binary.write_bytes(b"binary")
            node = build_execution_plan(
                module(
                    [
                        skill("produce", output=["input.yaml"]),
                        skill("consume", output=["result.yaml"], required_input=["input.yaml"]),
                    ]
                ),
                platforms=["windows"],
                bin_dir=Path(temporary),
                tag="game-1",
            ).nodes[1]
            with self.assertRaises(PipelineFailure) as missing:
                run_analysis_pipeline(
                    node,
                    binary_path=binary,
                    game_root=root,
                    old_game_root=None,
                    agent="codex",
                )
            self.assertEqual("missing_input", missing.exception.reason)

            (binary.parent / "input.yaml").write_text("- invalid\n", encoding="utf-8")
            with self.assertRaises(PipelineFailure) as invalid:
                run_analysis_pipeline(
                    node,
                    binary_path=binary,
                    game_root=root,
                    old_game_root=None,
                    agent="codex",
                )
            self.assertEqual("invalid_input", invalid.exception.reason)

    def test_preprocessor_success_requires_valid_outputs(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "game-1"
            binary = root / "engine" / "hw.dll"
            binary.parent.mkdir(parents=True)
            binary.write_bytes(b"binary")
            node = build_execution_plan(
                module([skill("find", output=["result.yaml"])]),
                platforms=["windows"],
                bin_dir=Path(temporary),
                tag="game-1",
            ).nodes[0]

            def preprocessor(**kwargs):
                Path(kwargs["expected_outputs"][0]).write_text("- invalid\n", encoding="utf-8")
                return PREPROCESS_STATUS_SUCCESS

            with self.assertRaises(PipelineFailure) as raised:
                run_analysis_pipeline(
                    node,
                    binary_path=binary,
                    game_root=root,
                    old_game_root=None,
                    agent="codex",
                    preprocessor_runner=preprocessor,
                )
            self.assertEqual("preprocess_contract_violation", raised.exception.reason)

    def test_absent_ok_skips_even_when_preprocessor_writes_output(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "game-1"
            binary = root / "engine" / "hw.dll"
            binary.parent.mkdir(parents=True)
            binary.write_bytes(b"binary")
            node = build_execution_plan(
                module([skill("find", output=["result.yaml"])]),
                platforms=["windows"],
                bin_dir=Path(temporary),
                tag="game-1",
            ).nodes[0]
            agent = MagicMock()

            def preprocessor(**kwargs):
                Path(kwargs["expected_outputs"][0]).write_text("preserved: true\n", encoding="utf-8")
                return PREPROCESS_STATUS_ABSENT_OK

            result = run_analysis_pipeline(
                node,
                binary_path=binary,
                game_root=root,
                old_game_root=None,
                agent="codex",
                preprocessor_runner=preprocessor,
                agent_skill_runner=agent,
            )
            self.assertEqual(PipelineResult("skipped", "preprocessor", "preprocess_absent"), result)
            agent.assert_not_called()
            self.assertTrue((binary.parent / "result.yaml").is_file())

    def test_failed_preprocessor_output_is_preserved_until_agent_runs(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "game-1"
            binary = root / "engine" / "hw.dll"
            binary.parent.mkdir(parents=True)
            binary.write_bytes(b"binary")
            node = build_execution_plan(
                module([skill("find", output=["result.yaml"])]),
                platforms=["windows"],
                bin_dir=Path(temporary),
                tag="game-1",
            ).nodes[0]
            observed = {}

            def preprocessor(**kwargs):
                Path(kwargs["expected_outputs"][0]).write_text("source: preprocessor\n", encoding="utf-8")
                return PREPROCESS_STATUS_FAILED

            def agent(_name, **kwargs):
                output = Path(kwargs["expected_yaml_paths"][0])
                observed["before_agent"] = output.read_text(encoding="utf-8")
                output.write_text("source: agent\n", encoding="utf-8")
                return True

            result = run_analysis_pipeline(
                node,
                binary_path=binary,
                game_root=root,
                old_game_root=None,
                agent="codex",
                preprocessor_runner=preprocessor,
                agent_skill_runner=agent,
            )
            self.assertEqual(PipelineResult("succeeded", "agent"), result)
            self.assertEqual("source: preprocessor\n", observed["before_agent"])

    def test_runner_exception_is_diagnosed_and_falls_back_to_agent(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "game-1"
            binary = root / "engine" / "hw.dll"
            binary.parent.mkdir(parents=True)
            binary.write_bytes(b"binary")
            node = build_execution_plan(
                module([skill("find", output=["result.yaml"])]),
                platforms=["windows"],
                bin_dir=Path(temporary),
                tag="game-1",
            ).nodes[0]
            reporting = RecordingAnalysisReporting()
            agent = MagicMock(return_value=True)

            def preprocessor(**_kwargs):
                raise RuntimeError("runner dispatch failed")

            def write_agent_output(*args, **kwargs):
                Path(kwargs["expected_yaml_paths"][0]).write_text("source: agent\n", encoding="utf-8")
                return agent(*args, **kwargs)

            stderr = io.StringIO()
            with redirect_stderr(stderr):
                result = run_analysis_pipeline(
                    node,
                    binary_path=binary,
                    game_root=root,
                    old_game_root=None,
                    agent="codex",
                    reporting=reporting,
                    task_id="stage-0000-engine-windows/find",
                    preprocessor_runner=preprocessor,
                    agent_skill_runner=write_agent_output,
                )

            self.assertEqual(PipelineResult("succeeded", "agent"), result)
            agent.assert_called_once()
            diagnostic_events = [
                event
                for event in reporting.events
                if event["event_type"] == "skill.progress"
                and event["payload"].get("event") == "preprocessor_diagnostic"
            ]
            self.assertEqual(1, len(diagnostic_events))
            self.assertEqual("runner_failed", diagnostic_events[0]["payload"]["reason"])
            self.assertEqual("RuntimeError", diagnostic_events[0]["payload"]["exception_type"])
            self.assertEqual("runner dispatch failed", diagnostic_events[0]["payload"]["message"])
            self.assertIn("runner dispatch failed", stderr.getvalue())
            self.assertNotIn("Traceback", stderr.getvalue())

    def test_optional_only_normal_mode_skips_after_failed_or_missing_preprocessor(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "game-1"
            binary = root / "engine" / "hw.dll"
            binary.parent.mkdir(parents=True)
            binary.write_bytes(b"binary")
            node = build_execution_plan(
                module([skill("optional", optional_output=["optional.yaml"])]),
                platforms=["windows"],
                bin_dir=Path(temporary),
                tag="game-1",
            ).nodes[0]
            agent = MagicMock()
            for status in (PREPROCESS_STATUS_FAILED, PREPROCESS_STATUS_NO_SCRIPT):
                with self.subTest(status=status):
                    result = run_analysis_pipeline(
                        node,
                        binary_path=binary,
                        game_root=root,
                        old_game_root=None,
                        agent="codex",
                        preprocessor_runner=lambda status=status, **_kwargs: status,
                        agent_skill_runner=agent,
                    )
                    self.assertEqual(
                        PipelineResult("skipped", "preprocessor", "optional_output_absent"),
                        result,
                    )
            agent.assert_not_called()

    def test_skip_pp_optional_only_runs_agent_and_skips_without_output(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "game-1"
            binary = root / "engine" / "hw.dll"
            binary.parent.mkdir(parents=True)
            binary.write_bytes(b"binary")
            node = build_execution_plan(
                module([skill("optional", optional_output=["optional.yaml"])]),
                platforms=["windows"],
                bin_dir=Path(temporary),
                tag="game-1",
            ).nodes[0]
            agent = MagicMock(return_value=True)
            result = run_analysis_pipeline(
                node,
                binary_path=binary,
                game_root=root,
                old_game_root=None,
                agent="codex",
                skip_preprocessors=True,
                agent_skill_runner=agent,
            )
            self.assertEqual(PipelineResult("skipped", "agent", "optional_output_absent"), result)
            agent.assert_called_once()

    def test_zero_output_skill_uses_cs2_agent_semantics(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "game-1"
            binary = root / "engine" / "hw.dll"
            binary.parent.mkdir(parents=True)
            binary.write_bytes(b"binary")
            node = build_execution_plan(
                module([skill("zero")]),
                platforms=["windows"],
                bin_dir=Path(temporary),
                tag="game-1",
            ).nodes[0]
            result = run_analysis_pipeline(
                node,
                binary_path=binary,
                game_root=root,
                old_game_root=None,
                agent="codex",
                preprocessor_runner=lambda **_kwargs: PREPROCESS_STATUS_NO_SCRIPT,
                agent_skill_runner=lambda *_args, **_kwargs: True,
            )
            self.assertEqual(PipelineResult("succeeded", "agent"), result)

    def test_agent_output_uses_same_validator(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "game-1"
            binary = root / "engine" / "hw.dll"
            binary.parent.mkdir(parents=True)
            binary.write_bytes(b"binary")
            node = build_execution_plan(
                module([skill("find", output=["result.yaml"])]),
                platforms=["windows"],
                bin_dir=Path(temporary),
                tag="game-1",
            ).nodes[0]

            def agent(_name, **kwargs):
                Path(kwargs["expected_yaml_paths"][0]).write_text("- invalid\n", encoding="utf-8")
                return True

            with self.assertRaises(PipelineFailure) as raised:
                run_analysis_pipeline(
                    node,
                    binary_path=binary,
                    game_root=root,
                    old_game_root=None,
                    agent="codex",
                    skip_preprocessors=True,
                    agent_skill_runner=agent,
                )
            self.assertEqual("agent_output_invalid", raised.exception.reason)

    def test_mcp_readiness_is_recovered_before_agent(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "game-1"
            binary = root / "engine" / "hw.dll"
            binary.parent.mkdir(parents=True)
            binary.write_bytes(b"binary")
            node = build_execution_plan(
                module([skill("find", output=["result.yaml"])]),
                platforms=["windows"],
                bin_dir=Path(temporary),
                tag="game-1",
            ).nodes[0]
            recovered_runtime = McpRuntime(
                DEFAULT_HOST,
                DEFAULT_PORT,
                str(binary),
                McpDatabaseBinding(True, "recovered-db", str(binary), "worker", True, True),
            )
            ensure_ready = MagicMock(return_value=recovered_runtime)

            def agent(_name, **kwargs):
                Path(kwargs["expected_yaml_paths"][0]).write_text("ok: true\n", encoding="utf-8")
                return True

            result = run_analysis_pipeline(
                node,
                binary_path=binary,
                game_root=root,
                old_game_root=None,
                agent="codex",
                preprocessor_runner=lambda **_kwargs: PREPROCESS_STATUS_NO_SCRIPT,
                ensure_mcp_ready=ensure_ready,
                agent_skill_runner=agent,
            )
            self.assertEqual(PipelineResult("succeeded", "agent"), result)
            ensure_ready.assert_called_once_with()

    def test_skip_error_continues_but_records_failure(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            config = root / "config.yaml"
            config.write_text(
                """modules:
  - name: engine
    path_windows: Game/hw.dll
    module_windows: hw.dll
    skills:
      - name: first
      - name: second
""",
                encoding="utf-8",
            )
            write_pe32(root / "bin" / "game-1" / "engine" / "hw.dll")
            summary = AnalysisSummary()
            lifecycle = MagicMock()
            lifecycle.__enter__.return_value = lifecycle
            lifecycle.runtime = McpRuntime(
                DEFAULT_HOST,
                DEFAULT_PORT,
                "hw.dll",
                McpDatabaseBinding(False, None, "hw.dll", "worker", True, True),
            )
            with (
                patch("ida_analyze_bin.IdaMcpLifecycle", return_value=lifecycle),
                patch(
                    "ida_analyze_bin.run_analysis_pipeline",
                    side_effect=[AnalysisRunError("first failed"), PipelineResult("succeeded", "agent")],
                ) as pipeline,
            ):
                analyze(
                    gamever="game-1",
                    config_path=config,
                    bindir=root / "bin",
                    platforms=["windows"],
                    skip_error=True,
                    summary=summary,
                )
            self.assertEqual(2, pipeline.call_count)
            self.assertEqual((1, 1, 0), (summary.successful, summary.failed, summary.skipped))

    def test_fail_fast_stops_after_first_runtime_failure(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            config = root / "config.yaml"
            config.write_text(
                """modules:
  - name: engine
    path_windows: Game/hw.dll
    module_windows: hw.dll
    skills:
      - name: first
      - name: second
""",
                encoding="utf-8",
            )
            write_pe32(root / "bin" / "game-1" / "engine" / "hw.dll")
            summary = AnalysisSummary()
            lifecycle = MagicMock()
            lifecycle.__enter__.return_value = lifecycle
            lifecycle.runtime = McpRuntime(
                DEFAULT_HOST,
                DEFAULT_PORT,
                "hw.dll",
                McpDatabaseBinding(False, None, "hw.dll", "worker", True, True),
            )
            with (
                patch("ida_analyze_bin.IdaMcpLifecycle", return_value=lifecycle),
                patch(
                    "ida_analyze_bin.run_analysis_pipeline",
                    side_effect=AnalysisRunError("first failed"),
                ) as pipeline,
                self.assertRaises(AnalysisRunError),
            ):
                analyze(
                    gamever="game-1",
                    config_path=config,
                    bindir=root / "bin",
                    platforms=["windows"],
                    summary=summary,
                )
            self.assertEqual(1, pipeline.call_count)
            self.assertEqual((0, 1, 0), (summary.successful, summary.failed, summary.skipped))

    def test_unknown_module_is_an_explicit_error(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            config = root / "config.yaml"
            config.write_text(
                """modules:
  - name: engine
    path_windows: Game/hw.dll
    module_windows: hw.dll
    skills: []
""",
                encoding="utf-8",
            )
            reporter = RecordingProcessReporter()
            with self.assertRaisesRegex(AnalysisRunError, "Module.*missing"):
                analyze(
                    gamever="game-1",
                    config_path=config,
                    bindir=root / "bin",
                    platforms=["windows"],
                    modules_filter=["missing"],
                    reporter=reporter,
                    run_id="invalid-plan-run",
                )
            self.assertEqual([], reporter.plan["nodes"])
            self.assertEqual(["graph_invalid"], reporter.plan["warnings"])
            self.assertEqual(("invalid-plan-run", RunStatus.FAILED), reporter.finalized[:2])
            self.assertTrue(reporter.flushed)
            self.assertTrue(reporter.closed)

    def test_analyzer_reports_stable_lifecycle_for_existing_outputs(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            config = root / "config.yaml"
            config.write_text(
                """modules:
  - name: engine
    path_windows: Game/hw.dll
    module_windows: hw.dll
    skills:
      - name: find
        expected_output: result.yaml
""",
                encoding="utf-8",
            )
            write_pe32(root / "bin" / "game-1" / "engine" / "hw.dll")
            output = root / "bin" / "game-1" / "engine" / "result.yaml"
            output.write_text("ok: true\n", encoding="utf-8")
            reporter = RecordingProcessReporter()
            summary = AnalysisSummary()

            analyze(
                gamever="game-1",
                config_path=config,
                bindir=root / "bin",
                platforms=["windows"],
                reporter=reporter,
                run_id="scheduled-run",
                summary=summary,
            )

            task_id = "stage-0000-engine-windows/find"
            task_events = [event for event in reporter.events if event.task_id == task_id]
            self.assertEqual(["skipped"], [event.status.value for event in task_events])
            self.assertEqual("existing_outputs", task_events[0].reason.value)
            self.assertEqual(task_id, reporter.plan["nodes"][0]["id"])
            self.assertEqual(("scheduled-run", RunStatus.SUCCEEDED), reporter.finalized[:2])
            self.assertEqual(1, reporter.finalized[2]["skipped"])
            self.assertTrue(reporter.flushed)
            self.assertTrue(reporter.closed)

    def test_binary_failure_aborts_tasks_and_finalizes_failed_run(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            config = root / "config.yaml"
            config.write_text(
                """modules:
  - name: engine
    path_windows: Game/hw.dll
    module_windows: hw.dll
    skills:
      - name: find
        expected_output: result.yaml
""",
                encoding="utf-8",
            )
            reporter = RecordingProcessReporter()
            summary = AnalysisSummary()

            analyze(
                gamever="game-1",
                config_path=config,
                bindir=root / "bin",
                platforms=["windows"],
                skip_error=True,
                reporter=reporter,
                summary=summary,
            )

            task = next(event for event in reporter.events if event.task_id == "stage-0000-engine-windows/find")
            self.assertEqual("aborted", task.status.value)
            self.assertEqual("missing_binary", task.reason.value)
            self.assertEqual(RunStatus.FAILED, reporter.finalized[1])
            self.assertEqual(1, summary.failed)


class McpLifecycleTests(unittest.TestCase):
    def test_runtime_binding_is_forwarded_to_preprocessor(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "game-1"
            binary = root / "engine" / "hw.dll"
            binary.parent.mkdir(parents=True)
            binary.write_bytes(b"binary")
            node = build_execution_plan(
                module([skill("find", output=["result.yaml"])]),
                platforms=["windows"],
                bin_dir=Path(temporary),
                tag="game-1",
            ).nodes[0]
            runtime = McpRuntime(
                DEFAULT_HOST,
                DEFAULT_PORT,
                str(binary),
                McpDatabaseBinding(True, "server-db", str(binary), "worker", True, True),
            )
            seen = {}

            def preprocessor(**kwargs):
                seen.update(kwargs)
                Path(kwargs["expected_outputs"][0]).write_text("ok: true\n", encoding="utf-8")
                return PREPROCESS_STATUS_SUCCESS

            self.assertEqual(
                PipelineResult("succeeded", "preprocessor"),
                run_analysis_pipeline(
                    node,
                    binary_path=binary,
                    game_root=root,
                    old_game_root=None,
                    agent="codex",
                    mcp_runtime=runtime,
                    preprocessor_runner=preprocessor,
                ),
            )
            self.assertEqual(DEFAULT_HOST, seen["host"])
            self.assertEqual(DEFAULT_PORT, seen["port"])
            self.assertEqual("server-db", seen["explicit_database"])
            self.assertEqual(str(binary.resolve()), seen["expected_binary"])

    def test_all_existing_outputs_skip_ida_startup(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            config = root / "config.yaml"
            config.write_text(
                """modules:
  - name: engine
    path_windows: Game/hw.dll
    module_windows: hw.dll
    skills:
      - name: first
        expected_output: [result.yaml]
""",
                encoding="utf-8",
            )
            module_root = root / "bin" / "game-1" / "engine"
            write_pe32(module_root / "hw.dll")
            (module_root / "result.yaml").write_text("not: [valid\n", encoding="utf-8")
            summary = AnalysisSummary()
            with patch("ida_analyze_bin.IdaMcpLifecycle", side_effect=AssertionError("must not start")):
                analyze(
                    gamever="game-1",
                    config_path=config,
                    bindir=root / "bin",
                    platforms=["windows"],
                    summary=summary,
                )
            self.assertEqual((0, 0, 1), (summary.successful, summary.failed, summary.skipped))

    def test_analyze_owns_one_lifecycle_per_binary(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            config = root / "config.yaml"
            config.write_text(
                """modules:
  - name: engine
    path_windows: Game/hw.dll
    module_windows: hw.dll
    symbols:
      - name: TestSymbol
        category: func
        alias: [TestAlias]
    skills:
      - name: first
      - name: second
""",
                encoding="utf-8",
            )
            binary = root / "bin" / "game-1" / "engine" / "hw.dll"
            write_pe32(binary)
            runtime = McpRuntime(
                DEFAULT_HOST,
                DEFAULT_PORT,
                str(binary),
                McpDatabaseBinding(False, None, str(binary), "worker", True, True),
            )
            lifecycle = MagicMock()
            lifecycle.__enter__.return_value = lifecycle
            lifecycle.runtime = runtime
            lifecycle.ensure_ready.return_value = runtime
            summary = AnalysisSummary()
            with (
                patch("ida_analyze_bin.IdaMcpLifecycle", return_value=lifecycle) as lifecycle_type,
                patch(
                    "ida_analyze_bin.run_analysis_pipeline",
                    side_effect=[PipelineResult("succeeded", "agent"), PipelineResult("succeeded", "agent")],
                ) as pipeline,
            ):
                analyze(
                    gamever="game-1",
                    config_path=config,
                    bindir=root / "bin",
                    platforms=["windows"],
                    ida_args="quiet",
                    summary=summary,
                )
            lifecycle_type.assert_called_once_with(binary, "windows", DEFAULT_HOST, DEFAULT_PORT, "quiet", False)
            lifecycle.ensure_ready.assert_called_once_with()
            self.assertIs(runtime, pipeline.call_args_list[0].kwargs["mcp_runtime"])
            self.assertIs(runtime, pipeline.call_args_list[1].kwargs["mcp_runtime"])
            self.assertIs(lifecycle.ensure_ready, pipeline.call_args_list[0].kwargs["ensure_mcp_ready"])
            self.assertEqual(
                {"TestSymbol": ("TestAlias",)},
                pipeline.call_args_list[0].kwargs["symbol_aliases"],
            )
            self.assertIn(
                os.path.normcase(str((binary.parent / "TestSymbol.windows.yaml").resolve())),
                pipeline.call_args_list[0].kwargs["artifact_types"],
            )
            self.assertEqual((2, 0, 0), (summary.successful, summary.failed, summary.skipped))

    def test_selected_node_forces_existing_output_and_ignores_unselected_binary(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            config = root / "config.yaml"
            config.write_text(
                """modules:
  - name: engine
    path_windows: Game/hw.dll
    module_windows: hw.dll
    skills:
      - name: selected
        expected_output: result.yaml
  - name: client
    path_windows: Game/client.dll
    module_windows: client.dll
    skills:
      - name: unselected
        expected_output: client.yaml
""",
                encoding="utf-8",
            )
            binary = root / "bin" / "game-1" / "engine" / "hw.dll"
            write_pe32(binary)
            output = binary.parent / "result.yaml"
            output.write_text("value: existing\n", encoding="utf-8")
            lifecycle = MagicMock()
            lifecycle.__enter__.return_value = lifecycle
            lifecycle.runtime = McpRuntime(
                DEFAULT_HOST,
                DEFAULT_PORT,
                str(binary),
                McpDatabaseBinding(False, None, str(binary), "worker", True, True),
            )
            lifecycle.ensure_ready.return_value = lifecycle.runtime
            reporter = RecordingProcessReporter()
            summary = AnalysisSummary()

            with (
                patch("ida_analyze_bin.IdaMcpLifecycle", return_value=lifecycle) as lifecycle_type,
                patch(
                    "ida_analyze_bin.run_analysis_pipeline", return_value=PipelineResult("succeeded", "agent")
                ) as pipeline,
            ):
                analyze(
                    gamever="game-1",
                    config_path=config,
                    bindir=root / "bin",
                    platforms=["windows"],
                    selected_node_ids=["engine:windows:selected"],
                    reporter=reporter,
                    summary=summary,
                )

            lifecycle_type.assert_called_once()
            self.assertTrue(pipeline.call_args.kwargs["force_execution"])
            self.assertEqual(["selected"], [node["name"] for node in reporter.plan["nodes"]])
            self.assertEqual((1, 0, 0), (summary.successful, summary.failed, summary.skipped))

    def test_selected_node_jobs_track_failures_per_binary(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            config = root / "config.yaml"
            config.write_text(
                """modules:
  - name: engine
    path_windows: Game/hw.dll
    module_windows: hw.dll
    skills:
      - name: fails
        expected_output: engine.yaml
  - name: client
    path_windows: Game/client.dll
    module_windows: client.dll
    skills:
      - name: succeeds
        expected_output: client.yaml
""",
                encoding="utf-8",
            )
            engine_binary = root / "bin" / "game-1" / "engine" / "hw.dll"
            client_binary = root / "bin" / "game-1" / "client" / "client.dll"
            write_pe32(engine_binary)
            write_pe32(client_binary)
            lifecycles = []
            for binary in (engine_binary, client_binary):
                lifecycle = MagicMock()
                lifecycle.__enter__.return_value = lifecycle
                lifecycle.runtime = McpRuntime(
                    DEFAULT_HOST,
                    DEFAULT_PORT,
                    str(binary),
                    McpDatabaseBinding(False, None, str(binary), "worker", True, True),
                )
                lifecycle.ensure_ready.return_value = lifecycle.runtime
                lifecycles.append(lifecycle)
            reporter = RecordingProcessReporter()
            summary = AnalysisSummary()

            with (
                patch("ida_analyze_bin.IdaMcpLifecycle", side_effect=lifecycles),
                patch(
                    "ida_analyze_bin.run_analysis_pipeline",
                    side_effect=[PipelineFailure("test_failure", "expected"), PipelineResult("succeeded", "agent")],
                ),
            ):
                analyze(
                    gamever="game-1",
                    config_path=config,
                    bindir=root / "bin",
                    platforms=["windows"],
                    selected_node_ids=["engine:windows:fails", "client:windows:succeeds"],
                    skip_error=True,
                    reporter=reporter,
                    summary=summary,
                )

            job_ids = {job["module_name"]: job["id"] for job in reporter.plan["jobs"]}
            terminal_statuses = {
                event.task_id: event.status
                for event in reporter.events
                if event.task_id in job_ids.values() and event.status in {TaskStatus.SUCCEEDED, TaskStatus.FAILED}
            }
            self.assertEqual(TaskStatus.FAILED, terminal_statuses[job_ids["engine"]])
            self.assertEqual(TaskStatus.SUCCEEDED, terminal_statuses[job_ids["client"]])
            self.assertEqual((1, 1, 0), (summary.successful, summary.failed, summary.skipped))

    def test_selected_node_lifecycle_failure_only_aborts_remaining_nodes(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            config = root / "config.yaml"
            config.write_text(
                """modules:
  - name: engine
    path_windows: Game/hw.dll
    module_windows: hw.dll
    skills:
      - name: first
        expected_output: first.yaml
      - name: second
        expected_output: second.yaml
""",
                encoding="utf-8",
            )
            binary = root / "bin" / "game-1" / "engine" / "hw.dll"
            write_pe32(binary)
            lifecycle = MagicMock()
            lifecycle.__enter__.return_value = lifecycle
            lifecycle.runtime = McpRuntime(
                DEFAULT_HOST,
                DEFAULT_PORT,
                str(binary),
                McpDatabaseBinding(False, None, str(binary), "worker", True, True),
            )
            lifecycle.ensure_ready.side_effect = McpLifecycleError("worker stopped")
            reporter = RecordingProcessReporter()
            summary = AnalysisSummary()

            with (
                patch("ida_analyze_bin.IdaMcpLifecycle", return_value=lifecycle),
                patch("ida_analyze_bin.run_analysis_pipeline", return_value=PipelineResult("succeeded", "agent")),
            ):
                analyze(
                    gamever="game-1",
                    config_path=config,
                    bindir=root / "bin",
                    platforms=["windows"],
                    selected_node_ids=["engine:windows:first", "engine:windows:second"],
                    skip_error=True,
                    reporter=reporter,
                    summary=summary,
                )

            task_ids = {node["name"]: node["id"] for node in reporter.plan["nodes"]}
            terminal_statuses = {
                event.task_id: event.status
                for event in reporter.events
                if event.task_id in task_ids.values()
                and event.status in {TaskStatus.SUCCEEDED, TaskStatus.FAILED, TaskStatus.ABORTED}
            }
            self.assertEqual(TaskStatus.SUCCEEDED, terminal_statuses[task_ids["first"]])
            self.assertEqual(TaskStatus.ABORTED, terminal_statuses[task_ids["second"]])
            self.assertEqual((1, 1, 0), (summary.successful, summary.failed, summary.skipped))

    def test_analyze_decrypts_blob_binary_before_analysis(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            config = root / "config.yaml"
            config.write_text(
                """modules:
  - name: engine
    path_windows: Game/hw.dll
    module_windows: hw.dll
    skills:
      - name: find
        expected_output: [result.yaml]
""",
                encoding="utf-8",
            )
            binary = root / "bin" / "game-1" / "engine" / "hw.dll"
            binary.parent.mkdir(parents=True)
            binary.write_bytes(make_blob())
            lifecycle = MagicMock()
            lifecycle.__enter__.return_value = lifecycle
            lifecycle.runtime = McpRuntime(
                DEFAULT_HOST,
                DEFAULT_PORT,
                str(binary),
                McpDatabaseBinding(False, None, str(binary), "worker", True, True),
            )
            lifecycle.ensure_ready.return_value = lifecycle.runtime

            def record_binary(_node, **kwargs):
                Path(kwargs["binary_path"]).parent.joinpath("result.yaml").write_text("ok: true\n", encoding="utf-8")
                return PipelineResult("succeeded", "agent")

            summary = AnalysisSummary()
            with (
                patch("ida_analyze_bin.IdaMcpLifecycle", return_value=lifecycle) as lifecycle_type,
                patch("ida_analyze_bin.run_analysis_pipeline", side_effect=record_binary) as pipeline,
            ):
                analyze(
                    gamever="game-1",
                    config_path=config,
                    bindir=root / "bin",
                    platforms=["windows"],
                    summary=summary,
                )

            lifecycle_binary = lifecycle_type.call_args.args[0]
            self.assertEqual("hw.decrypt.dll", Path(lifecycle_binary).name)
            self.assertTrue(Path(lifecycle_binary).is_file())
            self.assertEqual("hw.decrypt.dll", Path(pipeline.call_args.kwargs["binary_path"]).name)
            self.assertEqual((1, 0, 0), (summary.successful, summary.failed, summary.skipped))

    def test_analyze_allows_binary_mutation_during_skill_execution(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            config = root / "config.yaml"
            config.write_text(
                """modules:
  - name: engine
    path_windows: Game/hw.dll
    module_windows: hw.dll
    skills:
      - name: mutate
""",
                encoding="utf-8",
            )
            binary = root / "bin" / "game-1" / "engine" / "hw.dll"
            write_pe32(binary)
            runtime = McpRuntime(
                DEFAULT_HOST,
                DEFAULT_PORT,
                str(binary),
                McpDatabaseBinding(False, None, str(binary), "worker", True, True),
            )
            lifecycle = MagicMock()
            lifecycle.__enter__.return_value = lifecycle
            lifecycle.runtime = runtime
            lifecycle.ensure_ready.return_value = runtime

            def mutate_binary(_node, **kwargs):
                Path(kwargs["binary_path"]).write_bytes(b"mutated")
                return PipelineResult("succeeded", "agent")

            summary = AnalysisSummary()
            with (
                patch("ida_analyze_bin.IdaMcpLifecycle", return_value=lifecycle),
                patch("ida_analyze_bin.run_analysis_pipeline", side_effect=mutate_binary),
            ):
                analyze(
                    gamever="game-1",
                    config_path=config,
                    bindir=root / "bin",
                    platforms=["windows"],
                    summary=summary,
                )
            self.assertEqual((1, 0, 0), (summary.successful, summary.failed, summary.skipped))

    def test_id0_lock_fails_before_process_start(self):
        with tempfile.TemporaryDirectory() as temporary:
            binary = Path(temporary) / "hw.dll"
            binary.write_bytes(b"binary")
            stale_idb = Path(f"{binary}.i64")
            stale_idb.write_bytes(b"stale")
            lock_file = Path(f"{binary}.id0")
            lock_file.write_bytes(b"lock")
            with (
                patch("ida_analyze_bin.start_idalib_mcp") as start,
                self.assertRaisesRegex(McpLifecycleError, "IDB lock file detected"),
            ):
                IdaMcpLifecycle(binary, "windows", DEFAULT_HOST, DEFAULT_PORT, "").__enter__()
            start.assert_not_called()
            self.assertTrue(stale_idb.is_file())
            self.assertTrue(lock_file.is_file())

    def test_invalidation_refuses_to_remove_an_active_id0_database(self):
        with tempfile.TemporaryDirectory() as temporary:
            binary = Path(temporary) / "hw.dll"
            binary.write_bytes(b"binary")
            stale_idb = Path(f"{binary}.i64")
            stale_idb.write_bytes(b"stale")
            lock_file = Path(f"{binary}.id0")
            lock_file.write_bytes(b"lock")

            with self.assertRaisesRegex(McpLifecycleError, "IDB lock file detected"):
                _invalidate_ida_database(binary)

            self.assertTrue(stale_idb.is_file())
            self.assertTrue(lock_file.is_file())

    def test_survey_path_merge_preserves_original_idb_input_sha256(self):
        self.assertIn("ida_nalt.retrieve_input_file_sha256()", SURVEY_CURRENT_IDB_PATH_PY_EVAL)
        merged = _merge_survey_path(
            {"metadata": {"sha256": "unavailable"}},
            {"metadata": {"path": "hw.dll.i64", "input_sha256": " ABCDEF "}},
        )
        self.assertEqual("hw.dll.i64", merged["metadata"]["path"])
        self.assertEqual("ABCDEF", merged["metadata"]["input_sha256"])

    def test_lifecycle_rebuilds_a_stale_idb_once(self):
        first_process = MagicMock()
        first_process.poll.return_value = None
        rebuilt_process = MagicMock()
        rebuilt_process.poll.return_value = None
        binding = McpDatabaseBinding(False, None, "hw.dll", "worker", True, True)

        with tempfile.TemporaryDirectory() as temporary:
            binary = Path(temporary) / "hw.dll"
            binary.write_bytes(b"binary")
            stale_files = [
                Path(f"{binary}.i64"),
                Path(f"{binary}.id1"),
                Path(f"{binary}.i64.nam"),
            ]
            for path in stale_files:
                path.write_bytes(b"stale")
            runtime = McpRuntime(DEFAULT_HOST, DEFAULT_PORT, str(binary), binding)

            with (
                patch("ida_analyze_bin.start_idalib_mcp", side_effect=[first_process, rebuilt_process]) as start,
                patch(
                    "ida_analyze_bin.verify_owned_mcp_with_single_recovery",
                    side_effect=[(first_process, None), (rebuilt_process, runtime)],
                ) as verify,
                patch("ida_analyze_bin.stop_idalib_mcp_process") as stop,
                patch("ida_analyze_bin.wait_for_port_release", return_value=True) as wait_for_release,
                patch("ida_analyze_bin.save_ida_database") as save_database,
                patch("ida_analyze_bin.quit_ida_gracefully") as quit_gracefully,
                IdaMcpLifecycle(binary, "windows", DEFAULT_HOST, DEFAULT_PORT, "") as lifecycle,
            ):
                self.assertIs(runtime, lifecycle.runtime)
                self.assertEqual(0, lifecycle.recovery_budget.remaining_restarts)

            self.assertEqual(2, start.call_count)
            self.assertEqual(2, verify.call_count)
            stop.assert_called_once_with(first_process, debug=False)
            save_database.assert_called_once_with(
                DEFAULT_HOST,
                DEFAULT_PORT,
                expected_binary=binary,
                debug=False,
            )
            self.assertEqual(
                [(DEFAULT_HOST, DEFAULT_PORT), (DEFAULT_HOST, DEFAULT_PORT)],
                [call.args for call in wait_for_release.call_args_list],
            )
            quit_gracefully.assert_called_once_with(
                rebuilt_process,
                DEFAULT_HOST,
                DEFAULT_PORT,
                expected_binary=binary,
                debug=False,
            )
            self.assertTrue(all(not path.exists() for path in stale_files))

    def test_lifecycle_preserves_stale_idb_when_port_does_not_release(self):
        process = MagicMock()
        process.poll.return_value = None
        with tempfile.TemporaryDirectory() as temporary:
            binary = Path(temporary) / "hw.dll"
            binary.write_bytes(b"binary")
            stale_idb = Path(f"{binary}.i64")
            stale_idb.write_bytes(b"stale")

            with (
                patch("ida_analyze_bin.start_idalib_mcp", return_value=process) as start,
                patch("ida_analyze_bin.verify_owned_mcp_with_single_recovery", return_value=(process, None)),
                patch("ida_analyze_bin.stop_idalib_mcp_process") as stop,
                patch("ida_analyze_bin.wait_for_port_release", return_value=False),
                self.assertRaisesRegex(McpLifecycleError, "remained in use before IDB rebuild"),
            ):
                IdaMcpLifecycle(binary, "windows", DEFAULT_HOST, DEFAULT_PORT, "").__enter__()

            start.assert_called_once()
            stop.assert_called_once_with(process, debug=False)
            self.assertTrue(stale_idb.is_file())

    def test_lifecycle_ensure_ready_rebuilds_a_stale_idb_once(self):
        first_process = MagicMock()
        first_process.poll.return_value = None
        rebuilt_process = MagicMock()
        rebuilt_process.poll.return_value = None
        with tempfile.TemporaryDirectory() as temporary:
            binary = Path(temporary) / "hw.dll"
            binary.write_bytes(b"binary")
            stale_idb = Path(f"{binary}.i64")
            stale_idb.write_bytes(b"stale")
            binding = McpDatabaseBinding(False, None, str(binary), "worker", True, True)
            runtime = McpRuntime(DEFAULT_HOST, DEFAULT_PORT, str(binary), binding)
            lifecycle = IdaMcpLifecycle(binary, "windows", DEFAULT_HOST, DEFAULT_PORT, "")
            lifecycle.process = first_process

            with (
                patch("ida_analyze_bin.ensure_mcp_available", return_value=(first_process, True)),
                patch(
                    "ida_analyze_bin.verify_owned_mcp_with_single_recovery",
                    side_effect=[(first_process, None), (rebuilt_process, runtime)],
                ) as verify,
                patch("ida_analyze_bin.stop_idalib_mcp_process") as stop,
                patch("ida_analyze_bin.wait_for_port_release", return_value=True),
                patch("ida_analyze_bin.start_idalib_mcp", return_value=rebuilt_process) as start,
            ):
                self.assertIs(runtime, lifecycle.ensure_ready())

            self.assertEqual(2, verify.call_count)
            stop.assert_called_once_with(first_process, debug=False)
            start.assert_called_once_with(binary, DEFAULT_HOST, DEFAULT_PORT, "", False)
            self.assertFalse(stale_idb.exists())

    def test_start_builds_argument_vector_and_requires_readiness(self):
        process = MagicMock()
        process.poll.return_value = None
        with (
            patch("ida_analyze_bin.is_port_in_use", return_value=False),
            patch("ida_analyze_bin.subprocess.Popen", return_value=process) as popen,
            patch("ida_analyze_bin.wait_for_mcp_ready", return_value=True) as ready,
        ):
            result = start_idalib_mcp("hw.dll", DEFAULT_HOST, DEFAULT_PORT, "batch quiet")
        self.assertIs(process, result)
        self.assertEqual(
            [
                "idalib-mcp",
                "--unsafe",
                "--host",
                DEFAULT_HOST,
                "--port",
                str(DEFAULT_PORT),
                "batch",
                "quiet",
                "hw.dll",
            ],
            popen.call_args.args[0],
        )
        ready.assert_called_once_with(process, DEFAULT_HOST, DEFAULT_PORT)

    def test_opened_binary_identity_uses_hash_and_platform_metadata(self):
        with tempfile.TemporaryDirectory() as temporary:
            binary = Path(temporary) / "hw.dll"
            binary.write_bytes(b"binary")
            sha256 = hashlib.sha256(b"binary").hexdigest()
            ok, reasons = validate_opened_binary_identity(
                binary,
                "windows",
                {"metadata": {"sha256": sha256, "arch": "32", "format": "PE"}},
            )
            self.assertTrue(ok, reasons)
            ok, reasons = validate_opened_binary_identity(
                binary,
                "linux",
                {"metadata": {"sha256": sha256, "arch": "32", "format": "PE"}},
            )
            self.assertFalse(ok)
            self.assertTrue(any("PE database" in reason for reason in reasons), reasons)

    def test_idb_identity_requires_original_input_sha256(self):
        with tempfile.TemporaryDirectory() as temporary:
            binary = Path(temporary) / "hw.dll"
            binary.write_bytes(b"binary")
            for suffix in (".i64", ".idb"):
                with self.subTest(suffix=suffix):
                    ok, reasons = validate_opened_binary_identity(
                        binary,
                        "windows",
                        {"metadata": {"path": f"{binary}{suffix}"}},
                    )
                    self.assertFalse(ok)
                    self.assertEqual(["IDB input sha256 is unavailable"], reasons)

    def test_idb_identity_normalizes_placeholder_input_hashes(self):
        with tempfile.TemporaryDirectory() as temporary:
            binary = Path(temporary) / "hw.dll"
            binary.write_bytes(b"binary")
            for placeholder in ("unavailable", "UNKNOWN", "none", " null "):
                with self.subTest(placeholder=placeholder):
                    ok, reasons = validate_opened_binary_identity(
                        binary,
                        "windows",
                        {
                            "metadata": {
                                "path": f"{binary}.i64",
                                "sha256": "unavailable",
                                "input_sha256": placeholder,
                            }
                        },
                    )
                    self.assertFalse(ok)
                    self.assertEqual(["IDB input sha256 is unavailable"], reasons)
                    self.assertNotIn("sha256 mismatch", " ".join(reasons))

    def test_missing_idb_input_hash_preserves_other_identity_failures(self):
        with tempfile.TemporaryDirectory() as temporary:
            binary = Path(temporary) / "hw.dll"
            binary.write_bytes(b"binary")
            ok, reasons = validate_opened_binary_identity(
                binary,
                "windows",
                {
                    "metadata": {
                        "path": str(Path(temporary) / "wrong.dll.i64"),
                        "arch": "64",
                        "format": "ELF",
                    }
                },
            )
            self.assertFalse(ok)
            self.assertTrue(any("unexpected 64-bit" in reason for reason in reasons), reasons)
            self.assertTrue(any("ELF database" in reason for reason in reasons), reasons)
            self.assertIn("IDB input sha256 is unavailable", reasons)
            self.assertTrue(any("path mismatch" in reason for reason in reasons), reasons)

    def test_idb_identity_uses_original_input_sha256_instead_of_survey_hash(self):
        with tempfile.TemporaryDirectory() as temporary:
            binary = Path(temporary) / "hw.dll"
            binary.write_bytes(b"binary")
            expected_sha256 = hashlib.sha256(b"binary").hexdigest()
            ok, reasons = validate_opened_binary_identity(
                binary,
                "windows",
                {
                    "metadata": {
                        "path": f"{binary}.i64",
                        "sha256": "0" * 64,
                        "input_sha256": expected_sha256,
                    }
                },
            )
            self.assertTrue(ok, reasons)

            ok, reasons = validate_opened_binary_identity(
                binary,
                "windows",
                {
                    "metadata": {
                        "path": f"{binary}.idb",
                        "sha256": expected_sha256,
                        "input_sha256": "0" * 64,
                    }
                },
            )
            self.assertFalse(ok)
            self.assertTrue(any("IDB input" in reason and "sha256 mismatch" in reason for reason in reasons), reasons)

    def test_mcp_tool_json_accepts_sdk_snake_case_structured_content(self):
        payload = {"metadata": {"module": "hw.dll", "arch": "32"}}
        result = SimpleNamespace(structuredContent=None, structured_content=payload, content=[])
        self.assertEqual(payload, _parse_mcp_tool_json(result))

    def test_recovery_budget_allows_only_one_restart(self):
        process = MagicMock()
        process.poll.return_value = None
        restarted = MagicMock()
        restarted.poll.return_value = None
        budget = McpRecoveryBudget()
        with (
            patch("ida_analyze_bin.check_mcp_worker_health", new=AsyncMock(return_value=False)),
            patch("ida_analyze_bin.quit_ida_gracefully"),
            patch("ida_analyze_bin.is_port_in_use", return_value=False),
            patch("ida_analyze_bin.start_idalib_mcp", return_value=restarted) as start,
        ):
            first_process, first_ok = ensure_mcp_available(
                process,
                "hw.dll",
                DEFAULT_HOST,
                DEFAULT_PORT,
                "",
                False,
                recovery_budget=budget,
            )
            second_process, second_ok = ensure_mcp_available(
                restarted,
                "hw.dll",
                DEFAULT_HOST,
                DEFAULT_PORT,
                "",
                False,
                recovery_budget=budget,
            )
        self.assertIs(restarted, first_process)
        self.assertTrue(first_ok)
        self.assertIs(restarted, second_process)
        self.assertFalse(second_ok)
        start.assert_called_once_with("hw.dll", DEFAULT_HOST, DEFAULT_PORT, "", False)

    def test_verified_lifecycle_saves_then_uses_targeted_graceful_shutdown(self):
        process = MagicMock()
        process.poll.return_value = None
        binding = McpDatabaseBinding(False, None, "hw.dll", "worker", True, True)
        runtime = McpRuntime(DEFAULT_HOST, DEFAULT_PORT, "hw.dll", binding)
        with (
            patch("ida_analyze_bin.start_idalib_mcp", return_value=process),
            patch("ida_analyze_bin.verify_owned_mcp_with_single_recovery", return_value=(process, runtime)),
            patch("ida_analyze_bin.save_ida_database") as save_database,
            patch("ida_analyze_bin.quit_ida_gracefully") as quit_gracefully,
            IdaMcpLifecycle("hw.dll", "windows", DEFAULT_HOST, DEFAULT_PORT, ""),
        ):
            pass
        save_database.assert_called_once_with(
            DEFAULT_HOST,
            DEFAULT_PORT,
            expected_binary=Path("hw.dll"),
            debug=False,
        )
        quit_gracefully.assert_called_once_with(
            process,
            DEFAULT_HOST,
            DEFAULT_PORT,
            expected_binary=Path("hw.dll"),
            debug=False,
        )

    def test_verified_lifecycle_closes_when_final_save_fails(self):
        process = MagicMock()
        process.poll.return_value = None
        binding = McpDatabaseBinding(False, None, "hw.dll", "worker", True, True)
        runtime = McpRuntime(DEFAULT_HOST, DEFAULT_PORT, "hw.dll", binding)
        with (
            patch("ida_analyze_bin.start_idalib_mcp", return_value=process),
            patch("ida_analyze_bin.verify_owned_mcp_with_single_recovery", return_value=(process, runtime)),
            patch("ida_analyze_bin.save_ida_database", side_effect=McpLifecycleError("save failed")),
            patch("ida_analyze_bin.quit_ida_gracefully") as quit_gracefully,
            self.assertRaisesRegex(McpLifecycleError, "save failed"),
        ):
            with IdaMcpLifecycle("hw.dll", "windows", DEFAULT_HOST, DEFAULT_PORT, ""):
                pass
        quit_gracefully.assert_called_once_with(
            process,
            DEFAULT_HOST,
            DEFAULT_PORT,
            expected_binary=Path("hw.dll"),
            debug=False,
        )

    def test_unverified_lifecycle_only_stops_its_supervisor(self):
        process = MagicMock()
        process.poll.return_value = None
        with (
            patch("ida_analyze_bin.start_idalib_mcp", return_value=process),
            patch("ida_analyze_bin.verify_owned_mcp_with_single_recovery", return_value=(process, None)),
            patch("ida_analyze_bin.stop_idalib_mcp_process") as stop,
            patch("ida_analyze_bin.wait_for_port_release", return_value=True),
            patch("ida_analyze_bin.quit_ida_gracefully") as quit_gracefully,
            self.assertRaisesRegex(McpLifecycleError, "identity verification failed"),
        ):
            IdaMcpLifecycle("hw.dll", "windows", DEFAULT_HOST, DEFAULT_PORT, "").__enter__()
        stop.assert_called_once_with(process, debug=False)
        quit_gracefully.assert_not_called()


class McpShutdownTests(unittest.IsolatedAsyncioTestCase):
    async def test_idb_save_is_sent_only_to_owned_auto_started_worker(self):
        call_tool = AsyncMock()
        owned = McpDatabaseBinding(True, "server-db", "hw.dll", "worker", True, True)
        with patch(
            "ida_analyze_bin.open_ida_mcp_session",
            return_value=bound_session_context(owned, call_tool),
        ):
            self.assertTrue(
                await save_ida_database_via_mcp(
                    DEFAULT_HOST,
                    DEFAULT_PORT,
                    expected_binary="hw.dll",
                    auto_started=True,
                )
            )
        call_tool.assert_awaited_once_with("idb_save", {})

        call_tool = AsyncMock()
        unowned = McpDatabaseBinding(True, "server-db", "hw.dll", "worker", False, True)
        with patch(
            "ida_analyze_bin.open_ida_mcp_session",
            return_value=bound_session_context(unowned, call_tool),
        ):
            self.assertFalse(
                await save_ida_database_via_mcp(
                    DEFAULT_HOST,
                    DEFAULT_PORT,
                    expected_binary="hw.dll",
                    auto_started=True,
                )
            )
        call_tool.assert_not_awaited()

    async def test_qexit_is_sent_only_to_owned_auto_started_worker(self):
        call_tool = AsyncMock()
        owned = McpDatabaseBinding(True, "server-db", "hw.dll", "worker", True, True)
        with patch(
            "ida_analyze_bin.open_ida_mcp_session",
            return_value=bound_session_context(owned, call_tool),
        ):
            self.assertTrue(
                await quit_ida_via_mcp(
                    DEFAULT_HOST,
                    DEFAULT_PORT,
                    expected_binary="hw.dll",
                    auto_started=True,
                )
            )
        call_tool.assert_awaited_once_with("py_eval", {"code": "import idc; idc.qexit(0)"})

        call_tool = AsyncMock()
        unowned = McpDatabaseBinding(True, "server-db", "hw.dll", "worker", False, True)
        with patch(
            "ida_analyze_bin.open_ida_mcp_session",
            return_value=bound_session_context(unowned, call_tool),
        ):
            self.assertFalse(
                await quit_ida_via_mcp(
                    DEFAULT_HOST,
                    DEFAULT_PORT,
                    expected_binary="hw.dll",
                    auto_started=True,
                )
            )
        call_tool.assert_not_awaited()


if __name__ == "__main__":
    unittest.main()
