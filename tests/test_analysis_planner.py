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
    expected_symbol_artifacts,
    parse_config_document,
)
from ida_analyze_bin import (
    ANALYSIS_STAGES,
    DEFAULT_HOST,
    DEFAULT_PORT,
    AnalysisRunError,
    AnalysisSummary,
    IdaMcpLifecycle,
    McpLifecycleError,
    McpRecoveryBudget,
    McpRuntime,
    PipelineFailure,
    PipelineResult,
    _is_major_update_gamever,
    analyze,
    ensure_mcp_available,
    main,
    parse_args,
    quit_ida_via_mcp,
    resolve_oldgamever,
    run_analysis_pipeline,
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
from process_reporter import InMemoryReporter
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
            "path_linux": None,
            "skills": skills,
            "symbols": [],
        }
    ]


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
                        "skills": [
                            {
                                "name": "find",
                                "alias": "old",
                                "retry": 4,
                                "optional_output_windows": ["optional.windows.yaml"],
                            }
                        ],
                        "symbols": [{"name": "A::b", "type": "structmember", "struct": "A", "member": "b"}],
                    }
                ]
            }
        )
        self.assertEqual(["old"], modules[0]["skills"][0]["aliases"])
        self.assertEqual(4, modules[0]["skills"][0]["max_retries"])
        self.assertEqual(["optional.windows.yaml"], modules[0]["skills"][0]["optional_output_windows"])
        self.assertEqual("A", modules[0]["symbols"][0]["struct"])
        required, optional = expected_symbol_artifacts(modules)
        self.assertIn("engine/A_b.windows.yaml", required)
        self.assertIn("engine/optional.windows.yaml", optional)

    def test_rejects_cross_directory_and_absolute_artifacts(self):
        for path in ("../other/a.yaml", "other/a.yaml", "C:/a.yaml", "/a.yaml"):
            with self.subTest(path=path), self.assertRaises(AnalysisPlanError):
                parse_config_document(
                    {
                        "modules": [
                            {
                                "name": "engine",
                                "path_windows": "Game/hw.dll",
                                "skills": [{"name": "find", "expected_output": [path]}],
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
        args = self.parse_args(env={"GSVIBE_GAMEVER": "cstrike-10120"})
        self.assertEqual("cstrike-10120", args.gamever)
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
                "-console-events",
            ],
            env={
                "GSVIBE_GAMEVER": "cstrike-10000",
                "GSVIBE_AGENT": "claude",
                "GSVIBE_AGENT_MODEL": "env-agent-model",
                "GSVIBE_LLM_MODEL": "env-model",
                "GSVIBE_LLM_APIKEY": "env-key",
                "GSVIBE_LLM_BASEURL": "https://env.invalid/v1",
                "GSVIBE_LLM_TEMPERATURE": "1.0",
                "GSVIBE_LLM_FAKE_AS": "codex",
                "GSVIBE_LLM_EFFORT": "low",
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
        self.assertTrue(args.console_events)

    def test_removed_and_deferred_options_are_rejected(self):
        for option in (
            "-config",
            "-plan-only",
            "-vcall_finder",
            "-rename",
            "-process_reporter",
            "-run_id",
        ):
            with self.subTest(option=option):
                self.assert_parse_error(["-gamever", "cstrike-10120", option, "value"])
        self.assert_parse_error(["-gamever", "cstrike-10120", "-platform", "all-platform"])

    def test_invalid_lists_retry_llm_and_agent_fail_fast(self):
        invalid_argv = (
            ["-gamever", "cstrike-10120", "-platform", ""],
            ["-gamever", "cstrike-10120", "-platform", "windows,windows"],
            ["-gamever", "cstrike-10120", "-modules", "engine,,client"],
            ["-gamever", "cstrike-10120", "-modules", "engine,engine"],
            ["-gamever", "cstrike-10120", "-maxretry", "0"],
            ["-gamever", "cstrike-10120", "-llm_temperature", "3"],
            ["-gamever", "cstrike-10120", "-agent", ""],
            ["-gamever", "cstrike-10120", "-llm_fake_as", "codex"],
        )
        for argv in invalid_argv:
            with self.subTest(argv=argv):
                self.assert_parse_error(argv)

    def test_oldgamever_auto_resolution_is_family_aware(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for tag in ("cstrike-10118", "cstrike-10119", "svencoop-99999", "cstrike-10121"):
                (root / tag).mkdir()
            self.assertEqual("cstrike-10119", resolve_oldgamever("cstrike-10120", root))
            args = self.parse_args(
                ["-gamever", "cstrike-10120", "-bindir", str(root)],
            )
            self.assertEqual("cstrike-10119", args.oldgamever)
            self.assert_parse_error(
                [
                    "-gamever",
                    "cstrike-10120",
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
                "downloads:\n  - tag: cstrike-10120\n    major_update: true\n",
                encoding="utf-8",
            )
            self.assertTrue(_is_major_update_gamever("cstrike-10120", path))
            self.assertFalse(_is_major_update_gamever("cstrike-10119", path))

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
            self.assertIn(f"Config file: {config}", output.getvalue())
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
        self.assertEqual(["codex", "exec", "Run SKILL: .claude/skills/find-symbol/SKILL.md"], initial)
        self.assertEqual(["codex", "exec", "resume", "--last", "Run SKILL: .claude/skills/find-symbol/SKILL.md"], retry)

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
                reporter=InMemoryReporter(),
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
                "name: old\ntype: func\nfunc_sig: AA BB\nfunc_addr: '0x10'\n",
                encoding="utf-8",
            )
            node = build_execution_plan(
                module([skill("find", output=["result.yaml"])]),
                platforms=["windows"],
                bin_dir=Path(temporary),
                tag="game-2",
            ).nodes[0]
            calls = []

            def agent(_name, **kwargs):
                calls.append(("agent", kwargs["model"], kwargs["debug"]))
                Path(kwargs["expected_yaml_paths"][0]).write_text("name: new\n", encoding="utf-8")
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
                reporter=InMemoryReporter(),
                preprocessor_runner=lambda **_kwargs: calls.append("preprocessor"),
                agent_skill_runner=agent,
            )
            self.assertEqual(PipelineResult("succeeded", "agent"), result)
            self.assertEqual([("agent", "gpt-5", True)], calls)
            self.assertEqual("name: new\n", (root / "engine" / "result.yaml").read_text(encoding="utf-8"))

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
                reporter=InMemoryReporter(),
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
                    reporter=InMemoryReporter(),
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
                    reporter=InMemoryReporter(),
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
                    reporter=InMemoryReporter(),
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
                reporter=InMemoryReporter(),
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
                reporter=InMemoryReporter(),
                preprocessor_runner=preprocessor,
                agent_skill_runner=agent,
            )
            self.assertEqual(PipelineResult("succeeded", "agent"), result)
            self.assertEqual("source: preprocessor\n", observed["before_agent"])

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
                        reporter=InMemoryReporter(),
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
                reporter=InMemoryReporter(),
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
                reporter=InMemoryReporter(),
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
                    reporter=InMemoryReporter(),
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
                reporter=InMemoryReporter(),
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
                    reporter=InMemoryReporter(),
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
                    reporter=InMemoryReporter(),
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
    skills: []
""",
                encoding="utf-8",
            )
            with self.assertRaisesRegex(AnalysisRunError, "Module.*missing"):
                analyze(
                    gamever="game-1",
                    config_path=config,
                    bindir=root / "bin",
                    platforms=["windows"],
                    modules_filter=["missing"],
                )


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
                    reporter=InMemoryReporter(),
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
                    reporter=InMemoryReporter(),
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
    symbols:
      - name: TestSymbol
        type: func
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
                    reporter=InMemoryReporter(),
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

    def test_id0_lock_fails_before_process_start(self):
        with tempfile.TemporaryDirectory() as temporary:
            binary = Path(temporary) / "hw.dll"
            binary.write_bytes(b"binary")
            Path(f"{binary}.id0").write_bytes(b"lock")
            with (
                patch("ida_analyze_bin.start_idalib_mcp") as start,
                self.assertRaisesRegex(McpLifecycleError, "IDB lock file detected"),
            ):
                IdaMcpLifecycle(binary, "windows", DEFAULT_HOST, DEFAULT_PORT, "").__enter__()
            start.assert_not_called()

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

    def test_verified_lifecycle_uses_targeted_graceful_shutdown(self):
        process = MagicMock()
        process.poll.return_value = None
        binding = McpDatabaseBinding(False, None, "hw.dll", "worker", True, True)
        runtime = McpRuntime(DEFAULT_HOST, DEFAULT_PORT, "hw.dll", binding)
        with (
            patch("ida_analyze_bin.start_idalib_mcp", return_value=process),
            patch("ida_analyze_bin.verify_owned_mcp_with_single_recovery", return_value=(process, runtime)),
            patch("ida_analyze_bin.quit_ida_gracefully") as quit_gracefully,
            IdaMcpLifecycle("hw.dll", "windows", DEFAULT_HOST, DEFAULT_PORT, ""),
        ):
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
