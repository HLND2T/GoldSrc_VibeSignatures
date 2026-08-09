from __future__ import annotations

import io
import os
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest.mock import patch

from agent_runner import build_agent_command
from analysis_planner import (
    AnalysisPlanError,
    build_execution_plan,
    expected_symbol_artifacts,
    parse_config_document,
)
from ida_analyze_bin import (
    ANALYSIS_STAGES,
    AnalysisRunError,
    AnalysisSummary,
    _is_major_update_gamever,
    analyze,
    main,
    parse_args,
    resolve_oldgamever,
    run_analysis_pipeline,
)
from process_reporter import InMemoryReporter
from tests.test_support import write_pe32


def skill(name, *, output=(), required_input=(), optional_input=(), prerequisite=()):
    return {
        "name": name,
        "expected_output": list(output),
        "expected_output_windows": [],
        "expected_output_linux": [],
        "optional_output": [],
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
        with patch.dict(os.environ, env or {}, clear=True), redirect_stderr(io.StringIO()):
            with self.assertRaises(SystemExit) as raised:
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
        self.assertTrue(args.console_events)

    def test_removed_and_deferred_options_are_rejected(self):
        for option in (
            "-config",
            "-plan-only",
            "-vcall_finder",
            "-rename",
            "-ida_args",
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
        self.assertEqual(("history", "deterministic", "llm", "agent"), ANALYSIS_STAGES)

    def test_codex_agent_command_uses_one_prompt(self):
        initial = build_agent_command("codex", "find-symbol")
        retry = build_agent_command("codex", "find-symbol", retry=True)
        self.assertEqual(["codex", "exec", "Run SKILL: .claude/skills/find-symbol/SKILL.md"], initial)
        self.assertEqual(["codex", "exec", "resume", "--last", "Run SKILL: .claude/skills/find-symbol/SKILL.md"], retry)

    def test_pipeline_stops_after_deterministic_output(self):
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

            def deterministic(_name, *, context):
                calls.append("deterministic")
                Path(context["required_outputs"][0]).write_text("ok: true\n", encoding="utf-8")
                return True

            stage = run_analysis_pipeline(
                node,
                binary_path=binary,
                game_root=root,
                old_game_root=None,
                agent="codex",
                reporter=InMemoryReporter(),
                deterministic_runner=deterministic,
                llm_runner=lambda *_args, **_kwargs: calls.append("llm"),
                agent_skill_runner=lambda *_args, **_kwargs: calls.append("agent"),
            )
            self.assertEqual("deterministic", stage)
            self.assertEqual(["deterministic"], calls)

    def test_skip_pp_bypasses_history_and_both_preprocessors(self):
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

            stage = run_analysis_pipeline(
                node,
                binary_path=binary,
                game_root=root,
                old_game_root=old_root,
                agent="codex",
                agent_model="gpt-5",
                debug=True,
                skip_preprocessors=True,
                reporter=InMemoryReporter(),
                deterministic_runner=lambda *_args, **_kwargs: calls.append("deterministic"),
                llm_runner=lambda *_args, **_kwargs: calls.append("llm"),
                agent_skill_runner=agent,
            )
            self.assertEqual("agent", stage)
            self.assertEqual([("agent", "gpt-5", True)], calls)
            self.assertEqual("name: new\n", (root / "engine" / "result.yaml").read_text(encoding="utf-8"))

    def test_llm_runtime_config_is_passed_only_to_llm_preprocessor(self):
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

            def deterministic(_name, *, context):
                seen["deterministic_context"] = context
                return False

            def llm(_name, *, context, llm_config):
                seen["llm_context"] = context
                seen["llm_config"] = llm_config
                Path(context["required_outputs"][0]).write_text("ok: true\n", encoding="utf-8")
                return True

            stage = run_analysis_pipeline(
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
                deterministic_runner=deterministic,
                llm_runner=llm,
                agent_skill_runner=lambda *_args, **_kwargs: False,
            )
            self.assertEqual("llm", stage)
            self.assertNotIn("llm_config", seen["deterministic_context"])
            self.assertNotIn("api_key", seen["llm_context"])
            self.assertEqual("secret", seen["llm_config"]["api_key"])
            self.assertEqual(node.max_retries, seen["llm_config"]["max_retries"])

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
            with patch(
                "ida_analyze_bin.run_analysis_pipeline",
                side_effect=[AnalysisRunError("first failed"), "agent"],
            ) as pipeline:
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
            with (
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


if __name__ == "__main__":
    unittest.main()
