from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from agent_runner import build_agent_command
from analysis_planner import (
    AnalysisPlanError,
    build_execution_plan,
    expected_symbol_artifacts,
    parse_config_document,
)
from ida_analyze_bin import ANALYSIS_STAGES, run_analysis_pipeline
from process_reporter import InMemoryReporter


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


if __name__ == "__main__":
    unittest.main()
