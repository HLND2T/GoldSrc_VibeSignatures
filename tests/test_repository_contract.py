from __future__ import annotations

import hashlib
import unittest
from pathlib import Path

import yaml

from analysis_config import iter_analysis_config_tags
from analysis_planner import PLATFORMS, parse_config_document
from binary_format import inspect_binary

ROOT = Path(__file__).parents[1]
MODULES = {"engine", "client", "gameui", "server"}


def _config_tags() -> set[str]:
    # configs/config.yaml is the -allgamever batch index, not a per-game config.
    return {path.stem for path in (ROOT / "configs").glob("*.yaml") if path.name != "config.yaml"}


class RepositoryContractTests(unittest.TestCase):
    def test_generate_reference_yaml_skill_contract(self):
        skill_path = ROOT / ".claude" / "skills" / "generate-reference-yaml" / "SKILL.md"
        self.assertTrue(skill_path.is_file())
        text = skill_path.read_text(encoding="utf-8")
        for marker in (
            "name: generate-reference-yaml",
            "generate_reference_yaml.py",
            "-platform windows",
            "-platform linux",
            "sequentially",
            "ida_preprocessor_scripts/references/<gamever>/<module>/<func_name>.<platform>.yaml",
        ):
            self.assertIn(marker, text)
        metadata = yaml.safe_load((skill_path.parent / "agents" / "openai.yaml").read_text(encoding="utf-8"))
        self.assertIs(metadata["policy"]["allow_implicit_invocation"], False)

    def test_create_preprocessor_skill_wires_llm_reference_generation(self):
        path = ROOT / ".claude" / "skills" / "create-preprocessor-scripts" / "SKILL.md"
        text = path.read_text(encoding="utf-8")
        for marker in (
            "generate-reference-yaml",
            "generate_reference_yaml.py",
            "REFERENCE_GAMEVER",
            "canonical reference gamever",
            "per-gamever override",
            "-gamever <REFERENCE_GAMEVER>",
            "references/<REFERENCE_GAMEVER>/<REFERENCE_MODULE>/<PREDECESSOR>.windows.yaml",
            "references/<REFERENCE_GAMEVER>/<REFERENCE_MODULE>/<PREDECESSOR>.linux.yaml",
            "New predecessor: mandatory multi-phase workflow",
            "-skill <PREDECESSOR_SKILL>",
            "Reference generation and annotation must cover both `disasm_code` and `procedure`.",
        ):
            self.assertIn(marker, text)
        self.assertNotIn("GSVIBE_REFERENCE_GAMEVER", text)
        self.assertNotIn(".env", text)

    def test_create_agent_fallback_skill_resolves_reference_gamever(self):
        path = ROOT / ".claude" / "skills" / "create-agent-skill-fallback" / "SKILL.md"
        text = path.read_text(encoding="utf-8")
        for marker in (
            "current gamever",
            "canonical reference gamever",
            "GSVIBE_REFERENCE_GAMEVER",
            "default `hl-10210`",
            "Only stop after both",
        ):
            self.assertIn(marker, text)

    def test_reference_yamls_match_generation_contract(self):
        reference_root = ROOT / "ida_preprocessor_scripts" / "references"
        references = list(reference_root.glob("**/*.yaml")) if reference_root.is_dir() else []
        self.assertTrue(references)
        for path in references:
            with self.subTest(path=path.relative_to(ROOT).as_posix()):
                document = yaml.safe_load(path.read_text(encoding="utf-8"))
                self.assertIsInstance(document, dict)
                self.assertEqual(
                    {"func_name", "func_va", "disasm_code", "procedure"},
                    set(document),
                )
                self.assertIsInstance(document["func_name"], str)
                self.assertTrue(document["func_name"].strip())
                self.assertNotIsInstance(document["func_va"], bool)
                func_va = int(document["func_va"], 0) if isinstance(document["func_va"], str) else document["func_va"]
                self.assertIsInstance(func_va, int)
                self.assertGreaterEqual(func_va, 0)
                self.assertLessEqual(func_va, 0xFFFFFFFF)
                self.assertIsInstance(document["disasm_code"], str)
                self.assertTrue(document["disasm_code"].strip())
                self.assertIsInstance(document["procedure"], str)

    def test_build_number_llm_decompile_production_contract(self):
        script = ROOT / "ida_preprocessor_scripts" / "find-build_number.py"
        prompt = ROOT / "ida_preprocessor_scripts" / "prompt" / "call_llm_decompile.md"
        self.assertTrue(script.is_file())
        self.assertTrue(prompt.is_file())
        script_text = script.read_text(encoding="utf-8")
        for marker in (
            '"symbol_name": "build_number"',
            '"prompt_path": "prompt/call_llm_decompile.md"',
            '"references/{gamever}/engine/SV_SendServerinfo.{platform}.yaml"',
            '"expected_result_sections": ["found_call"]',
            "llm_config=None",
        ):
            self.assertIn(marker, script_text)

        prompt_text = prompt.read_text(encoding="utf-8")
        for marker in (
            "{reference_blocks}",
            "{target_blocks}",
            "{symbol_name_list}",
            "found_vcall",
            "found_call",
            "found_funcptr",
            "found_gv",
            "found_struct_offset",
            "GoldSrc vtable slots are 4 bytes",
        ):
            self.assertIn(marker, prompt_text)

        engine_tags = set()
        for tag in sorted(_config_tags()):
            document = yaml.safe_load((ROOT / "configs" / f"{tag}.yaml").read_text(encoding="utf-8"))
            engine = next((module for module in document["modules"] if module["name"] == "engine"), None)
            if engine is None:
                continue
            engine_tags.add(tag)
            finder = next(skill for skill in engine["skills"] if skill["name"] == "find-build_number")
            self.assertEqual(["build_number.{platform}.yaml"], finder["expected_output"])
            self.assertEqual(["SV_SendServerinfo.{platform}.yaml"], finder["expected_input"])
            self.assertNotIn("optional_input", finder)
            symbol = next(symbol for symbol in engine["symbols"] if symbol["name"] == "build_number")
            self.assertEqual("func", symbol["category"])
        self.assertEqual(
            {
                "cof-5936",
                "hl-10210",
                "hl-3248",
                "hl-3266",
                "hl-3329",
                "hl-3647",
                "hl-4554",
                "hl-6153",
                "hl-8684",
                "svencoop-10257",
            },
            engine_tags,
        )

        for gamever in ("hl-10210", "svencoop-10257"):
            for platform in ("windows", "linux"):
                with self.subTest(gamever=gamever, platform=platform):
                    reference = (
                        ROOT
                        / "ida_preprocessor_scripts"
                        / "references"
                        / gamever
                        / "engine"
                        / f"SV_SendServerinfo.{platform}.yaml"
                    )
                    document = yaml.safe_load(reference.read_text(encoding="utf-8"))
                    self.assertIn("call    build_number", document["disasm_code"])
                    self.assertIn("build_number()", document["procedure"])

    def test_download_and_config_tags_match(self):
        downloads = yaml.safe_load((ROOT / "download.yaml").read_text(encoding="utf-8"))["downloads"]
        download_tags = {entry["tag"] for entry in downloads}
        self.assertTrue(download_tags <= _config_tags())
        self.assertTrue(all("config" not in entry for entry in downloads))
        for entry in downloads:
            document = yaml.safe_load((ROOT / "configs" / f"{entry['tag']}.yaml").read_text(encoding="utf-8"))
            for module in parse_config_document(document):
                configured_paths = [module[f"path_{platform}"] for platform in PLATFORMS if module[f"path_{platform}"]]
                self.assertTrue(configured_paths)
                for path in configured_paths:
                    self.assertTrue(path.startswith(entry["basepath"] + "/"))

    def test_config_index_matches_config_files(self):
        indexed = set(iter_analysis_config_tags(ROOT))
        actual = _config_tags()
        # configs/config.yaml is the single authority for -allgamever: its
        # declared gamevers must be exactly the per-game configs present, so a
        # new config is not silently dropped from (or missing from) the batch.
        self.assertEqual(actual, indexed)

    def test_production_configs_have_modules_and_at_least_one_platform_binary(self):
        for tag in sorted(_config_tags()):
            with self.subTest(tag=tag):
                document = yaml.safe_load((ROOT / "configs" / f"{tag}.yaml").read_text(encoding="utf-8"))
                modules = parse_config_document(document)
                self.assertTrue(modules)
                for module in modules:
                    self.assertTrue(
                        any(module[f"path_{platform}"] or module[f"module_{platform}"] for platform in PLATFORMS)
                    )

    def test_goldsrc_engines_register_r_renderview_production_finder(self):
        for tag in ("hl-10210", "svencoop-10257"):
            with self.subTest(tag=tag):
                document = yaml.safe_load((ROOT / "configs" / f"{tag}.yaml").read_text(encoding="utf-8"))
                engine = next(module for module in document["modules"] if module["name"] == "engine")
                finder = next(skill for skill in engine["skills"] if skill["name"] == "find-R_RenderView")
                self.assertEqual(["R_RenderView.{platform}.yaml"], finder["expected_output"])
                symbol = next(symbol for symbol in engine["symbols"] if symbol["name"] == "R_RenderView")
                self.assertEqual("func", symbol["category"])
        self.assertTrue((ROOT / "ida_preprocessor_scripts" / "find-R_RenderView.py").is_file())
        self.assertTrue((ROOT / ".claude" / "skills" / "create-preprocessor-scripts" / "SKILL.md").is_file())

    def test_goldsrc_engines_register_client_dll_init_production_finder(self):
        engine_tags = {
            "cof-5936",
            "hl-10210",
            "hl-3248",
            "hl-3266",
            "hl-3329",
            "hl-3647",
            "hl-4554",
            "hl-6153",
            "hl-8684",
            "svencoop-10257",
        }
        for tag in engine_tags:
            with self.subTest(tag=tag):
                document = yaml.safe_load((ROOT / "configs" / f"{tag}.yaml").read_text(encoding="utf-8"))
                engine = next(module for module in document["modules"] if module["name"] == "engine")
                finder = next(skill for skill in engine["skills"] if skill["name"] == "find-ClientDLL_Init")
                self.assertEqual(["ClientDLL_Init.{platform}.yaml"], finder["expected_output"])
                symbol = next(symbol for symbol in engine["symbols"] if symbol["name"] == "ClientDLL_Init")
                self.assertEqual("func", symbol["category"])
        self.assertTrue((ROOT / "ida_preprocessor_scripts" / "find-ClientDLL_Init.py").is_file())

    def test_no_disallowed_source2_subsystems_or_architecture_paths(self):
        disallowed = ("win64", "cpp_tests", "hl2sdk")
        checked = [path for path in ROOT.glob("*.py") if path.name not in {"format_repo_files.py"}]
        checked.extend((ROOT / "gamesymbol_snapshot_lib").glob("*.py"))
        for path in checked:
            text = path.read_text(encoding="utf-8").casefold()
            for marker in disallowed:
                self.assertNotIn(marker, text, f"{marker} remains in {path}")

    def test_documented_commands_and_ci_gate_match(self):
        readme = (ROOT / "README.md").read_text(encoding="utf-8")
        workflow = (ROOT / ".github" / "workflows" / "ci.yaml").read_text(encoding="utf-8")
        commands = (
            "uv sync --locked",
            "uv run python format_repo_files.py --check",
            "uv run python tests/run_test_suite.py unit -b --durations 30",
            "uv run python tests/run_test_suite.py repository-contract -b --durations 30",
            "uv run python tests/run_test_suite.py all -b --durations 30",
            "uv run python tests/run_test_suite.py redis-integration -b --durations 30",
        )
        for command in commands:
            self.assertIn(command, readme)
            self.assertIn(command, workflow)

        frontend_commands = (
            "npm ci",
            "npm test",
            "npm run lint",
            "npm run build",
            "npm run verify:gamesymbols",
            "npm run test:e2e",
        )
        pages_readme = (ROOT / "pages" / "README.md").read_text(encoding="utf-8")
        pages_workflow = (ROOT / ".github" / "workflows" / "ci.yaml").read_text(encoding="utf-8")
        for command in frontend_commands:
            self.assertIn(command, pages_readme)
            self.assertIn(command, pages_workflow)

    def test_published_sven_snapshot_matches_goldsrc_contract(self):
        path = ROOT / "gamesymbols" / "svencoop-10257.yaml"
        self.assertTrue(path.is_file())
        document = yaml.safe_load(path.read_text(encoding="utf-8"))
        self.assertEqual(5, document["schema_version"])
        self.assertEqual("svencoop-10257", document["game_version"])
        self.assertEqual(2, document["file_count"])
        self.assertEqual(
            {"engine/R_RenderView.linux.yaml", "engine/R_RenderView.windows.yaml"},
            set(document["files"]),
        )
        self.assertEqual(MODULES, set(document["binaries"]))

    def test_pages_workflow_keeps_content_addressed_history_append_only(self):
        workflow = (ROOT / ".github" / "workflows" / "deploy-pages.yml").read_text(encoding="utf-8")
        for marker in (
            "pages-snapshots",
            "--archive",
            "refs/heads/pages-snapshots",
            "actions/deploy-pages@v5",
            "[a-z0-9]+(-[a-z0-9]+)*-[0-9]+",
        ):
            self.assertIn(marker, workflow)
        self.assertNotIn("push --force", workflow)

    def test_sven_local_dlls_are_read_only_pe32_smoke_inputs(self):
        root = ROOT / "bin" / "svencoop"
        expected = {
            "client/client.dll",
            "engine/hw.dll",
            "gameui/GameUI.dll",
            "server/server.dll",
        }
        existing = {path.relative_to(root).as_posix() for path in root.glob("*/*.dll")} if root.is_dir() else set()
        if not existing:
            self.skipTest("Local Sven Co-op smoke binaries are not present")
        self.assertEqual(expected, existing)
        before = {name: hashlib.sha256((root / name).read_bytes()).hexdigest() for name in expected}
        self.assertEqual(
            {
                "client/client.dll": "f40e74b7a703d193188d628066660ff0ac4be2b09613ae4b7f8d2c671991e7d6",
                "engine/hw.dll": "e3c7f374b70845fb6f45c05906e4b5fe3dc9f394ab37bb653501d3b6a3282596",
                "gameui/GameUI.dll": "99382b87319d21139c0675d8a45669d64ef930f9e43dbd582461575383545f75",
                "server/server.dll": "f8be8b7ba8af2a5006127c3c36ced3717d94aec1120ef8b5678e28b23f0b07c0",
            },
            before,
        )
        for name in expected:
            info = inspect_binary(root / name)
            self.assertEqual(("PE", 32, "I386"), (info.container, info.bits, info.machine))
        after = {name: hashlib.sha256((root / name).read_bytes()).hexdigest() for name in expected}
        self.assertEqual(before, after)


if __name__ == "__main__":
    unittest.main()
