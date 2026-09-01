from __future__ import annotations

import hashlib
import json
import tempfile
import unittest
from pathlib import Path, PurePosixPath

import yaml

import download_depot
from bin_artifact_contract import validate_repository_artifact_contract
from analysis_config import iter_analysis_config_tags
from analysis_planner import (
    PLATFORMS,
    build_execution_plan,
    module_declares_platform,
    parse_config_document,
    symbol_artifact_filename,
)
from binary_format import inspect_binary
from gamesymbol_snapshot_lib.config import load_contract
from tests.run_test_suite import GROUP_FILES, SOURCE_ALL_GROUPS

ROOT = Path(__file__).parents[1]


def _config_tags() -> set[str]:
    # configs/config.yaml is the -allgamever batch index, not a per-game config.
    return {path.stem for path in (ROOT / "configs").glob("*.yaml") if path.name != "config.yaml"}


class RepositoryContractTests(unittest.TestCase):
    def test_tracked_bin_artifacts_match_the_formal_repository_contract(self):
        inventory = validate_repository_artifact_contract(ROOT)
        self.assertEqual(273, len(inventory.paths))
        self.assertEqual(_config_tags(), {item.game_version for item in inventory.gamevers})

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

    def test_llm_decompile_prompt_contract(self):
        prompt = ROOT / "ida_preprocessor_scripts" / "prompt" / "call_llm_decompile.md"
        self.assertTrue(prompt.is_file())
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

    def test_registered_analysis_skills_have_implementations_and_declared_outputs(self):
        preprocessor_root = ROOT / "ida_preprocessor_scripts"
        fallback_root = ROOT / ".claude" / "skills"
        saw_registered_skill = False

        with tempfile.TemporaryDirectory() as temporary:
            for tag in sorted(_config_tags()):
                with self.subTest(tag=tag):
                    document = yaml.safe_load((ROOT / "configs" / f"{tag}.yaml").read_text(encoding="utf-8"))
                    modules = parse_config_document(document)
                    plan = build_execution_plan(
                        modules,
                        platforms=PLATFORMS,
                        bin_dir=temporary,
                        tag=tag,
                    )
                    declared_artifacts = set()

                    for module in modules:
                        for skill in module["skills"]:
                            saw_registered_skill = True
                            preprocessor = preprocessor_root / f"{skill['name']}.py"
                            fallback = fallback_root / skill["name"] / "SKILL.md"
                            self.assertTrue(
                                preprocessor.is_file() or fallback.is_file(),
                                f"Registered skill {skill['name']!r} has no preprocessor or Agent fallback",
                            )

                        for platform in PLATFORMS:
                            if not module_declares_platform(module, platform):
                                continue
                            for symbol in module["symbols"]:
                                if symbol.get("platform") not in {None, platform}:
                                    continue
                                declared_artifacts.add(f"{module['name']}/{symbol_artifact_filename(symbol, platform)}")

                    for node in plan.nodes:
                        for output in (*node.required_outputs, *node.optional_outputs):
                            self.assertIn(
                                output,
                                declared_artifacts,
                                f"Output {output!r} from {node.id} has no declared symbol",
                            )
                    contract = load_contract(
                        ROOT / "configs" / f"{tag}.yaml",
                        tag,
                        ROOT / "bin",
                        artifactdir=ROOT / "bin_artifacts",
                    )
                    self.assertEqual(contract.formal_paths, set(contract.owners_by_path))
                    self.assertTrue(all(len(owners) == 1 for owners in contract.owners_by_path.values()))

        self.assertTrue(saw_registered_skill)

    def test_download_and_config_tags_match(self):
        downloads = yaml.safe_load((ROOT / "download.yaml").read_text(encoding="utf-8"))["downloads"]
        download_tags = {entry["tag"] for entry in downloads}
        self.assertTrue(download_tags <= _config_tags())
        self.assertTrue(all("config" not in entry for entry in downloads))
        for entry in downloads:
            document = yaml.safe_load((ROOT / "configs" / f"{entry['tag']}.yaml").read_text(encoding="utf-8"))
            expected_paths = set()
            for module in document["modules"]:
                for platform in PLATFORMS:
                    if not module.get(f"module_{platform}"):
                        continue
                    depot_path = module.get(f"depot_{platform}")
                    self.assertIsInstance(depot_path, str)
                    parsed = PurePosixPath(depot_path)
                    self.assertFalse(parsed.is_absolute())
                    self.assertTrue(parsed.parts)
                    self.assertFalse(any(part in {"", ".", ".."} for part in parsed.parts))
                    expected_paths.add(parsed.as_posix())
            self.assertEqual(
                expected_paths,
                set(download_depot.load_module_filelist(ROOT / "configs" / f"{entry['tag']}.yaml", entry["basepath"])),
            )

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
                self.assertFalse(any(key.startswith("path_") for module in document["modules"] for key in module))
                for module in modules:
                    self.assertTrue(
                        any(module[f"path_{platform}"] or module[f"module_{platform}"] for platform in PLATFORMS)
                    )

    def test_ci_runs_required_checks(self):
        workflow = (ROOT / ".github" / "workflows" / "ci.yaml").read_text(encoding="utf-8")
        self.assertNotIn("generated-output-contract", GROUP_FILES)
        self.assertEqual(tuple(GROUP_FILES), SOURCE_ALL_GROUPS)
        backend_commands = (
            "uv sync --locked",
            "uv run python format_repo_files.py --check",
            "uv run python tests/run_test_suite.py unit -b --durations 30",
            "uv run python tests/run_test_suite.py repository-contract -b --durations 30",
            "uv run python tests/run_test_suite.py all -b --durations 30",
            "uv run python tests/run_test_suite.py redis-integration -b --durations 30",
        )
        frontend_commands = (
            "npm ci",
            "npm test",
            "npm run lint",
            "npm run build",
            "npm run verify:gamesymbols",
            "npm run test:e2e",
        )
        for command in (*backend_commands, *frontend_commands):
            self.assertIn(command, workflow)
        self.assertNotIn("generated-output-contract", workflow)

    def test_gamesymbol_pr_workflow_runs_merge_planner_with_selected_node_routing(self):
        workflow_text = (ROOT / ".github" / "workflows" / "gamesymbol-pr-validation.yml").read_text(encoding="utf-8")
        workflow = yaml.load(workflow_text, Loader=yaml.BaseLoader)
        jobs = workflow["jobs"]
        self.assertIn("edited", workflow["on"]["pull_request"]["types"])
        self.assertEqual("pr-validate", jobs["pr-validate"]["name"])
        self.assertEqual(
            {
                "plan",
                "warmup-idb",
                "validate-hosted",
                "analyze-self-hosted",
                "fork-analysis-blocked",
            },
            set(jobs["pr-validate"]["needs"]),
        )
        self.assertIn("always()", jobs["pr-validate"]["if"])
        self.assertEqual("always()", jobs["pr-validate"]["if"])
        self.assertNotIn("classify", jobs)
        aggregate = next(
            step for step in jobs["pr-validate"]["steps"] if step.get("name") == "Aggregate source validation results"
        )
        self.assertEqual("${{ needs.plan.result }}", aggregate["env"]["PLAN_RESULT"])
        self.assertEqual("${{ needs.warmup-idb.result }}", aggregate["env"]["WARMUP_RESULT"])
        self.assertEqual("${{ needs.validate-hosted.result }}", aggregate["env"]["HOSTED_RESULT"])
        self.assertEqual("${{ needs.analyze-self-hosted.result }}", aggregate["env"]["ANALYSIS_RESULT"])
        self.assertEqual("${{ needs.fork-analysis-blocked.result }}", aggregate["env"]["FORK_RESULT"])
        self.assertNotIn("cache_mode", jobs["plan"]["outputs"])
        self.assertNotIn("GSVIBE_IDB_CACHE_MODE", workflow_text)
        self.assertNotIn("-cache-mode", workflow_text)
        plan_steps = jobs["plan"]["steps"]
        planner = next(step for step in plan_steps if step.get("name") == "Generate canonical bound plan from PR merge")
        self.assertIn(".trusted-planner/gamesymbol_pr_validation.py plan", planner["run"])
        trusted_checkout = next(step for step in plan_steps if step.get("name") == "Checkout trusted base planner")
        self.assertEqual("${{ github.event.pull_request.base.sha }}", trusted_checkout["with"]["ref"])
        self.assertEqual("false", trusted_checkout["with"]["persist-credentials"])
        self.assertNotIn("uv run", aggregate["run"])
        self_hosted = jobs["analyze-self-hosted"]
        self.assertEqual(["self-hosted", "windows", "x64"], self_hosted["runs-on"])
        self.assertEqual("${{ github.repository }}-gamesymbol-self-hosted-ida", self_hosted["concurrency"]["group"])
        self.assertEqual("false", self_hosted["concurrency"]["cancel-in-progress"])
        step_names = [step.get("name") for step in self_hosted["steps"]]
        ordered = [
            "Clean persisted submodule analysis state",
            "Download exact warm IDB cache selection",
            "Verify exact warm IDB cache selection",
            "Restore exact warm IDB cache generations",
            "Analyze selected nodes and build self-consistent candidates",
            "Remove generated submodule analysis state",
        ]
        self.assertEqual(
            sorted(step_names.index(name) for name in ordered), [step_names.index(name) for name in ordered]
        )
        warm_steps = [step for step in self_hosted["steps"] if "warm IDB cache" in step.get("name", "")]
        self.assertTrue(warm_steps)
        self.assertTrue(all("if" not in step for step in warm_steps))
        # The consumer must not warm or publish; that authority belongs to the reusable producer.
        self.assertNotIn("idb_cache_workflow.py prepare", workflow_text)
        producer = jobs["warmup-idb"]
        self.assertEqual("./.github/workflows/warmup-idb.yml", producer["uses"])
        self.assertEqual("bound-plan", producer["with"]["scope"])
        self.assertNotIn("cache_mode", producer["with"])
        self.assertIn("warmup-idb", self_hosted["needs"])
        self.assertIn("needs.warmup-idb.result == 'success'", self_hosted["if"])
        self.assertNotIn("cold", self_hosted["if"])
        self.assertNotIn("needs.warmup-idb.result == 'skipped'", self_hosted["if"])
        analyzer = next(
            step
            for step in self_hosted["steps"]
            if step.get("name") == "Analyze selected nodes and build self-consistent candidates"
        )
        self.assertNotIn("cache_mode", analyzer["run"])
        self.assertIn("$env:RUNNER_TEMP 'rebuilt-bin-artifacts'", analyzer["run"])
        self.assertIn("$plannerCli compare", analyzer["run"])
        self.assertIn("-artifactdir $artifactRoot", analyzer["run"])
        self.assertIn("git diff --exit-code -- bin_artifacts", analyzer["run"])
        restore_index = step_names.index("Restore exact warm IDB cache generations")
        analyze_index = step_names.index("Analyze selected nodes and build self-consistent candidates")
        self.assertNotIn(
            "git clean",
            "\n".join(step.get("run", "") for step in self_hosted["steps"][restore_index + 1 : analyze_index]),
        )
        for forbidden in (
            "LLM_FAKE_AS",
            "gamesymbol_candidate.py publish",
            "git commit",
            "git push",
            "download.yaml[-1]",
            "robocopy",
        ):
            self.assertNotIn(forbidden, workflow_text)

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
        self.assertIn("gh release download", workflow)
        self.assertNotIn("'gamesymbols/**'", workflow)
        self.assertNotIn("push --force", workflow)

    def test_sven_local_dlls_are_read_only_pe32_smoke_inputs(self):
        # The bin submodule already pins the exact binary bytes; this test only
        # guards the smoke-input contract (PE32 i386) and that inspection is
        # non-mutating, without hardcoding volatile hashes.
        root = ROOT / "bin" / "svencoop-10257"
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
        for name in expected:
            info = inspect_binary(root / name)
            self.assertEqual(("PE", 32, "I386"), (info.container, info.bits, info.machine))
        after = {name: hashlib.sha256((root / name).read_bytes()).hexdigest() for name in expected}
        self.assertEqual(before, after)


if __name__ == "__main__":
    unittest.main()
