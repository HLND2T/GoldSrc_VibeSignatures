from __future__ import annotations

import hashlib
import json
import tempfile
import unittest
from pathlib import Path, PurePosixPath

import yaml

import download_depot
from analysis_config import iter_analysis_config_tags
from analysis_planner import (
    PLATFORMS,
    build_execution_plan,
    module_declares_platform,
    parse_config_document,
    symbol_artifact_filename,
)
from binary_format import inspect_binary
from gamedata_contract import (
    analysis_config_sha256,
    discover_generator_modules,
    generator_contract_sha256,
    validate_gamedata_tree,
)
from gamesymbol_snapshot_lib.config import load_contract
from gamesymbol_snapshot_lib.metadata import verify_metadata
from gamesymbol_snapshot_lib.paths import iter_snapshot_paths
from release_workflow_lib.hashing import sha256_file

ROOT = Path(__file__).parents[1]


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
                    contract = load_contract(ROOT / "configs" / f"{tag}.yaml", tag, ROOT / "bin")
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

    def test_gamesymbol_pr_workflow_runs_merge_planner_with_selected_node_routing(self):
        workflow_text = (ROOT / ".github" / "workflows" / "gamesymbol-pr-validation.yml").read_text(encoding="utf-8")
        workflow = yaml.load(workflow_text, Loader=yaml.BaseLoader)
        jobs = workflow["jobs"]
        self.assertIn("edited", workflow["on"]["pull_request"]["types"])
        self.assertEqual("pr-validate", jobs["pr-validate"]["name"])
        self.assertEqual(
            {
                "classify",
                "plan",
                "validate-hosted",
                "analyze-self-hosted",
                "fork-analysis-blocked",
                "validate-output",
            },
            set(jobs["pr-validate"]["needs"]),
        )
        self.assertIn("always()", jobs["pr-validate"]["if"])
        self.assertIn("github.event.action != 'closed'", jobs["pr-validate"]["if"])
        self.assertEqual("classify", jobs["validate-output"]["needs"])
        self.assertIn("route == 'output'", jobs["validate-output"]["if"])
        self.assertEqual("./.github/workflows/release-output-validation.yml", jobs["validate-output"]["uses"])
        self.assertEqual("classify", jobs["plan"]["needs"])
        self.assertIn("route == 'source'", jobs["plan"]["if"])
        for job_id in ("validate-hosted", "analyze-self-hosted", "fork-analysis-blocked"):
            self.assertIn("route == 'source'", jobs[job_id]["if"])
        aggregate = next(
            step for step in jobs["pr-validate"]["steps"] if step.get("name") == "Aggregate source validation results"
        )
        self.assertEqual("${{ needs.plan.result }}", aggregate["env"]["PLAN_RESULT"])
        self.assertEqual("${{ needs.validate-hosted.result }}", aggregate["env"]["HOSTED_RESULT"])
        self.assertEqual("${{ needs.analyze-self-hosted.result }}", aggregate["env"]["ANALYSIS_RESULT"])
        self.assertEqual("${{ needs.fork-analysis-blocked.result }}", aggregate["env"]["FORK_RESULT"])
        output_aggregate = next(
            step
            for step in jobs["pr-validate"]["steps"]
            if step.get("name") == "Aggregate trusted output validation result"
        )
        self.assertIn("route == 'output'", output_aggregate["if"])
        route_guard = next(
            step for step in jobs["pr-validate"]["steps"] if step.get("name") == "Require exactly one trusted PR route"
        )
        self.assertEqual("${{ needs.classify.result }}", route_guard["env"]["CLASSIFY_RESULT"])
        self.assertEqual("${{ steps.route.outputs.cache_mode }}", jobs["plan"]["outputs"]["cache_mode"])
        self.assertIn("-cache-mode", workflow_text)
        plan_steps = jobs["plan"]["steps"]
        planner = next(step for step in plan_steps if step.get("name") == "Generate canonical bound plan from PR merge")
        self.assertIn("uv run python gamesymbol_pr_validation.py plan", planner["run"])
        self.assertNotIn("base-planner", workflow_text)
        self.assertFalse(any(step.get("name") == "Export trusted base planner" for step in plan_steps))
        self.assertNotIn("uv run", aggregate["run"])
        self_hosted = jobs["analyze-self-hosted"]
        self.assertEqual(["self-hosted", "windows", "x64"], self_hosted["runs-on"])
        self.assertEqual("${{ github.repository }}-gamesymbol-self-hosted-ida", self_hosted["concurrency"]["group"])
        self.assertEqual("false", self_hosted["concurrency"]["cancel-in-progress"])
        step_names = [step.get("name") for step in self_hosted["steps"]]
        ordered = [
            "Clean persisted submodule analysis state",
            "Prepare exact warm IDB cache selection",
            "Verify exact warm IDB cache selection",
            "Restore exact warm IDB cache generations",
            "Analyze selected nodes and compare actual snapshots",
            "Remove generated submodule analysis state",
        ]
        self.assertEqual(
            sorted(step_names.index(name) for name in ordered), [step_names.index(name) for name in ordered]
        )
        warm_steps = [step for step in self_hosted["steps"] if "warm IDB cache" in step.get("name", "")]
        self.assertTrue(warm_steps)
        self.assertTrue(all("cache_mode == 'warm'" in step["if"] for step in warm_steps))
        analyzer = next(
            step
            for step in self_hosted["steps"]
            if step.get("name") == "Analyze selected nodes and compare actual snapshots"
        )
        self.assertIn("'-cache_mode', $plan.cache_mode", analyzer["run"])
        restore_index = step_names.index("Restore exact warm IDB cache generations")
        analyze_index = step_names.index("Analyze selected nodes and compare actual snapshots")
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

    def test_release_phase_two_workflows_keep_read_write_authority_split(self):
        workflows = {
            name: yaml.load((ROOT / ".github" / "workflows" / name).read_text(encoding="utf-8"), Loader=yaml.BaseLoader)
            for name in (
                "release-build.yml",
                "release-output-validation.yml",
                "release-promotion.yml",
                "release-operations.yml",
            )
        }
        build = workflows["release-build.yml"]
        self.assertEqual("read", build["permissions"]["contents"])
        build_job = build["jobs"]["build-output"]
        self.assertEqual(["self-hosted", "Windows", "X64", "gsvibe-release"], build_job["runs-on"])
        self.assertEqual("release", build_job["environment"])
        self.assertIn("GSVIBE_RELEASE_PHASE2_ENABLED", json.dumps(build))
        self.assertIn("actions/create-github-app-token@v2", json.dumps(build_job))

        output = workflows["release-output-validation.yml"]
        output_job = output["jobs"]["verify-output"]
        self.assertEqual("read", output["permissions"]["contents"])
        self.assertNotIn("environment", output_job)
        self.assertNotIn("create-github-app-token", json.dumps(output_job))
        checkout = next(step for step in output_job["steps"] if step.get("name") == "Checkout trusted base verifier")
        self.assertEqual("${{ inputs.base_sha }}", checkout["with"]["ref"])
        self.assertIn("base_branch", output["on"]["workflow_call"]["inputs"])

        promotion = workflows["release-promotion.yml"]
        verifier = promotion["jobs"]["verify-promotion"]
        writer = promotion["jobs"]["promotion-write"]
        self.assertNotIn("environment", verifier)
        self.assertEqual("release", writer["environment"])
        self.assertEqual("verify-promotion", writer["needs"])
        self.assertIn("needs.verify-promotion.outputs.approval_sha256", json.dumps(writer))
        self.assertIn("release_workflow.py promote", json.dumps(writer))

        operations = workflows["release-operations.yml"]
        choices = operations["on"]["workflow_dispatch"]["inputs"]["operation"]["options"]
        self.assertEqual(
            {"retry", "resume-promotion", "republish", "abandon", "repair-index", "cleanup", "reconcile"},
            set(choices),
        )
        self.assertEqual("release", operations["jobs"]["operate"]["environment"])
        self.assertIn("GSVIBE_RELEASE_REPUBLISH_ENABLED", json.dumps(operations))
        concurrency_groups = {
            build_job["concurrency"]["group"],
            writer["concurrency"]["group"],
            operations["jobs"]["operate"]["concurrency"]["group"],
        }
        self.assertEqual({"${{ github.repository }}-release-phase2"}, concurrency_groups)
        for workflow in workflows.values():
            for job in workflow["jobs"].values():
                for step in job.get("steps", []):
                    run = step.get("run", "")
                    self.assertNotIn("${{ inputs.", run)
                    self.assertNotIn("${{ github.event.pull_request.", run)

    def test_published_gamesymbol_snapshots_match_goldsrc_contract(self):
        # The exact published set is deliberately not pinned: the bin submodule
        # pins binary bytes, and new game versions must not require editing this
        # test. Structural contract checks below still guard every published file.
        published = {path.stem for path in iter_snapshot_paths(ROOT / "gamesymbols")}
        self.assertTrue(published)

        for tag in sorted(published):
            with self.subTest(tag=tag):
                path = ROOT / "gamesymbols" / f"{tag}.yaml"
                document = yaml.safe_load(path.read_text(encoding="utf-8"))
                contract = load_contract(ROOT / "configs" / f"{tag}.yaml", tag, ROOT / "bin")
                self.assertEqual(6, document["schema_version"])
                self.assertEqual(tag, document["game_version"])
                self.assertEqual(document["file_count"], len(document["files"]))
                self.assertTrue(contract.required_paths <= set(document["files"]) <= contract.formal_paths)
                actual_binaries = {
                    (module, platform): metadata
                    for module, platforms in document["binaries"].items()
                    for platform, metadata in platforms.items()
                }
                self.assertEqual(set(contract.binary_targets), set(actual_binaries))
                self.assertTrue(actual_binaries)
                for metadata in actual_binaries.values():
                    self.assertNotIn("path", metadata)
                    self.assertGreater(metadata["size"], 0)
                companion = ROOT / "gamesymbols" / f"{tag}.metadata.yaml"
                self.assertTrue(companion.is_file())
                verify_metadata(
                    metadata_path=companion,
                    snapshot_path=path,
                    config_path=ROOT / "configs" / f"{tag}.yaml",
                    game_version=tag,
                )
                config_path = ROOT / "configs" / f"{tag}.yaml"
                generators = discover_generator_modules(ROOT / "gamedata-generators")
                files, manifest_sha256 = validate_gamedata_tree(
                    ROOT / "gamedata" / tag,
                    tag,
                    generators,
                    candidate_sha256=sha256_file(path),
                    analysis_config_sha256=analysis_config_sha256(config_path),
                    generator_contract_digest=generator_contract_sha256(generators),
                )
                self.assertTrue(files)
                self.assertRegex(manifest_sha256, r"^[0-9a-f]{64}$")
        self.assertFalse((ROOT / "gamesymbols" / "cstrike-10210.metadata.yaml").exists())
        self.assertFalse((ROOT / "gamesymbols" / "cstrike-8684.metadata.yaml").exists())
        self.assertFalse((ROOT / "gamedata" / "cstrike-10210").exists())
        self.assertFalse((ROOT / "gamedata" / "cstrike-8684").exists())

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
