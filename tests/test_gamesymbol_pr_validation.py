from __future__ import annotations

import hashlib
import json
import re
import subprocess
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import yaml

from gamesymbol_snapshot_lib.analysis_sources import (
    AnalysisSourceError,
    SourceIndex,
    build_source_index,
    validate_reference_consumers,
)
from gamesymbol_snapshot_lib.config import load_contract
from gamesymbol_snapshot_lib.impact_registry import ImpactRegistryError, parse_impact_registry
from gamesymbol_snapshot_lib.pr_cli import (
    GitRepository,
    PrCliError,
    _artifact_inventory,
    build_plan,
    compare_rebuilt_artifacts,
    materialize_from_plan,
    verify_bound_tag_inputs,
)
from gamesymbol_snapshot_lib.pr_validation import (
    CACHE_MODE_WARM,
    PLAN_SCHEMA_VERSION,
    BoundImpactPlan,
    ChangedPath,
    ImpactPlanningError,
    TagImpact,
    evaluate_pr_validation,
    plan_tag_impact,
)
from ida_analyze_util import canonical_symbol_yaml_bytes
from tests.test_support import write_pe32


class ImpactRegistryTests(unittest.TestCase):
    def test_parses_limited_scopes_and_matches_paths(self):
        rules = parse_impact_registry(
            {
                "schema_version": 1,
                "rules": [
                    {"paths": ["ida_preprocessor_scripts/**/*.py"], "scope": "all", "reason": "shared"},
                    {
                        "paths": ["windows-only.py"],
                        "scope": "platform",
                        "platforms": ["windows"],
                        "tags": ["hl-10210"],
                        "reason": "windows",
                    },
                    {
                        "paths": ["category.py"],
                        "scope": "category",
                        "categories": ["func"],
                        "reason": "func",
                    },
                    {"paths": ["skill.py"], "scope": "skill", "skills": ["find"], "reason": "find"},
                ],
            }
        )
        self.assertTrue(rules[0].matches_path("ida_preprocessor_scripts/nested/find.py"))
        self.assertEqual(frozenset({"hl-10210"}), rules[1].tags)
        self.assertEqual(frozenset({"func"}), rules[2].categories)
        self.assertEqual(frozenset({"find"}), rules[3].skills)

    def test_rejects_unsafe_paths_invalid_scopes_and_unknown_selectors(self):
        invalid_rules = (
            {"paths": ["/absolute.py"], "scope": "all", "reason": "bad"},
            {"paths": ["../escape.py"], "scope": "all", "reason": "bad"},
            {"paths": ["bad\\path.py"], "scope": "all", "reason": "bad"},
            {"paths": ["bad[0].py"], "scope": "all", "reason": "bad"},
            {"paths": ["x.py"], "scope": "unknown", "reason": "bad"},
            {"paths": ["x.py"], "scope": "platform", "platforms": ["mac"], "reason": "bad"},
            {"paths": ["x.py"], "scope": "category", "categories": ["class"], "reason": "bad"},
            {"paths": ["x.py"], "scope": "all", "skills": ["find"], "reason": "bad"},
        )
        for rule in invalid_rules:
            with self.subTest(rule=rule), self.assertRaises(ImpactRegistryError):
                parse_impact_registry({"schema_version": 1, "rules": [rule]})


class AnalysisSourceIndexTests(unittest.TestCase):
    def _contract(self, root: Path, tag: str):
        config = root / f"{tag}.yaml"
        config.write_text(
            yaml.safe_dump(
                {
                    "modules": [
                        {
                            "name": "engine",
                            "path_windows": "Game/hw.dll",
                            "module_windows": "hw.dll",
                            "skills": [{"name": "find-demo", "expected_output": ["Demo.{platform}.yaml"]}],
                            "symbols": [{"name": "Demo", "category": "func"}],
                        }
                    ]
                },
                sort_keys=False,
            ),
            encoding="utf-8",
        )
        return load_contract(config, tag, root / "bin", artifactdir=root / "bin_artifacts")

    def test_indexes_root_import_prompt_current_reference_and_canonical_fallback(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            script = (
                "from ida_analyze_util import preprocess_common_skill\n"
                "LLM_DECOMPILE = [{'prompt_path': 'prompt/call_llm_decompile.md', "
                "'reference_yaml_paths': ['references/{gamever}/{module_name}/Demo.{platform}.yaml']}]\n"
            )
            common_tree = {
                "ida_preprocessor_scripts/find-demo.py": script,
                "ida_analyze_util.py": "def preprocess_common_skill(): pass\n",
                "ida_preprocessor_scripts/prompt/call_llm_decompile.md": "prompt",
                "ida_preprocessor_scripts/references/hl-10210/engine/Demo.windows.yaml": "func_name: Demo\n",
            }
            current_tree = dict(common_tree)
            current_tree["ida_preprocessor_scripts/references/game-1/engine/Demo.windows.yaml"] = "func_name: Demo\n"

            current = build_source_index(self._contract(root, "game-1"), current_tree)
            fallback = build_source_index(self._contract(root, "game-2"), common_tree)

            node = "engine:windows:find-demo"
            self.assertEqual(frozenset({node}), current.owners("ida_analyze_util.py"))
            self.assertEqual(frozenset({node}), current.owners("ida_preprocessor_scripts/prompt/call_llm_decompile.md"))
            self.assertEqual(
                frozenset({node}),
                current.owners("ida_preprocessor_scripts/references/game-1/engine/Demo.windows.yaml"),
            )
            self.assertFalse(current.owners("ida_preprocessor_scripts/references/hl-10210/engine/Demo.windows.yaml"))
            self.assertEqual(
                frozenset({node}),
                fallback.owners("ida_preprocessor_scripts/references/hl-10210/engine/Demo.windows.yaml"),
            )

    def test_rejects_orphan_head_reference(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            tree = {
                "ida_preprocessor_scripts/find-demo.py": "from ida_analyze_util import x\n",
                "ida_analyze_util.py": "x = 1\n",
                "ida_preprocessor_scripts/references/hl-10210/engine/Orphan.windows.yaml": "func_name: x\n",
            }
            with self.assertRaisesRegex(AnalysisSourceError, "no analysis consumer"):
                validate_reference_consumers(tree, [build_source_index(self._contract(root, "game-1"), tree)])


class ImpactPlanningTests(unittest.TestCase):
    def _contract(self, root: Path, *, max_retries: int = 2):
        config = root / f"config-{max_retries}.yaml"
        config.write_text(
            yaml.safe_dump(
                {
                    "modules": [
                        {
                            "name": "engine",
                            "path_windows": "Game/hw.dll",
                            "module_windows": "hw.dll",
                            "skills": [
                                {
                                    "name": "produce",
                                    "expected_output": ["A.{platform}.yaml"],
                                    "max_retries": max_retries,
                                },
                                {
                                    "name": "consume",
                                    "expected_input": ["A.{platform}.yaml"],
                                    "expected_output": ["B.{platform}.yaml"],
                                },
                            ],
                            "symbols": [
                                {"name": "A", "category": "func"},
                                {"name": "B", "category": "gv"},
                            ],
                        }
                    ]
                },
                sort_keys=False,
            ),
            encoding="utf-8",
        )
        return load_contract(config, "game-1", root / "bin", artifactdir=root / "bin_artifacts")

    def test_source_seed_expands_downstream_and_invalidates_owned_outputs(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            contract = self._contract(root)
            source = SourceIndex(
                {"ida_preprocessor_scripts/produce.py": frozenset({"engine:windows:produce"})},
                frozenset({"ida_preprocessor_scripts/produce.py"}),
            )
            impact = plan_tag_impact(
                tag="game-1",
                base_contract=contract,
                merge_contract=contract,
                changed_paths=(
                    ChangedPath("M", "ida_preprocessor_scripts/produce.py", "ida_preprocessor_scripts/produce.py"),
                ),
                base_sources=source,
                merge_sources=source,
                base_rules=(),
                merge_rules=(),
            )
            self.assertEqual(("engine:windows:produce", "engine:windows:consume"), impact.analysis_nodes)
            self.assertEqual(("engine/A.windows.yaml", "engine/B.windows.yaml"), impact.invalidated_paths)
            self.assertTrue(impact.snapshot_rebuild)
            self.assertTrue(impact.gamedata_rebuild)

    def test_operational_config_change_is_snapshot_only_and_unmapped_analysis_fails_closed(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            base = self._contract(root, max_retries=1)
            merge = self._contract(root, max_retries=20)
            impact = plan_tag_impact(
                tag="game-1",
                base_contract=base,
                merge_contract=merge,
                changed_paths=(ChangedPath("M", "configs/game-1.yaml", "configs/game-1.yaml"),),
                base_sources=None,
                merge_sources=None,
                base_rules=(),
                merge_rules=(),
            )
            self.assertEqual((), impact.analysis_nodes)
            self.assertTrue(impact.snapshot_rebuild)
            with self.assertRaisesRegex(ImpactPlanningError, "no mapped consumer"):
                plan_tag_impact(
                    tag="game-1",
                    base_contract=base,
                    merge_contract=merge,
                    changed_paths=(ChangedPath("A", None, "ida_preprocessor_scripts/unmapped.py"),),
                    base_sources=None,
                    merge_sources=None,
                    base_rules=(),
                    merge_rules=(),
                )

    def test_snapshot_and_gamedata_domains_route_without_ida_and_zero_symbol_tags_stay_noop(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            contract = self._contract(root)
            snapshot_only = plan_tag_impact(
                tag="game-1",
                base_contract=contract,
                merge_contract=contract,
                changed_paths=(ChangedPath("M", "gamesymbol_candidate.py", "gamesymbol_candidate.py"),),
                base_sources=None,
                merge_sources=None,
                base_rules=(),
                merge_rules=(),
            )
            self.assertEqual((), snapshot_only.analysis_nodes)
            self.assertTrue(snapshot_only.snapshot_rebuild)
            self.assertFalse(snapshot_only.gamedata_rebuild)
            hashing_only = plan_tag_impact(
                tag="game-1",
                base_contract=contract,
                merge_contract=contract,
                changed_paths=(ChangedPath("M", "binary_hashing.py", "binary_hashing.py"),),
                base_sources=None,
                merge_sources=None,
                base_rules=(),
                merge_rules=(),
            )
            self.assertEqual((), hashing_only.analysis_nodes)
            self.assertTrue(hashing_only.snapshot_rebuild)
            self.assertFalse(hashing_only.gamedata_rebuild)
            gamedata_only = plan_tag_impact(
                tag="game-1",
                base_contract=contract,
                merge_contract=contract,
                changed_paths=(ChangedPath("M", "gamedata_contract.py", "gamedata_contract.py"),),
                base_sources=None,
                merge_sources=None,
                base_rules=(),
                merge_rules=(),
            )
            self.assertFalse(gamedata_only.snapshot_rebuild)
            self.assertTrue(gamedata_only.gamedata_rebuild)
            empty_config = root / "empty.yaml"
            empty_config.write_text(
                yaml.safe_dump(
                    {
                        "modules": [
                            {
                                "name": "engine",
                                "path_windows": "Game/hw.dll",
                                "module_windows": "hw.dll",
                                "skills": [],
                                "symbols": [],
                            }
                        ]
                    },
                    sort_keys=False,
                ),
                encoding="utf-8",
            )
            empty = load_contract(empty_config, "game-2", root / "bin", artifactdir=root / "bin_artifacts")
            rules = parse_impact_registry(
                {"schema_version": 1, "rules": [{"paths": ["shared.py"], "scope": "all", "reason": "shared"}]}
            )
            noop = plan_tag_impact(
                tag="game-2",
                base_contract=empty,
                merge_contract=empty,
                changed_paths=(ChangedPath("M", "shared.py", "shared.py"),),
                base_sources=None,
                merge_sources=None,
                base_rules=rules,
                merge_rules=rules,
            )
            self.assertFalse(noop.has_actions)

    def test_skill_registry_and_binary_seeds(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            contract = self._contract(root)
            rules = parse_impact_registry(
                {
                    "schema_version": 1,
                    "rules": [{"paths": ["shared.py"], "scope": "skill", "skills": ["produce"], "reason": "shared"}],
                }
            )
            impact = plan_tag_impact(
                tag="game-1",
                base_contract=contract,
                merge_contract=contract,
                changed_paths=(
                    ChangedPath("M", ".claude/skills/produce/SKILL.md", ".claude/skills/produce/SKILL.md"),
                    ChangedPath("M", "shared.py", "shared.py"),
                ),
                base_sources=None,
                merge_sources=None,
                base_rules=rules,
                merge_rules=(),
                binary_changed_pairs=frozenset({("engine", "windows")}),
            )
            self.assertEqual(set(contract.nodes), set(impact.analysis_nodes))

    def test_artifact_change_maps_to_owner_and_downstream_and_rejects_unknown_path(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            contract = self._contract(root)
            impact = plan_tag_impact(
                tag="game-1",
                base_contract=contract,
                merge_contract=contract,
                changed_paths=(
                    ChangedPath(
                        "M",
                        "bin_artifacts/game-1/engine/A.windows.yaml",
                        "bin_artifacts/game-1/engine/A.windows.yaml",
                    ),
                ),
                base_sources=None,
                merge_sources=None,
                base_rules=(),
                merge_rules=(),
            )
            self.assertEqual(
                ("engine:windows:produce", "engine:windows:consume"),
                impact.analysis_nodes,
            )
            self.assertEqual(
                ("engine/A.windows.yaml", "engine/B.windows.yaml"),
                impact.invalidated_paths,
            )
            deleted = plan_tag_impact(
                tag="game-1",
                base_contract=contract,
                merge_contract=contract,
                changed_paths=(
                    ChangedPath(
                        "D",
                        "bin_artifacts/game-1/engine/A.windows.yaml",
                        None,
                    ),
                ),
                base_sources=None,
                merge_sources=None,
                base_rules=(),
                merge_rules=(),
            )
            self.assertEqual(impact.analysis_nodes, deleted.analysis_nodes)
            with self.assertRaisesRegex(ImpactPlanningError, "outside the formal contract"):
                plan_tag_impact(
                    tag="game-1",
                    base_contract=contract,
                    merge_contract=contract,
                    changed_paths=(
                        ChangedPath(
                            "A",
                            None,
                            "bin_artifacts/game-1/engine/Unknown.windows.yaml",
                        ),
                    ),
                    base_sources=None,
                    merge_sources=None,
                    base_rules=(),
                    merge_rules=(),
                )
            empty_config = root / "empty.yaml"
            empty_config.write_text(
                yaml.safe_dump(
                    {
                        "modules": [
                            {
                                "name": "engine",
                                "path_windows": "Game/hw.dll",
                                "module_windows": "hw.dll",
                                "skills": [],
                                "symbols": [],
                            }
                        ]
                    },
                    sort_keys=False,
                ),
                encoding="utf-8",
            )
            empty = load_contract(
                empty_config,
                "game-1",
                root / "bin",
                artifactdir=root / "bin_artifacts",
            )
            with self.assertRaisesRegex(ImpactPlanningError, "empty merge contract"):
                plan_tag_impact(
                    tag="game-1",
                    base_contract=contract,
                    merge_contract=empty,
                    changed_paths=(
                        ChangedPath(
                            "D",
                            "bin_artifacts/game-1/engine/A.windows.yaml",
                            None,
                        ),
                    ),
                    base_sources=None,
                    merge_sources=None,
                    base_rules=(),
                    merge_rules=(),
                )

    def test_bound_plan_digest_binds_shas_actions_and_digests(self):
        action = TagImpact("game-1", (), (), True, True, ("snapshot",))
        plan = BoundImpactPlan(
            "a" * 40,
            "b" * 40,
            "c" * 40,
            "d" * 40,
            "e" * 40,
            (action,),
            {"x": "y"},
        )
        document = json.loads(plan.canonical_bytes())
        self.assertEqual(PLAN_SCHEMA_VERSION, document["schema_version"])
        self.assertNotIn("mode", document["tags"][0])
        self.assertNotIn("fallback_reason", document["tags"][0])
        self.assertEqual(CACHE_MODE_WARM, document["cache_mode"])
        digest = document.pop("plan_sha256")
        encoded = json.dumps(document, sort_keys=True, separators=(",", ":")).encode("utf-8")
        self.assertEqual(hashlib.sha256(encoded).hexdigest(), digest)


class PrValidationGateTests(unittest.TestCase):
    def test_gate_truth_table(self):
        cases = (
            ({}, True),
            ({"has_actions": True, "has_hosted": True, "validate_hosted_result": "success"}, True),
            (
                {"has_actions": True, "has_analysis": True, "analyze_self_hosted_result": "success"},
                True,
            ),
            (
                {
                    "has_actions": True,
                    "has_analysis": True,
                    "has_hosted": True,
                    "validate_hosted_result": "success",
                    "analyze_self_hosted_result": "success",
                },
                True,
            ),
            (
                {
                    "has_actions": True,
                    "has_analysis": True,
                    "same_repository": False,
                    "fork_analysis_blocked_result": "failure",
                },
                False,
            ),
            ({"plan_result": "failure"}, False),
            ({"has_actions": True, "has_hosted": True}, False),
            ({"validate_hosted_result": "success"}, False),
        )
        defaults = {
            "plan_result": "success",
            "validate_hosted_result": "skipped",
            "analyze_self_hosted_result": "skipped",
            "fork_analysis_blocked_result": "skipped",
            "has_actions": False,
            "has_analysis": False,
            "has_hosted": False,
            "same_repository": True,
        }
        for overrides, expected in cases:
            with self.subTest(overrides=overrides):
                decision = evaluate_pr_validation(**(defaults | overrides))
                self.assertEqual(expected, decision.passed, decision.errors)

    def test_gate_rejects_unexpected_success_and_unknown_results(self):
        unexpected = evaluate_pr_validation(
            plan_result="success",
            validate_hosted_result="success",
            analyze_self_hosted_result="skipped",
            fork_analysis_blocked_result="skipped",
            has_actions=False,
            has_analysis=False,
            has_hosted=False,
            same_repository=True,
        )
        self.assertFalse(unexpected.passed)
        unknown = evaluate_pr_validation(
            plan_result="success",
            validate_hosted_result="queued",
            analyze_self_hosted_result="skipped",
            fork_analysis_blocked_result="skipped",
            has_actions=True,
            has_analysis=False,
            has_hosted=True,
            same_repository=True,
        )
        self.assertFalse(unknown.passed)


class BoundPlanValidationTests(unittest.TestCase):
    def _repository(self, root: Path) -> tuple[str, str, dict[str, str | None]]:
        subprocess.run(["git", "init", "-q", str(root)], check=True)
        subprocess.run(["git", "-C", str(root), "config", "user.email", "test@example.com"], check=True)
        subprocess.run(["git", "-C", str(root), "config", "user.name", "Test"], check=True)
        files = {
            "configs/config.yaml": b"gamevers:\n  - game-1\n",
            "configs/game-1.yaml": b"modules: []\n",
            "gamesymbol-impact.yaml": b"version: 1\nrules: []\n",
        }
        for relative, raw in files.items():
            path = root / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(raw)
        subprocess.run(["git", "-C", str(root), "add", "."], check=True)
        subprocess.run(["git", "-C", str(root), "commit", "-q", "-m", "base"], check=True)
        base_sha = subprocess.check_output(["git", "-C", str(root), "rev-parse", "HEAD"], text=True).strip()
        subprocess.run(["git", "-C", str(root), "commit", "-q", "--allow-empty", "-m", "merge"], check=True)
        merge_sha = subprocess.check_output(["git", "-C", str(root), "rev-parse", "HEAD"], text=True).strip()
        digests = {
            "merge_config_index": hashlib.sha256(files["configs/config.yaml"]).hexdigest(),
            "merge_registry": hashlib.sha256(files["gamesymbol-impact.yaml"]).hexdigest(),
            "merge_config:game-1": hashlib.sha256(files["configs/game-1.yaml"]).hexdigest(),
        }
        return base_sha, merge_sha, digests

    def _write_plan(
        self,
        path: Path,
        *,
        merge_sha: str,
        digests: dict[str, str | None],
        merge_bin_commit: str | None = None,
    ) -> None:
        action = TagImpact("game-1", (), (), True, False, ("snapshot",))
        plan = BoundImpactPlan(
            merge_sha,
            merge_sha,
            merge_sha,
            None,
            merge_bin_commit,
            (action,),
            digests,
        )
        path.write_bytes(plan.canonical_bytes())

    def test_materialize_rejects_tampered_plan_and_bound_merge_inputs(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            base_sha, merge_sha, digests = self._repository(root)
            plan_path = root / "plan.json"
            self._write_plan(plan_path, merge_sha=merge_sha, digests=digests)
            tampered = json.loads(plan_path.read_text(encoding="utf-8"))
            tampered["plan_sha256"] = "0" * 64
            plan_path.write_text(json.dumps(tampered), encoding="utf-8")
            with self.assertRaisesRegex(PrCliError, "plan digest mismatch"):
                materialize_from_plan(
                    repo_root=root,
                    plan_path=plan_path,
                    tag="game-1",
                    merge_ref=merge_sha,
                    bindir=root / "bin",
                    artifactdir=root / "bin_artifacts",
                )

            self._write_plan(plan_path, merge_sha=merge_sha, digests=digests)
            invalid_mode = json.loads(plan_path.read_text(encoding="utf-8"))
            invalid_mode["cache_mode"] = "cold"
            unsigned = {key: value for key, value in invalid_mode.items() if key != "plan_sha256"}
            invalid_mode["plan_sha256"] = hashlib.sha256(
                json.dumps(unsigned, sort_keys=True, separators=(",", ":")).encode("utf-8")
            ).hexdigest()
            plan_path.write_text(json.dumps(invalid_mode), encoding="utf-8")
            with self.assertRaisesRegex(PrCliError, "Invalid bound impact plan"):
                materialize_from_plan(
                    repo_root=root,
                    plan_path=plan_path,
                    tag="game-1",
                    merge_ref=merge_sha,
                    bindir=root / "bin",
                    artifactdir=root / "bin_artifacts",
                )

            self._write_plan(plan_path, merge_sha=merge_sha, digests=digests)
            with self.assertRaisesRegex(PrCliError, "merge SHA"):
                materialize_from_plan(
                    repo_root=root,
                    plan_path=plan_path,
                    tag="game-1",
                    merge_ref=base_sha,
                    bindir=root / "bin",
                    artifactdir=root / "bin_artifacts",
                )

            self._write_plan(plan_path, merge_sha=merge_sha, digests=digests, merge_bin_commit="f" * 40)
            with self.assertRaisesRegex(PrCliError, "bin gitlink"):
                materialize_from_plan(
                    repo_root=root,
                    plan_path=plan_path,
                    tag="game-1",
                    merge_ref=merge_sha,
                    bindir=root / "bin",
                    artifactdir=root / "bin_artifacts",
                )

            for key in (
                "merge_config_index",
                "merge_registry",
                "merge_config:game-1",
            ):
                with self.subTest(key=key):
                    mismatched = dict(digests)
                    mismatched[key] = "0" * 64
                    self._write_plan(plan_path, merge_sha=merge_sha, digests=mismatched)
                    with self.assertRaisesRegex(PrCliError, re.escape(key)):
                        materialize_from_plan(
                            repo_root=root,
                            plan_path=plan_path,
                            tag="game-1",
                            merge_ref=merge_sha,
                            bindir=root / "bin",
                            artifactdir=root / "bin_artifacts",
                        )


class ArtifactRebuildComparisonTests(unittest.TestCase):
    def test_artifact_only_plan_materializes_isolated_tree_and_compares_git_blob_bytes(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            repo = root / "repo"
            rebuilt = root / "rebuilt"
            repo.mkdir()
            subprocess.run(["git", "init", "-q", str(repo)], check=True)
            subprocess.run(["git", "-C", str(repo), "config", "user.email", "test@example.com"], check=True)
            subprocess.run(["git", "-C", str(repo), "config", "user.name", "Test"], check=True)
            (repo / "configs").mkdir()
            (repo / "configs" / "config.yaml").write_text("gamevers:\n  - game-1\n", encoding="utf-8")
            (repo / "configs" / "game-1.yaml").write_text(
                yaml.safe_dump(
                    {
                        "modules": [
                            {
                                "name": "engine",
                                "path_windows": "Game/hw.dll",
                                "module_windows": "hw.dll",
                                "skills": [{"name": "find", "expected_output": ["Demo.{platform}.yaml"]}],
                                "symbols": [{"name": "Demo", "category": "func"}],
                            }
                        ]
                    },
                    sort_keys=False,
                ),
                encoding="utf-8",
            )
            artifact = repo / "bin_artifacts" / "game-1" / "engine" / "Demo.windows.yaml"
            artifact.parent.mkdir(parents=True)
            artifact.write_bytes(canonical_symbol_yaml_bytes({"func_name": "Demo", "func_va": "0x10"}))
            subprocess.run(["git", "-C", str(repo), "add", "."], check=True)
            subprocess.run(["git", "-C", str(repo), "commit", "-q", "-m", "base"], check=True)
            base_sha = subprocess.check_output(["git", "-C", str(repo), "rev-parse", "HEAD"], text=True).strip()
            artifact.write_bytes(canonical_symbol_yaml_bytes({"func_name": "Demo", "func_va": "0x11"}))
            subprocess.run(["git", "-C", str(repo), "add", "."], check=True)
            subprocess.run(["git", "-C", str(repo), "commit", "-q", "-m", "merge"], check=True)
            merge_sha = subprocess.check_output(["git", "-C", str(repo), "rev-parse", "HEAD"], text=True).strip()
            expected_checkout_bytes = artifact.read_bytes()

            plan = build_plan(
                repo_root=repo,
                base_ref=base_sha,
                head_ref=merge_sha,
                merge_ref=merge_sha,
            )
            self.assertEqual(("engine:windows:find",), plan.tags[0].analysis_nodes)
            plan_path = root / "plan.json"
            plan_path.write_bytes(plan.canonical_bytes())
            self.assertEqual(
                (),
                materialize_from_plan(
                    repo_root=repo,
                    plan_path=plan_path,
                    tag="game-1",
                    merge_ref=merge_sha,
                    bindir=repo / "bin",
                    artifactdir=rebuilt,
                ),
            )
            rebuilt_artifact = rebuilt / "game-1" / "engine" / "Demo.windows.yaml"
            rebuilt_artifact.parent.mkdir(parents=True, exist_ok=True)
            rebuilt_artifact.write_bytes(expected_checkout_bytes)
            self.assertEqual(
                ("engine/Demo.windows.yaml",),
                compare_rebuilt_artifacts(
                    repo_root=repo,
                    plan_path=plan_path,
                    tag="game-1",
                    merge_ref=merge_sha,
                    bindir=repo / "bin",
                    artifactdir=rebuilt,
                ),
            )
            self.assertEqual(expected_checkout_bytes, artifact.read_bytes())
            rebuilt_artifact.write_bytes(canonical_symbol_yaml_bytes({"func_name": "Demo", "func_va": "0x12"}))
            with self.assertRaisesRegex(PrCliError, "inventory differs"):
                compare_rebuilt_artifacts(
                    repo_root=repo,
                    plan_path=plan_path,
                    tag="game-1",
                    merge_ref=merge_sha,
                    bindir=repo / "bin",
                    artifactdir=rebuilt,
                )


class GitBatchReadTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.repo = GitRepository(self.root)
        self.repo._run("init", "-q")
        self.repo._run("config", "user.email", "test@example.com")
        self.repo._run("config", "user.name", "Test")
        self.repo._run("config", "core.autocrlf", "false")
        self.files = {
            "plain.txt": b"plain\ntext\n",
            "empty.txt": b"",
            "nested/含 空格.bin": b"first\r\n\x00\xff\nlast",
        }
        for relative, raw in self.files.items():
            path = self.root / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(raw)
        self.repo._run("add", ".")
        self.repo._run("commit", "-q", "-m", "fixture")
        self.commit = self.repo.resolve("HEAD")

    def test_batch_preserves_blob_bytes_order_and_missing_paths(self):
        paths = (*self.files, "absent file", "plain.txt")
        (self.root / "plain.txt").write_bytes(b"uncommitted change")
        with patch("gamesymbol_snapshot_lib.pr_cli.subprocess.run", wraps=subprocess.run) as run:
            actual = self.repo.read_many(self.commit, paths)
        self.assertEqual({**self.files, "absent file": None}, actual)
        self.assertEqual([*self.files, "absent file"], list(actual))
        commands = [call.args[0][3:] for call in run.call_args_list]
        self.assertEqual(1, commands.count(["cat-file", "--batch"]))
        self.assertFalse(any(command[0] == "show" or command[:2] == ["cat-file", "-e"] for command in commands))
        batch = next(call for call in run.call_args_list if call.args[0][-1] == "--batch")
        self.assertEqual(len(actual), len(batch.kwargs["input"].splitlines()))

    def test_empty_batch_does_not_start_git(self):
        with patch("gamesymbol_snapshot_lib.pr_cli.subprocess.run") as run:
            self.assertEqual({}, self.repo.read_many("HEAD", ()))
        run.assert_not_called()

    def test_batch_resolves_symbolic_ref(self):
        self.assertEqual(self.files, self.repo.read_many("HEAD", tuple(self.files)))

    def test_batch_rejects_request_separators_before_starting_git(self):
        for separator in ("\r", "\n", "\0"):
            with self.subTest(separator=separator), patch("gamesymbol_snapshot_lib.pr_cli.subprocess.run") as run:
                with self.assertRaises(PrCliError):
                    self.repo.read_many(self.commit, (f"plain{separator}txt",))
                run.assert_not_called()

    def test_batch_rejects_non_blob_objects(self):
        with self.assertRaisesRegex(PrCliError, "blob"):
            self.repo.read_many(self.commit, ("nested",))

    def test_batch_rejects_invalid_or_incomplete_responses(self):
        oid = b"a" * 40
        invalid = (
            b"",
            b"bad header\n",
            b"not-an-object-id blob 0\n\n",
            oid + b" tree 0\n\n",
            oid + b" blob -1\n\n",
            oid + b" blob nan\n\n",
            oid + b" blob +1\nx\n",
            oid + b" blob " + b"9" * 5000 + b"\n\n",
            oid + b" blob 3\nxy",
            oid + b" blob 1\nx",
            oid + b" blob 1\nxx",
            oid + b" blob 0\n\nextra",
            b"wrong-request missing\n",
        )
        for raw in invalid:
            with self.subTest(raw=raw), patch.object(self.repo, "resolve", return_value=self.commit):
                result = subprocess.CompletedProcess([], 0, stdout=raw, stderr=b"")
                with patch("gamesymbol_snapshot_lib.pr_cli.subprocess.run", return_value=result):
                    with self.assertRaises(PrCliError):
                        self.repo.read_many(self.commit, ("plain.txt",))
        result = subprocess.CompletedProcess([], 0, stdout=oid + b" blob 0\n\n", stderr=b"")
        with patch.object(self.repo, "resolve", return_value=self.commit):
            with patch("gamesymbol_snapshot_lib.pr_cli.subprocess.run", return_value=result):
                with self.assertRaises(PrCliError):
                    self.repo.read_many(self.commit, ("plain.txt", "empty.txt"))

    def test_batch_git_failure_is_not_missing(self):
        result = subprocess.CompletedProcess([], 1, stdout=b"", stderr=b"object store unavailable")
        with patch.object(self.repo, "resolve", return_value=self.commit):
            with patch("gamesymbol_snapshot_lib.pr_cli.subprocess.run", return_value=result):
                with self.assertRaisesRegex(PrCliError, "object store unavailable"):
                    self.repo.read_many(self.commit, ("plain.txt",))


class ArtifactInventoryBatchTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.repo = GitRepository(self.root)
        self.repo._run("init", "-q")
        self.repo._run("config", "user.email", "test@example.com")
        self.repo._run("config", "user.name", "Test")
        self.repo._run("config", "core.autocrlf", "false")
        self.required = "engine/Required.windows.yaml"
        self.optional = "engine/Optional.windows.yaml"
        self.contract = SimpleNamespace(
            required_paths={self.required},
            optional_paths={self.optional},
            formal_paths={self.required, self.optional},
        )
        self.files = {self.required: b"required\r\n", self.optional: b"optional\x00\n"}
        for relative, raw in self.files.items():
            path = self.root / "bin_artifacts" / "game-1" / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(raw)
        self.repo._run("add", ".")
        self.repo._run("commit", "-q", "-m", "fixture")
        self.commit = self.repo.resolve("HEAD")

    def inventory(self, *, require_complete=True, contract=None):
        return _artifact_inventory(
            self.repo,
            "HEAD",
            "game-1",
            self.contract if contract is None else contract,
            require_complete=require_complete,
        )

    def test_complete_inventory_preserves_canonical_digest_with_one_batch(self):
        expected = tuple(
            {"path": path, "size": len(raw), "sha256": hashlib.sha256(raw).hexdigest()}
            for path, raw in sorted(self.files.items())
        )
        digest = hashlib.sha256(json.dumps(expected, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
        with patch("gamesymbol_snapshot_lib.pr_cli.subprocess.run", wraps=subprocess.run) as run:
            self.assertEqual((expected, digest), self.inventory())
        commands = [call.args[0][3:] for call in run.call_args_list]
        self.assertEqual(1, commands.count(["cat-file", "--batch"]))
        self.assertFalse(any(command[0] == "show" or command[:2] == ["cat-file", "-e"] for command in commands))

    def test_inventory_pins_ref_before_tree_enumeration(self):
        original = self.repo.list_files

        def move_head_after_listing(ref):
            paths = original(ref)
            path = self.root / "bin_artifacts" / "game-1" / self.required
            path.write_bytes(b"changed after tree enumeration")
            self.repo._run("add", ".")
            self.repo._run("commit", "-q", "-m", "move HEAD")
            return paths

        with patch.object(self.repo, "list_files", side_effect=move_head_after_listing):
            entries, _digest = self.inventory()
        entry = next(entry for entry in entries if entry["path"] == self.required)
        self.assertEqual(hashlib.sha256(self.files[self.required]).hexdigest(), entry["sha256"])

    def test_missing_required_is_rejected_only_in_complete_mode(self):
        self.repo._run("rm", "--", f"bin_artifacts/game-1/{self.required}")
        self.repo._run("commit", "-q", "-m", "remove required")
        with self.assertRaisesRegex(ImpactPlanningError, "inventory mismatch"):
            self.inventory()
        entries, _digest = self.inventory(require_complete=False)
        self.assertEqual([self.optional], [entry["path"] for entry in entries])

    def test_absent_optional_and_empty_inventory_remain_valid(self):
        self.repo._run("rm", "--", f"bin_artifacts/game-1/{self.optional}")
        self.repo._run("commit", "-q", "-m", "remove optional")
        entries, _digest = self.inventory()
        self.assertEqual([self.required], [entry["path"] for entry in entries])
        self.repo._run("rm", "--", f"bin_artifacts/game-1/{self.required}")
        self.repo._run("commit", "-q", "-m", "remove required")
        self.assertEqual(((), None), self.inventory(require_complete=False))
        self.assertEqual(
            ((), None),
            _artifact_inventory(self.repo, "HEAD", "game-1", None, require_complete=True),
        )
        empty = SimpleNamespace(required_paths=set(), optional_paths=set(), formal_paths=set())
        self.assertEqual(((), None), self.inventory(contract=empty))

    def test_extra_artifacts_and_artifacts_without_contract_are_rejected(self):
        with self.assertRaisesRegex(ImpactPlanningError, "no configured tag"):
            _artifact_inventory(self.repo, "HEAD", "game-1", None, require_complete=True)
        contract = SimpleNamespace(required_paths=set(), optional_paths=set(), formal_paths=set())
        for complete in (False, True):
            with self.subTest(complete=complete), self.assertRaisesRegex(ImpactPlanningError, "inventory mismatch"):
                self.inventory(require_complete=complete, contract=contract)

    def test_listed_artifact_missing_from_batch_fails_closed(self):
        missing = {f"bin_artifacts/game-1/{path}": None for path in self.files}
        with patch.object(self.repo, "read_many", return_value=missing):
            with self.assertRaisesRegex(ImpactPlanningError, "disappeared"):
                self.inventory()

    def test_bound_verification_reuses_config_bytes_and_rejects_single_byte_drift(self):
        _entries, digest = self.inventory()
        config = b"modules: []\n"
        action = {"tag": "game-1", "analysis_nodes": ["engine:windows:find"]}
        document = {
            "merge_sha": self.commit,
            "digests": {
                "merge_config:game-1": hashlib.sha256(config).hexdigest(),
                "merge_artifacts:game-1": digest,
            },
            "tags": [action],
        }
        with patch.object(self.repo, "read", return_value=config) as read:
            with patch("gamesymbol_snapshot_lib.pr_cli.load_contract", return_value=self.contract):
                self.assertEqual(action, verify_bound_tag_inputs(document, self.repo, "game-1"))
        read.assert_called_once_with(self.commit, "configs/game-1.yaml")
        path = self.root / "bin_artifacts" / "game-1" / self.optional
        path.write_bytes(b"Optional\x00\n")
        self.repo._run("add", ".")
        self.repo._run("commit", "-q", "-m", "single byte drift")
        document["merge_sha"] = self.repo.resolve("HEAD")
        with patch.object(self.repo, "read", return_value=config):
            with patch("gamesymbol_snapshot_lib.pr_cli.load_contract", return_value=self.contract):
                with self.assertRaisesRegex(PrCliError, "merge_artifacts:game-1"):
                    verify_bound_tag_inputs(document, self.repo, "game-1")


class GitDiffTests(unittest.TestCase):
    def test_parses_add_modify_delete_and_rename_with_nul_delimiters(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            subprocess.run(["git", "init", "-q", str(root)], check=True)
            subprocess.run(["git", "-C", str(root), "config", "user.email", "test@example.com"], check=True)
            subprocess.run(["git", "-C", str(root), "config", "user.name", "Test"], check=True)
            (root / "rename me.py").write_text("same\n", encoding="utf-8")
            (root / "modify.py").write_text("before\n", encoding="utf-8")
            (root / "delete.py").write_text("delete\n", encoding="utf-8")
            subprocess.run(["git", "-C", str(root), "add", "."], check=True)
            subprocess.run(["git", "-C", str(root), "commit", "-q", "-m", "base"], check=True)
            base = subprocess.check_output(["git", "-C", str(root), "rev-parse", "HEAD"], text=True).strip()
            subprocess.run(["git", "-C", str(root), "mv", "rename me.py", "renamed file.py"], check=True)
            (root / "modify.py").write_text("after\n", encoding="utf-8")
            (root / "delete.py").unlink()
            (root / "added.py").write_text("add\n", encoding="utf-8")
            subprocess.run(["git", "-C", str(root), "add", "-A"], check=True)
            subprocess.run(["git", "-C", str(root), "commit", "-q", "-m", "merge"], check=True)
            merge = subprocess.check_output(["git", "-C", str(root), "rev-parse", "HEAD"], text=True).strip()

            changes = GitRepository(root).changed_paths(base, merge)

            self.assertEqual({"A", "M", "D", "R"}, {change.status for change in changes})
            renamed = next(change for change in changes if change.status == "R")
            self.assertEqual(("rename me.py", "renamed file.py"), (renamed.old_path, renamed.new_path))


if __name__ == "__main__":
    unittest.main()
