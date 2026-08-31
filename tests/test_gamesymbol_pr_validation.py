from __future__ import annotations

import hashlib
import json
import re
import subprocess
import tempfile
import unittest
from pathlib import Path

import yaml

from gamesymbol_snapshot_lib.analysis_sources import (
    AnalysisSourceError,
    SourceIndex,
    build_source_index,
    validate_reference_consumers,
)
from gamesymbol_snapshot_lib.config import load_contract
from gamesymbol_snapshot_lib.errors import SnapshotConfigError
from gamesymbol_snapshot_lib.impact_registry import ImpactRegistryError, parse_impact_registry
from gamesymbol_snapshot_lib.materialize import materialize_baseline
from gamesymbol_snapshot_lib.operations import load_snapshot_context, pack_snapshot
from gamesymbol_snapshot_lib.pr_cli import (
    GitRepository,
    PrCliError,
    build_plan,
    compare_rebuilt_artifacts,
    materialize_from_plan,
)
from gamesymbol_snapshot_lib.pr_validation import (
    CACHE_MODE_WARM,
    BoundImpactPlan,
    ChangedPath,
    ImpactPlanningError,
    TagImpact,
    build_invalidation_plan,
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

    def test_untrusted_base_selects_full_rebuild(self):
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
                base_snapshot_trusted=False,
            )
            self.assertEqual("full-rebuild", impact.mode)
            self.assertEqual(set(contract.nodes), set(impact.analysis_nodes))
            self.assertIsNotNone(impact.fallback_reason)

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
            metadata_only = plan_tag_impact(
                tag="game-1",
                base_contract=contract,
                merge_contract=contract,
                changed_paths=(
                    ChangedPath(
                        "M",
                        "gamesymbols/game-1.metadata.yaml",
                        "gamesymbols/game-1.metadata.yaml",
                    ),
                ),
                base_sources=None,
                merge_sources=None,
                base_rules=(),
                merge_rules=(),
                metadata_changed=True,
            )
            self.assertEqual((), metadata_only.analysis_nodes)
            self.assertTrue(metadata_only.snapshot_rebuild)
            self.assertFalse(metadata_only.gamedata_rebuild)
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
            tracked_gamedata = plan_tag_impact(
                tag="game-1",
                base_contract=contract,
                merge_contract=contract,
                changed_paths=(
                    ChangedPath(
                        "M",
                        "gamedata/game-1/gamedata-manifest.json",
                        "gamedata/game-1/gamedata-manifest.json",
                    ),
                ),
                base_sources=None,
                merge_sources=None,
                base_rules=(),
                merge_rules=(),
                gamedata_changed=True,
            )
            self.assertFalse(tracked_gamedata.snapshot_rebuild)
            self.assertTrue(tracked_gamedata.gamedata_rebuild)

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

    def test_invalidation_plan_reuses_impact_planner(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            contract = self._contract(root)
            source = SourceIndex(
                {"ida_preprocessor_scripts/produce.py": frozenset({"engine:windows:produce"})},
                frozenset({"ida_preprocessor_scripts/produce.py"}),
            )
            plan = build_invalidation_plan(
                contract,
                contract,
                None,
                None,
                [ChangedPath("M", "ida_preprocessor_scripts/produce.py", "ida_preprocessor_scripts/produce.py")],
                root,
                base_sources=source,
                head_sources=source,
            )
            self.assertIn("engine/A.windows.yaml", plan.paths)
            self.assertIn("engine/B.windows.yaml", plan.paths)
            self.assertTrue(plan.reasons)

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

    def test_bound_plan_digest_binds_shas_actions_and_digests(self):
        action = TagImpact("game-1", "incremental", (), (), True, True, ("snapshot",))
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
            "gamesymbols/game-1.yaml": b"schema_version: 5\ngame_version: game-1\n",
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
            "merge_snapshot:game-1": hashlib.sha256(files["gamesymbols/game-1.yaml"]).hexdigest(),
            "merge_metadata:game-1": None,
            "merge_gamedata:game-1": None,
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
        action = TagImpact("game-1", "full-rebuild", (), (), True, False, ("snapshot",))
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


class MaterializationTests(unittest.TestCase):
    def test_selective_materialization_excludes_invalidated_and_clears_stale_yaml(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            config = root / "config.yaml"
            config.write_text(
                yaml.safe_dump(
                    {
                        "modules": [
                            {
                                "name": "engine",
                                "path_windows": "Game/hw.dll",
                                "module_windows": "hw.dll",
                                "skills": [
                                    {"name": "one", "expected_output": ["One.{platform}.yaml"]},
                                    {"name": "two", "expected_output": ["Two.{platform}.yaml"]},
                                ],
                                "symbols": [
                                    {"name": "One", "category": "func"},
                                    {"name": "Two", "category": "func"},
                                ],
                            }
                        ]
                    },
                    sort_keys=False,
                ),
                encoding="utf-8",
            )
            binary_module_dir = root / "base-bin" / "game-1" / "engine"
            artifact_module_dir = root / "base-artifacts" / "game-1" / "engine"
            write_pe32(binary_module_dir / "hw.dll")
            artifact_module_dir.mkdir(parents=True)
            (artifact_module_dir / "One.windows.yaml").write_text("func_name: One\nfunc_va: '0x10'\n", encoding="utf-8")
            (artifact_module_dir / "Two.windows.yaml").write_text("func_name: Two\nfunc_va: '0x20'\n", encoding="utf-8")
            snapshot = root / "base.yaml"
            pack_snapshot("game-1", root / "base-bin", config, snapshot, artifactdir=root / "base-artifacts")
            base = load_snapshot_context(
                snapshot, config, "game-1", root / "base-bin", artifactdir=root / "base-artifacts"
            )
            merge_contract = load_contract(config, "game-1", root / "merge-bin", artifactdir=root / "merge-artifacts")
            stale = root / "merge-artifacts" / "game-1" / "engine" / "Stale.yaml"
            stale.parent.mkdir(parents=True)
            stale.write_text("stale: true\n", encoding="utf-8")

            restored = materialize_baseline(
                base=base,
                merge_contract=merge_contract,
                artifactdir=root / "merge-artifacts",
                invalidated_paths=("engine/Two.windows.yaml",),
                mode="incremental",
            )

            self.assertEqual(("engine/One.windows.yaml",), restored)
            self.assertTrue((stale.parent / "One.windows.yaml").is_file())
            self.assertFalse((stale.parent / "Two.windows.yaml").exists())
            self.assertFalse(stale.exists())

    def test_full_rebuild_clears_yaml_without_restoring_base(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            config = AnalysisSourceIndexTests()._contract(root, "game-1")
            yaml_path = config.artifact_game_root / "engine" / "Demo.windows.yaml"
            yaml_path.parent.mkdir(parents=True)
            yaml_path.write_text("value: old\n", encoding="utf-8")
            self.assertEqual(
                (),
                materialize_baseline(
                    base=None,
                    merge_contract=config,
                    artifactdir=root / "bin_artifacts",
                    invalidated_paths=(),
                    mode="full-rebuild",
                ),
            )
            self.assertFalse(yaml_path.exists())

    def test_materialization_rejects_unsafe_invalidated_paths(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            contract = AnalysisSourceIndexTests()._contract(root, "game-1")
            with self.assertRaises(SnapshotConfigError):
                materialize_baseline(
                    base=None,
                    merge_contract=contract,
                    artifactdir=root / "bin_artifacts",
                    invalidated_paths=("../escape.yaml",),
                    mode="full-rebuild",
                )


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
