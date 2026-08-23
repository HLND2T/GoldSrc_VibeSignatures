#!/usr/bin/env python3
"""Run exactly one declared test group, or their disjoint union."""

from __future__ import annotations

import argparse
import unittest
from pathlib import Path

GROUP_FILES = {
    "unit": (
        "test_agent_runner.py",
        "test_config_and_depot.py",
        "test_binary_and_symbols.py",
        "test_ida_mcp_session.py",
        "test_generate_reference_yaml.py",
        "test_format_repo_files.py",
        "test_ida_llm_decompile.py",
        "test_ida_skill_preprocessor.py",
        "test_cvar_hooks_preprocessor.py",
        "test_analysis_planner.py",
        "test_process_api.py",
        "test_process_reporter.py",
        "test_process_reporter_factory.py",
        "test_snapshot_candidate.py",
        "test_gamesymbol_snapshot_config.py",
        "test_gamesymbol_pr_validation.py",
        "test_gamesymbol_metadata.py",
        "test_gamedata.py",
        "test_release_workflow.py",
        "test_decrypt_blob.py",
    ),
    "redis-integration": (
        "test_process_reporter_redis.py",
        "test_process_scheduler_redis.py",
        "test_process_status_reader_redis.py",
    ),
    "repository-contract": ("test_repository_contract.py",),
    "ida-integration": ("test_ida_integration.py",),
}


def validate_membership(root: Path) -> None:
    discovered = {path.name for path in root.glob("test_*.py") if path.name != "test_support.py"}
    declared = [name for files in GROUP_FILES.values() for name in files]
    duplicates = {name for name in declared if declared.count(name) > 1}
    missing = discovered - set(declared)
    stale = set(declared) - discovered
    if duplicates or missing or stale:
        raise RuntimeError(f"Invalid test group membership: duplicates={duplicates}, missing={missing}, stale={stale}")


def main(argv=None):
    parser = argparse.ArgumentParser(description="Run GoldSrc VibeSignatures tests")
    parser.add_argument("suite", choices=[*GROUP_FILES, "all"])
    parser.add_argument("-b", "--buffer", action="store_true")
    parser.add_argument("--durations", type=int, default=None)
    args = parser.parse_args(argv)
    root = Path(__file__).resolve().parent
    validate_membership(root)
    groups = tuple(GROUP_FILES) if args.suite == "all" else (args.suite,)
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()
    for group in groups:
        for filename in GROUP_FILES[group]:
            suite.addTests(loader.discover(str(root), pattern=filename, top_level_dir=str(root.parent)))
    result = unittest.TextTestRunner(verbosity=2, buffer=args.buffer).run(suite)
    return 0 if result.wasSuccessful() else 1


if __name__ == "__main__":
    raise SystemExit(main())
