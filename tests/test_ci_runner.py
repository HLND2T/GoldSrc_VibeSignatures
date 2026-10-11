import json
import os
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest.mock import patch

import ci_runner as ci


class CiRunnerTests(unittest.TestCase):
    def test_release_tracked_and_rebuild_use_real_cli_and_keep_manifest_contract(self):
        from tests.test_release_bundle import ReleaseBundleTests

        source = Path(ci.__file__).parent
        for mode in ("tracked", "rebuild"):
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                repo, generated, sha = ReleaseBundleTests().fixture(root)
                runner_temp = root / "runner-temp"
                runner_temp.mkdir()
                bundle = runner_temp / "idb-cache-selection"
                bundle.mkdir()
                selection = generated / "evidence" / "cache-selection.json"
                (bundle / "cache-selection.json").write_bytes(selection.read_bytes())
                variables = {
                    "GITHUB_WORKSPACE": str(repo),
                    "RUNNER_TEMP": str(runner_temp),
                    "SOURCE_SHA": sha,
                    "SOURCE_ARTIFACT_MODE": mode,
                    "VERSION": "v20260831a",
                    "BUILD_ID": "run-1-1",
                    "WORKFLOW_RUN_URL": "https://example.invalid/run/1",
                    "IDA_RUNTIME_PATH": str(generated / "evidence" / "ida-runtime.json"),
                    "PRODUCER_SELECTION_SHA256": ci.sha256_file(selection),
                }

                def invoke(args, *, capture=False, repo=repo):
                    self.assertEqual(["uv", "run", "python"], args[:3])
                    result = subprocess.run(
                        [sys.executable, str(source / args[3]), *map(str, args[4:])],
                        cwd=repo,
                        check=True,
                        text=True,
                        encoding="utf-8",
                        capture_output=True,
                    )
                    return result.stdout.strip() if capture else None

                def emit(values, *, environment=False):
                    if environment:
                        os.environ.update(values)

                with (
                    patch.dict(os.environ, variables),
                    patch.object(ci, "command", side_effect=invoke),
                    patch.object(ci, "emit", side_effect=emit),
                ):
                    if mode == "tracked":
                        ci.release_bind()
                    else:
                        os.environ["RELEASE_ARTIFACT_ROOT"] = str(repo / "bin_artifacts")
                    # Git timestamp lookup is read-only and shares the fixture's cwd.
                    real_command = ci.command

                    def command(args, repo=repo, real_command=real_command, **kwargs):
                        if args[0] == "git":
                            return subprocess.check_output(list(map(str, args)), cwd=repo, text=True).strip()
                        return real_command(args, **kwargs)

                    with patch.object(ci, "command", side_effect=command):
                        ci.release_datasets()
                        ci.release_bundle()
                manifest = json.loads(
                    (runner_temp / "release-bundle" / "release-manifest-v20260831a.json").read_bytes()
                )
                self.assertEqual(mode, manifest["source_artifact_mode"])
                self.assertEqual(mode == "rebuild", "warm_idb_selection_sha256" in manifest)

    def test_tail_concurrency_is_decimal_and_bounded(self):
        for value in ("0", "33", "2.0", "-1", "", " 2", "+2", "0x2"):
            with (
                patch.dict(os.environ, GSVIBE_TAIL_MAX_CONCURRENCY=value),
                self.subTest(value=value),
                self.assertRaises(ValueError),
            ):
                ci.tail_concurrency()
        with patch.dict(os.environ, {}, clear=True):
            self.assertEqual(2, ci.tail_concurrency())

    def test_parallel_stage_waits_for_siblings_and_bounds_admission(self):
        lock = threading.Lock()
        running = peak = 0
        completed = []

        def action(tag):
            nonlocal running, peak
            with lock:
                running += 1
                peak = max(peak, running)
            time.sleep(0.02)
            with lock:
                completed.append(tag)
                running -= 1
            if tag == "bad":
                raise ValueError("injected failure")

        with self.assertRaisesRegex(ValueError, "bad"):
            ci.parallel_tags(["one", "bad", "three", "four"], action, 2, "materialize")
        self.assertEqual(2, peak)
        self.assertCountEqual(["one", "bad", "three", "four"], completed)

    def test_clean_bin_rejects_wrong_repository_before_mutation(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "bin").mkdir()
            with patch.dict(os.environ, GITHUB_WORKSPACE=str(root)):
                with (
                    patch.object(ci, "command", return_value=str(root)) as command,
                    self.assertRaisesRegex(ValueError, "unexpected bin"),
                ):
                    ci.clean_bin()
                self.assertEqual(1, command.call_count)

    def test_pr_pipeline_keeps_barriers_trusted_tools_and_isolated_artifacts(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            bundle = root / "gamesymbol-validation"
            bundle.mkdir()
            plan = {"tags": [{"tag": tag, "analysis_nodes": [tag + ":node"]} for tag in ("game-1", "game-2")]}
            (bundle / "plan.json").write_text(json.dumps(plan), encoding="utf-8")
            calls = []
            with (
                patch.dict(
                    os.environ,
                    RUNNER_TEMP=str(root),
                    GITHUB_WORKSPACE=str(root / "checkout"),
                    GITHUB_RUN_ID="1",
                    GITHUB_RUN_ATTEMPT="1",
                ),
                patch.object(ci, "tool", side_effect=lambda *args, **kwargs: calls.append((args, kwargs))),
                patch.object(ci, "command") as git,
            ):
                ci.pr_validate()
            analysis_index = next(
                i for i, (args, _) in enumerate(calls) if args[0] == "ida_analyze_bin.py" and "-bindir" in args
            )
            materialize = [
                (i, kwargs)
                for i, (args, kwargs) in enumerate(calls)
                if args[:2] == ("gamesymbol_pr_validation.py", "materialize")
            ]
            compare = [
                (i, kwargs)
                for i, (args, kwargs) in enumerate(calls)
                if args[:2] == ("gamesymbol_pr_validation.py", "compare")
            ]
            self.assertEqual(2, len(materialize))
            self.assertEqual(2, len(compare))
            self.assertTrue(all(i < analysis_index for i, _ in materialize))
            self.assertTrue(all(i > analysis_index for i, _ in compare))
            self.assertTrue(
                all(
                    kwargs["project"] == root / "checkout" / ".trusted-validator" for _, kwargs in materialize + compare
                )
            )
            self.assertEqual(2, sum(args[:2] == ("gamesymbol_candidate.py", "mark") for args, _ in calls))
            self.assertFalse(any(args[:2] == ("gamesymbol_candidate.py", "publish") for args, _ in calls))
            git.assert_called_once_with(["git", "diff", "--exit-code", "--", "bin_artifacts"])

    def test_bad_materialization_blocks_analysis_but_runs_all_tags(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            bundle = root / "gamesymbol-validation"
            bundle.mkdir()
            (bundle / "plan.json").write_text(
                json.dumps({"tags": [{"tag": tag, "analysis_nodes": ["node"]} for tag in ("game-1", "game-2")]})
            )
            materialized = []
            analyzed = []

            def execute(script, *args, **kwargs):
                if script == "gamesymbol_pr_validation.py":
                    tag = args[args.index("-tag") + 1]
                    materialized.append(tag)
                    if tag == "game-1":
                        raise ValueError("bad materialization")
                if script == "ida_analyze_bin.py" and "-bindir" in args:
                    analyzed.append(args)

            with (
                patch.dict(
                    os.environ,
                    RUNNER_TEMP=str(root),
                    GITHUB_WORKSPACE=str(root / "checkout"),
                    GITHUB_RUN_ID="1",
                    GITHUB_RUN_ATTEMPT="1",
                ),
                patch.object(ci, "tool", side_effect=execute),
                self.assertRaisesRegex(ValueError, "materialization"),
            ):
                ci.pr_validate()
            self.assertCountEqual(["game-1", "game-2"], materialized)
            self.assertEqual([], analyzed)

    def test_clean_bin_rejects_link_escape(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            checkout = root / "checkout"
            outside = root / "outside"
            checkout.mkdir()
            outside.mkdir()
            try:
                (checkout / "bin").symlink_to(outside, target_is_directory=True)
            except OSError as exc:
                self.skipTest(str(exc))
            with patch.dict(os.environ, GITHUB_WORKSPACE=str(checkout)), patch.object(ci, "command") as command:
                with self.assertRaises(ValueError):
                    ci.clean_bin()
                command.assert_not_called()

    def test_pr_restore_checks_producer_digest_before_running(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            bundle = root / "gamesymbol-validation"
            bundle.mkdir()
            (bundle / "cache-selection.sha256").write_text("a" * 64)
            with (
                patch.dict(os.environ, RUNNER_TEMP=str(root), PRODUCER_SELECTION_SHA256="b" * 64),
                patch.object(ci, "tool") as tool,
            ):
                with self.assertRaisesRegex(ValueError, "digest mismatch"):
                    ci.pr_restore()
                tool.assert_not_called()

    def test_tracked_release_never_restores_idb(self):
        with patch.dict(os.environ, SOURCE_ARTIFACT_MODE="tracked"), patch.object(ci, "tool") as tool:
            ci.release_restore()
            tool.assert_not_called()

    def test_object_fetch_checks_actual_selection_digest_before_creating_client(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            bundle = root / "gamesymbol-validation"
            bundle.mkdir()
            (bundle / "cache-selection.sha256").write_text("a" * 64)
            (bundle / "cache-selection.json").write_text("{}")
            with (
                patch.dict(os.environ, RUNNER_TEMP=str(root), PRODUCER_SELECTION_SHA256="a" * 64),
                patch("idb_cache_s3.transport_from_environment") as client,
                self.assertRaises(ValueError),
            ):
                ci.transfer_idb_selection()
            client.assert_not_called()

    def test_host_tools_exclude_workflow_dependency_environment(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            paths = [str(root / ".venv" / "bin"), str(root / ".ci-tools" / ".venv" / "bin"), str(root / "host")]
            with (
                patch.dict(os.environ, GITHUB_WORKSPACE=str(root), PATH=os.pathsep.join(paths)),
                patch.object(ci.shutil, "which", return_value=str(root / "host" / "python")) as which,
            ):
                ci.host_tool("python")
                self.assertEqual(str(root / "host"), which.call_args.kwargs["path"])

    def test_failed_commands_do_not_print_credential_arguments(self):
        error = subprocess.CalledProcessError(1, ["tool", "secret-value"])
        with patch.dict(ci.COMMANDS, {"test": lambda: (_ for _ in ()).throw(error)}), patch("sys.stderr") as stderr:
            self.assertEqual(1, ci.main(["test"]))
            self.assertNotIn("secret-value", str(stderr.write.call_args_list))
