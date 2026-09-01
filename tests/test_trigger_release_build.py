import importlib.util
import json
import subprocess
import unittest
from pathlib import Path
from unittest.mock import patch


SCRIPT = Path(".claude/skills/trigger-release-build/scripts/trigger_release_build.py")
SPEC = importlib.util.spec_from_file_location("trigger_release_build", SCRIPT)
trigger = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(trigger)


def completed(command, *, stdout="", returncode=0, stderr=""):
    return subprocess.CompletedProcess(command, returncode, stdout=stdout, stderr=stderr)


class TestTriggerReleaseBuild(unittest.TestCase):
    def test_script_resolves_its_own_repository_root(self) -> None:
        expected = SCRIPT.resolve().parents[4]
        with patch.object(trigger, "run_command", return_value=completed([], stdout=f"{expected}\n")):
            self.assertEqual(expected, trigger.repository_root())

    def test_version_must_be_well_formed(self) -> None:
        self.assertEqual("v20260825a", trigger.require_version("v20260825a"))
        self.assertEqual("v20260825", trigger.require_version("v20260825"))
        with self.assertRaisesRegex(trigger.TriggerError, "invalid release version"):
            trigger.require_version("20260825a")
        with self.assertRaisesRegex(trigger.TriggerError, "invalid release version"):
            trigger.require_version("v123")

    def test_origin_repository_must_be_allowlisted(self) -> None:
        with patch.object(
            trigger,
            "run_command",
            return_value=completed([], stdout="https://github.com/other/repository.git\n"),
        ):
            with self.assertRaisesRegex(trigger.TriggerError, "not allowlisted"):
                trigger.require_repository(Path("."))

    def test_github_auth_failure_stops_before_permission_checks(self) -> None:
        with patch.object(trigger, "run_command", side_effect=trigger.TriggerError("gh auth status failed")) as run:
            with self.assertRaisesRegex(trigger.TriggerError, "auth status"):
                trigger.require_github_access(Path("."), "HLND2T/GoldSrc_VibeSignatures")
        run.assert_called_once_with(["gh", "auth", "status", "--hostname", "github.com"], Path("."))

    def test_release_state_selects_new_or_draft_resume(self) -> None:
        with patch.object(
            trigger,
            "run_command",
            side_effect=[
                completed([], returncode=2),
                completed([], returncode=1, stderr="gh: Not Found (HTTP 404)"),
            ],
        ):
            self.assertEqual(
                "new",
                trigger.release_state(Path("."), "HLND2T/GoldSrc_VibeSignatures", "v20260825a", "1" * 40),
            )

        with patch.object(
            trigger,
            "run_command",
            side_effect=[
                completed([], stdout=f"{'1' * 40}\trefs/tags/v20260825a\n"),
                completed([], stdout=json.dumps({"draft": True})),
            ],
        ):
            self.assertEqual(
                "resume",
                trigger.release_state(Path("."), "HLND2T/GoldSrc_VibeSignatures", "v20260825a", "1" * 40),
            )

    def test_release_state_refuses_mismatched_tag_and_published_release(self) -> None:
        with (
            patch.object(
                trigger,
                "run_command",
                side_effect=[
                    completed([], stdout=f"{'2' * 40}\trefs/tags/v20260825a\n"),
                    completed([], returncode=1, stderr="gh: Not Found (HTTP 404)"),
                ],
            ),
            self.assertRaisesRegex(trigger.TriggerError, "does not point"),
        ):
            trigger.release_state(Path("."), "HLND2T/GoldSrc_VibeSignatures", "v20260825a", "1" * 40)

        with (
            patch.object(
                trigger,
                "run_command",
                side_effect=[
                    completed([], stdout=f"{'1' * 40}\trefs/tags/v20260825a\n"),
                    completed([], stdout=json.dumps({"draft": False})),
                ],
            ),
            self.assertRaisesRegex(trigger.TriggerError, "already published"),
        ):
            trigger.release_state(Path("."), "HLND2T/GoldSrc_VibeSignatures", "v20260825a", "1" * 40)

    def test_no_active_release_run_allows_dispatch(self) -> None:
        with patch.object(trigger, "run_command", return_value=completed([], stdout="[]")):
            self.assertEqual(set(), trigger.require_no_duplicate(Path("."), "v20260825a"))

    def test_active_workflow_run_blocks_dispatch(self) -> None:
        responses = [
            completed(
                [],
                stdout=json.dumps(
                    [
                        {
                            "databaseId": 10,
                            "displayTitle": "Release build v20260825a",
                            "status": "in_progress",
                            "url": "https://run/10",
                        }
                    ]
                ),
            )
        ]
        with patch.object(trigger, "run_command", side_effect=responses):
            with self.assertRaisesRegex(trigger.TriggerError, "already active"):
                trigger.require_no_duplicate(Path("."), "v20260825a")

    def test_dispatch_uses_immutable_version_and_source(self) -> None:
        root = Path("repo")
        with patch.object(trigger, "run_command", return_value=completed([])) as run:
            trigger.dispatch(root, "v20260825a", "1" * 40)

        run.assert_called_once_with(
            [
                "gh",
                "workflow",
                "run",
                "release-build.yml",
                "--ref",
                "main",
                "-f",
                "version=v20260825a",
                "-f",
                f"source_sha={'1' * 40}",
            ],
            root,
        )

    def test_dispatch_stops_if_origin_main_advanced(self) -> None:
        with patch.object(trigger, "run_command", return_value=completed([], stdout=f"{'2' * 40}\trefs/heads/main\n")):
            with self.assertRaisesRegex(trigger.TriggerError, "advanced"):
                trigger.require_main_unchanged(Path("."), "1" * 40)

    def test_discover_run_reports_matching_new_run_url(self) -> None:
        run = {
            "databaseId": 12,
            "displayTitle": "Release build v20260825a",
            "status": "queued",
            "url": "https://run/12",
            "headSha": "1" * 40,
            "event": "workflow_dispatch",
        }
        with patch.object(trigger, "list_runs", return_value=[run]):
            self.assertEqual(
                "https://run/12",
                trigger.discover_run(Path("."), {11}, version="v20260825a", source_sha="1" * 40),
            )

    def test_execute_resolves_main_then_dispatches_and_reports_provenance(self) -> None:
        root = Path("repo")
        with (
            patch.object(trigger, "repository_root", return_value=root),
            patch.object(trigger, "require_repository", return_value="HLND2T/GoldSrc_VibeSignatures"),
            patch.object(trigger, "require_github_access") as access,
            patch.object(trigger, "resolve_source", return_value=("1" * 40, "subject")),
            patch.object(trigger, "release_state", return_value="new") as release_state,
            patch.object(trigger, "require_no_duplicate", return_value={10}),
            patch.object(trigger, "require_main_unchanged") as unchanged,
            patch.object(trigger, "dispatch") as dispatch,
            patch.object(trigger, "discover_run", return_value="https://run/11"),
        ):
            result = trigger.execute("v20260825a")

        self.assertEqual("v20260825a", result["version"])
        self.assertEqual("new", result["state"])
        self.assertEqual("https://run/11", result["run_url"])
        access.assert_called_once()
        release_state.assert_called_once_with(root, "HLND2T/GoldSrc_VibeSignatures", "v20260825a", "1" * 40)
        unchanged.assert_called_once_with(root, "1" * 40)
        dispatch.assert_called_once_with(root, "v20260825a", "1" * 40)

    def test_main_reports_selected_state(self) -> None:
        result = {
            "version": "v20260825a",
            "state": "new",
            "source_sha": "1" * 40,
            "subject": "subject",
            "run_url": "https://run/11",
        }
        with patch.object(trigger, "execute", return_value=result) as execute, patch("builtins.print") as output:
            self.assertEqual(0, trigger.main(["v20260825a"]))

        execute.assert_called_once_with("v20260825a")
        output.assert_any_call("Release state: new")


if __name__ == "__main__":
    unittest.main()
