import io
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import release_notes as release

NOTES = "## English\n- [Renderer] Fix cleanup.\n\n## \u4e2d\u6587\n- [Renderer] \u4fee\u590d\u6e05\u7406\u3002\n"


class ContextTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.git("init", "-q")
        self.git("config", "user.email", "test@example.invalid")
        self.git("config", "user.name", "Test")
        self.commit("initial")
        self.git("tag", "v1")
        self.commit("fix cleanup")
        self.git("tag", "v2")
        self.head = self.git("rev-parse", "HEAD").strip()

    def git(self, *args):
        return subprocess.check_output(["git", "-C", str(self.root), *args], text=True)

    def commit(self, message):
        with (self.root / "code.cpp").open("a") as source:
            source.write(message + "\n")
        self.git("add", ".")
        self.git("commit", "-qm", message)

    def test_baseline_ignores_current_drafts_prereleases_and_nonancestors(self):
        self.git("checkout", "-q", "--orphan", "unrelated")
        self.commit("unrelated")
        self.git("tag", "v-other")
        self.git("checkout", "-q", "v2")
        releases = [
            {"tag_name": "missing-tag", "published_at": "2026-06-06"},
            {"tag_name": "v2", "published_at": "2026-06-05"},
            {"tag_name": "v-other", "published_at": "2026-06-04"},
            {"tag_name": "v2", "published_at": "2026-06-03", "draft": True},
            {"tag_name": "v2", "published_at": "2026-06-02", "prerelease": True},
            {"tag_name": "v1", "published_at": "2026-06-01"},
        ]
        self.assertEqual("v1", release.select_baseline(self.root, releases, "v2", self.head))

    def test_first_release_and_changed_source(self):
        context = release.build_context(self.root, [], "v2", self.head)
        self.assertIn("First release", context)
        self.assertIn("fix cleanup", context)
        self.assertLessEqual(len(context.encode("utf-8")), release.MAX_CONTEXT_BYTES)

    def test_context_is_utf8_bounded_and_excludes_thirdparty_diff(self):
        thirdparty = self.root / "thirdparty"
        thirdparty.mkdir()
        (thirdparty / "vendor.cpp").write_text("unique-vendor-body", encoding="utf-8")
        (self.root / "code.cpp").write_text("\u4e2d\u6587" * 120000, encoding="utf-8")
        self.git("add", ".")
        self.git("commit", "-qm", "large source change")
        head = self.git("rev-parse", "HEAD").strip()
        context = release.build_context(self.root, [{"tag_name": "v1", "body": "style"}], "v3", head)
        self.assertLessEqual(len(context.encode("utf-8")), release.MAX_CONTEXT_BYTES)
        self.assertIn("TRUNCATED", context)
        self.assertNotIn("unique-vendor-body", context)

    def test_symbol_artifacts_are_evidence_and_initial_context_is_read_only(self):
        artifact = self.root / "bin_artifacts" / "hl-8684" / "symbol.yaml"
        artifact.parent.mkdir(parents=True)
        artifact.write_text("symbol-evidence-marker: fixed\n", encoding="utf-8")
        self.git("add", ".")
        self.git("commit", "-qm", "fix a signature")
        head = self.git("rev-parse", "HEAD").strip()
        before = {p.relative_to(self.root): p.read_bytes() for p in self.root.rglob("*") if p.is_file()}
        context = release.build_context(self.root, [{"tag_name": "v1", "body": "style"}], "v20260910a", head)
        self.assertIn("symbol-evidence-marker", context)
        self.assertLessEqual(len(context.encode("utf-8")), release.INITIAL_CONTEXT_BYTES)
        self.assertEqual(
            before, {p.relative_to(self.root): p.read_bytes() for p in self.root.rglob("*") if p.is_file()}
        )

    def test_cli_explicit_source_without_current_tag_and_default_claude(self):
        with tempfile.TemporaryDirectory() as temporary:
            context_path = Path(temporary) / "context.txt"
            output = Path(temporary) / "notes.md"
            shared = [
                "--repo-root",
                str(self.root),
                "--repository",
                "owner/repo",
                "--version",
                "v20260910a",
                "--source-sha",
                self.head,
            ]
            with (
                patch.object(release.GitHub, "paginate", return_value=[]),
                patch.dict(os.environ, {"GH_TOKEN": "fake"}),
            ):
                self.assertEqual(0, release.main(["context", *shared, "--output", str(context_path)]))
            with (
                patch.dict(
                    os.environ,
                    {name: value for name, value in os.environ.items() if not name.startswith("RELEASE_NOTES_")},
                    clear=True,
                ),
                patch.object(release, "generate_notes", return_value=NOTES) as generate,
            ):
                self.assertEqual(
                    0, release.main(["notes", *shared, "--input", str(context_path), "--output", str(output)])
                )
                self.assertEqual("claude", generate.call_args.args[1])
                self.assertEqual(self.head, generate.call_args.args[-1])
            self.assertEqual(NOTES, output.read_text(encoding="utf-8"))
            shared[-1] = "f" * 40
            with patch.object(release, "generate_notes") as generate:
                self.assertEqual(
                    1, release.main(["notes", *shared, "--input", str(context_path), "--output", str(output)])
                )
                generate.assert_not_called()


class NotesTests(unittest.TestCase):
    def test_safe_diagnostics_distinguish_failures_without_exception_text(self):
        cases = [
            (FileNotFoundError("private-key /private/path"), "cli_or_file_missing"),
            (PermissionError("private-key"), "permission_denied"),
            (subprocess.TimeoutExpired("secret-command", 600, output="private-key"), "cli_timeout"),
            (subprocess.CalledProcessError(7, "secret-command", output="private-key"), "cli_exit=7"),
            (json.JSONDecodeError("private-key", "private-context", 0), "invalid_json"),
            (
                release.ReleaseError("Release notes must contain exactly the two language sections"),
                "notes_language_sections",
            ),
            (release.ReleaseError("private-key https://private.invalid private-context"), "release_error"),
        ]
        for error, expected in cases:
            with self.subTest(expected=expected):
                self.assertEqual(expected, release.safe_diagnostic(error))

    def test_real_cli_failure_logs_only_allowlisted_hints(self):
        with tempfile.TemporaryDirectory() as root:
            command = [
                sys.executable,
                "-c",
                (
                    "import sys; print('API Error: 401 private-key private-context'); "
                    "print('authentication_error https://private.invalid', file=sys.stderr); sys.exit(3)"
                ),
            ]
            with self.assertRaises(subprocess.CalledProcessError) as caught:
                release.run_cli_process(command, "", root, os.environ.copy())
            error = caught.exception
            self.assertEqual("cli_exit=3; output_hint=http_401,authentication", release.safe_diagnostic(error))
            self.assertIsNone(error.output)
            self.assertIsNone(error.stderr)
            with (
                patch.object(release, "run_cli_once", side_effect=error),
                patch("sys.stderr", new_callable=io.StringIO) as log,
                self.assertRaises(release.ReleaseError),
            ):
                release.generate_notes("private-context", "claude", "model", "https://private.invalid", "private-key")
            self.assertEqual(2, log.getvalue().count("cli_exit=3"))
            for secret in ("private-key", "private-context", "https://private.invalid", "import sys"):
                self.assertNotIn(secret, log.getvalue())

    def test_provider_error_hints_and_untrusted_output(self):
        with self.assertRaises(release.ReleaseError) as caught:
            release.claude_result(json.dumps({"is_error": True, "result": "API Error: 429 private-key"}))
        self.assertEqual("provider_error; output_hint=http_429", release.safe_diagnostic(caught.exception))
        self.assertEqual("unclassified", release.cli_output_hint("private-key HTTP 123 secret 401"))
        self.assertEqual("cli_arguments", release.cli_output_hint("error: unknown option '--private-key'"))
        with self.assertRaises(release.ReleaseError) as caught:
            release.validate_codex_events(json.dumps({"type": "turn.failed", "error": {"message": "HTTP 503 secret"}}))
        self.assertEqual("provider_error; output_hint=http_503", release.safe_diagnostic(caught.exception))

    def test_duplicate_sections_reserved_marker_and_oversize_fail(self):
        for text in (
            NOTES + "\n## English\nextra",
            NOTES + "<!-- gsvibe-release-identity: {} -->",
            NOTES + "x" * release.MAX_NOTES_BYTES,
            NOTES + "```code```",
        ):
            with self.subTest(text=text[:40]), self.assertRaises(release.ReleaseError):
                release.validate_notes(text)

    def test_invalid_provider_and_endpoint(self):
        for provider, endpoint in (
            ("other", "https://example.invalid"),
            ("codex", "http://example.invalid"),
            ("claude", "https://user:pass@example.invalid"),
        ):
            with self.subTest(provider=provider, endpoint=endpoint), self.assertRaises(release.ReleaseError):
                release.validate_ai_settings(provider, "model", endpoint, "secret")

    def test_missing_key_or_model(self):
        for model, key in (("", "key"), ("model", "")):
            with self.assertRaises(release.ReleaseError):
                release.validate_ai_settings("codex", model, "https://api.invalid", key)

    def test_real_subprocess_timeout_and_failure(self):
        with tempfile.TemporaryDirectory() as root:
            with patch.object(release, "CLI_TIMEOUT_SECONDS", 0.1), self.assertRaises(subprocess.TimeoutExpired):
                release.run_cli_process(
                    [sys.executable, "-c", "import time; time.sleep(30)"], "", root, os.environ.copy()
                )
            with self.assertRaises(subprocess.CalledProcessError):
                release.run_cli_process([sys.executable, "-c", "raise SystemExit(3)"], "", root, os.environ.copy())

    def test_retry_on_failure_timeout_and_empty_output(self):
        for failure in (
            subprocess.TimeoutExpired("cli", 600),
            subprocess.CalledProcessError(1, "cli"),
            release.ReleaseError("empty"),
        ):
            with (
                self.subTest(failure=type(failure).__name__),
                patch.object(release, "run_cli_once", side_effect=[failure, NOTES]) as run,
            ):
                self.assertEqual(
                    NOTES, release.generate_notes("context", "claude", "model", "https://api.invalid", "key")
                )
                self.assertEqual(2, run.call_count)

    def test_exhausted_retries_fail_closed(self):
        with patch.object(release, "run_cli_once", side_effect=release.ReleaseError("empty")) as run:
            with self.assertRaises(release.ReleaseError):
                release.generate_notes("context", "codex", "model", "https://api.invalid", "key")
            self.assertEqual(2, run.call_count)

    def test_empty_or_nonbilingual_notes_fail(self):
        for text in (
            "",
            "   ",
            "error: authentication failed",
            "## English\nOnly English",
            "## English\n\n## \u4e2d\u6587\n",
            "## English\nText\n\n## \u4e2d\u6587\n",
        ):
            with self.assertRaises(release.ReleaseError):
                release.validate_notes(text)

    def test_codex_only_accepts_allowlisted_git_tool_events(self):
        release.validate_codex_events(
            json.dumps(
                {
                    "type": "item.completed",
                    "item": {"type": "mcp_tool_call", "server": "release_git", "tool": "git_history"},
                }
            )
        )
        for item_type in ("command_execution", "mcp_tool_call", "file_change", "web_search"):
            events = json.dumps({"type": "item.completed", "item": {"type": item_type}})
            with self.assertRaises(release.ReleaseError):
                release.validate_codex_events(events)

    def test_claude_error_result_is_rejected(self):
        with self.assertRaises(release.ReleaseError):
            release.claude_result(json.dumps({"is_error": True, "result": NOTES}))
        self.assertEqual(NOTES, release.claude_result(json.dumps({"is_error": False, "result": NOTES})))

    def test_cli_adapters_isolate_credentials_and_parse_results(self):
        def fake_process(command, context, work, environment):
            self.assertNotIn("GH_TOKEN", environment)
            self.assertNotIn("GITHUB_TOKEN", environment)
            self.assertNotIn("ACTIONS_RUNTIME_TOKEN", environment)
            self.assertNotIn("private-key", command)
            self.assertEqual([], list(work.iterdir()))
            if command[0] == "codex":
                self.assertEqual("private-key", environment["RELEASE_NOTES_API_KEY"])
                output = Path(command[command.index("--output-last-message") + 1])
                output.write_text(NOTES, encoding="utf-8")
                return json.dumps({"type": "item.completed", "item": {"type": "agent_message", "text": NOTES}})
            self.assertEqual("private-key", environment["ANTHROPIC_API_KEY"])
            self.assertEqual("", command[command.index("--tools") + 1])
            return json.dumps({"is_error": False, "result": NOTES})

        with (
            patch.dict(os.environ, {"GH_TOKEN": "github-secret", "ACTIONS_RUNTIME_TOKEN": "artifact-secret"}),
            patch.object(release, "run_cli_process", side_effect=fake_process),
        ):
            for provider in ("codex", "claude"):
                self.assertEqual(
                    NOTES, release.run_cli_once("context", provider, "model", "https://api.invalid", "private-key")
                )

    def test_credential_in_model_output_is_rejected(self):
        with (
            patch.object(release, "run_cli_once", return_value=NOTES + "private-key"),
            self.assertRaises(release.ReleaseError),
        ):
            release.generate_notes("context", "claude", "model", "https://api.invalid", "private-key")


if __name__ == "__main__":
    unittest.main()
