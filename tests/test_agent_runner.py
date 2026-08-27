from __future__ import annotations

import io
import json
import subprocess
import unittest
from pathlib import Path
from unittest.mock import patch

import agent_runner


class _FakePipe:
    def __init__(self, chunks: list[str]) -> None:
        self._chunks = list(chunks)
        self.closed = False

    def readline(self) -> str:
        return self._chunks.pop(0) if self._chunks else ""

    def close(self) -> None:
        self.closed = True


class _FakeStdin:
    def __init__(self) -> None:
        self.writes: list[str] = []
        self.closed = False

    def write(self, data: str) -> int:
        self.writes.append(data)
        return len(data)

    def flush(self) -> None:
        return None

    def close(self) -> None:
        self.closed = True


class _FakePopen:
    def __init__(
        self,
        *,
        stdout_chunks: list[str] | None = None,
        stderr_chunks: list[str] | None = None,
        returncode: int = 0,
    ) -> None:
        self.stdout = _FakePipe(stdout_chunks or [])
        self.stderr = _FakePipe(stderr_chunks or [])
        self.stdin = _FakeStdin()
        self.returncode = returncode
        self.killed = False
        self.wait_calls: list[int | None] = []

    def wait(self, timeout: int | None = None) -> int:
        self.wait_calls.append(timeout)
        return self.returncode

    def kill(self) -> None:
        self.killed = True


class _TimeoutPopen(_FakePopen):
    def wait(self, timeout: int | None = None) -> int:
        self.wait_calls.append(timeout)
        if len(self.wait_calls) == 1:
            raise subprocess.TimeoutExpired(["codex"], timeout)
        return self.returncode


class AgentRunnerConfigurationTests(unittest.TestCase):
    def test_project_configs_define_runner_contracts(self) -> None:
        claude_settings_path = Path(".claude/skill_runner.settings.json")
        codex_config_path = Path(".codex/skill_runner.config.toml")
        opencode_config_path = Path(".opencode/skill_runner.config.json")
        for config_path in (claude_settings_path, codex_config_path, opencode_config_path):
            self.assertTrue(config_path.is_file(), config_path)

        claude_settings = json.loads(claude_settings_path.read_text(encoding="utf-8"))
        codex_config = codex_config_path.read_text(encoding="utf-8")
        opencode_config = json.loads(opencode_config_path.read_text(encoding="utf-8"))
        self.assertIn("mcp__ida-pro-mcp__*", claude_settings["permissions"]["allow"])
        self.assertEqual(["mcp__ida-pro-mcp__open_file"], claude_settings["permissions"]["deny"])
        self.assertIn('project_doc_fallback_filenames = [".claude/SKILL_RUNNER.md"]', codex_config)
        self.assertEqual([".claude/SKILL_RUNNER.md"], opencode_config["instructions"])

    def test_agent_profiles_preserve_current_idb_safety(self) -> None:
        claude_agent = Path(".claude/agents/sig-finder.md").read_text(encoding="utf-8")
        opencode_agent = Path(".opencode/agents/sig-finder.md").read_text(encoding="utf-8")
        runner_prompt = Path(".claude/SKILL_RUNNER.md").read_text(encoding="utf-8")
        self.assertIn("mcp__ida-pro-mcp__open_file", claude_agent)
        self.assertIn("ida-pro-mcp_open_file: false", opencode_agent)
        self.assertIn("<skill_error>", runner_prompt)


class AgentRunnerCommandTests(unittest.TestCase):
    def test_model_arguments_follow_each_agent_cli(self) -> None:
        self.assertEqual(["--model", "sonnet"], agent_runner._agent_model_args("claude", "sonnet"))
        self.assertEqual(["-m", "gpt-5"], agent_runner._agent_model_args("codex", "gpt-5"))
        self.assertEqual(["-m", "openai/gpt-5"], agent_runner._agent_model_args("opencode", "openai/gpt-5"))
        with self.assertRaisesRegex(ValueError, "provider/model"):
            agent_runner._agent_model_args("opencode", "gpt-5")

    def test_claude_retry_resumes_same_explicit_session(self) -> None:
        initial = agent_runner._build_claude_command("claude", "find-symbol", "session-1", False)
        retry = agent_runner._build_claude_command("claude", "find-symbol", "session-1", True)
        self.assertIn(["--session-id", "session-1"], _argument_pairs(initial.args))
        self.assertIn(["--resume", "session-1"], _argument_pairs(retry.args))
        self.assertIn(["--settings", ".claude/skill_runner.settings.json"], _argument_pairs(initial.args))

    def test_opencode_retry_targets_extracted_session(self) -> None:
        output = 'not json\n{"sessionID":"ses-first"}\n{"sessionID":"ses-second"}'
        self.assertEqual("ses-first", agent_runner._extract_opencode_session_id(output))
        retry = agent_runner._build_opencode_command("opencode", "find-symbol", True, "ses-first")
        self.assertIn(["--session", "ses-first"], _argument_pairs(retry.args))
        self.assertNotIn("--continue", retry.args)

    def test_codex_injects_developer_instructions_and_uses_stdin_prompt(self) -> None:
        instructions = 'developer_instructions="sig finder"'
        command = agent_runner._build_codex_command("codex", "find-symbol", instructions, False)
        self.assertEqual(["codex", "--profile", "skill_runner", "-c", instructions], command.args[:5])
        self.assertEqual(["exec", "-"], command.args[-2:])
        self.assertEqual("Run SKILL: .claude/skills/find-symbol/SKILL.md", command.input_text)


class AgentRunnerProcessTests(unittest.TestCase):
    @patch("agent_runner.subprocess.Popen")
    def test_stream_capture_drains_and_debug_forwards_both_pipes(self, mock_popen) -> None:
        process = _FakePopen(stdout_chunks=["out one\n", "out two\n"], stderr_chunks=["err\n"], returncode=7)
        mock_popen.return_value = process
        stdout = io.StringIO()
        stderr = io.StringIO()

        with patch("agent_runner.sys.stdout", stdout), patch("agent_runner.sys.stderr", stderr):
            result = agent_runner._run_process_with_stream_capture(["agent"], debug=True, timeout=5)

        self.assertEqual(7, result.returncode)
        self.assertEqual("out one\nout two\n", result.stdout)
        self.assertEqual("err\n", result.stderr)
        self.assertEqual(result.stdout, stdout.getvalue())
        self.assertEqual(result.stderr, stderr.getvalue())
        self.assertTrue(process.stdout.closed)
        self.assertTrue(process.stderr.closed)

    @patch("agent_runner.subprocess.Popen")
    def test_timeout_kills_waits_and_preserves_partial_output(self, mock_popen) -> None:
        process = _TimeoutPopen(stdout_chunks=["partial out\n"], stderr_chunks=["partial err\n"])
        mock_popen.return_value = process

        with self.assertRaises(subprocess.TimeoutExpired) as raised:
            agent_runner._run_process_with_stream_capture(["codex"], timeout=2)

        self.assertTrue(process.killed)
        self.assertEqual([2, 1], process.wait_calls)
        self.assertEqual("partial out\n", raised.exception.output)
        self.assertEqual("partial err\n", raised.exception.stderr)


class AgentRunnerExecutionTests(unittest.TestCase):
    def setUp(self) -> None:
        agent_runner._MCP_PREFLIGHT_CACHE.clear()

    @patch("agent_runner._run_process_with_stream_capture")
    def test_preflight_caches_success_once_per_agent(self, mock_run_process) -> None:
        mock_run_process.side_effect = [
            subprocess.CompletedProcess(["claude", "mcp", "list"], 0, "ida-pro-mcp connected\n", ""),
            subprocess.CompletedProcess(["codex", "mcp", "list"], 0, "ida-pro-mcp connected\n", ""),
        ]

        self.assertTrue(agent_runner.has_required_mcp_server("claude"))
        self.assertTrue(agent_runner.has_required_mcp_server("claude"))
        self.assertTrue(agent_runner.has_required_mcp_server("codex"))
        self.assertTrue(agent_runner.has_required_mcp_server("codex"))
        self.assertEqual(2, mock_run_process.call_count)

    @patch("agent_runner._run_process_with_stream_capture")
    def test_preflight_retries_after_failure_then_caches_success(self, mock_run_process) -> None:
        mock_run_process.side_effect = [
            subprocess.CompletedProcess(["claude", "mcp", "list"], 0, "basic-memory connected\n", ""),
            subprocess.CompletedProcess(["claude", "mcp", "list"], 0, "ida-pro-mcp connected\n", ""),
        ]

        self.assertFalse(agent_runner.has_required_mcp_server("claude"))
        self.assertTrue(agent_runner.has_required_mcp_server("claude"))
        self.assertTrue(agent_runner.has_required_mcp_server("claude"))
        self.assertEqual(2, mock_run_process.call_count)

    @patch("agent_runner._run_process_with_stream_capture")
    def test_timeout_failure_is_not_cached(self, mock_run_process) -> None:
        timeout = subprocess.TimeoutExpired(["claude"], 30, output="partial out", stderr="partial err")
        mock_run_process.side_effect = [
            timeout,
            subprocess.CompletedProcess(["claude", "mcp", "list"], 0, "ida-pro-mcp connected\n", ""),
        ]

        first = agent_runner._perform_mcp_preflight("claude", debug=False, server_name="ida-pro-mcp")
        self.assertFalse(first.ok)
        self.assertEqual("mcp_preflight_timeout", first.reason)
        self.assertEqual(30, first.detail["timeout_seconds"])

        second = agent_runner._perform_mcp_preflight("claude", debug=False, server_name="ida-pro-mcp")
        self.assertTrue(second.ok)
        self.assertEqual(2, mock_run_process.call_count)

    @patch("agent_runner._run_process_with_stream_capture", side_effect=FileNotFoundError)
    def test_agent_not_found_failure_is_not_cached(self, mock_run_process) -> None:
        first = agent_runner._perform_mcp_preflight("codex", debug=False, server_name="ida-pro-mcp")
        self.assertFalse(first.ok)
        self.assertEqual("agent_not_found", first.reason)
        self.assertEqual("codex", first.detail["agent"])

        second = agent_runner._perform_mcp_preflight("codex", debug=False, server_name="ida-pro-mcp")
        self.assertFalse(second.ok)
        self.assertEqual(2, mock_run_process.call_count)

    @patch("agent_runner._run_process_with_stream_capture")
    def test_server_missing_failure_is_not_cached(self, mock_run_process) -> None:
        mock_run_process.side_effect = [
            subprocess.CompletedProcess(["claude", "mcp", "list"], 0, "basic-memory connected\n", ""),
            subprocess.CompletedProcess(["claude", "mcp", "list"], 0, "basic-memory connected\n", ""),
        ]

        first = agent_runner._perform_mcp_preflight("claude", debug=False, server_name="ida-pro-mcp")
        self.assertFalse(first.ok)
        self.assertEqual("mcp_unavailable", first.reason)
        self.assertEqual("ida-pro-mcp", first.detail["server"])
        self.assertEqual(0, first.detail["returncode"])

        second = agent_runner._perform_mcp_preflight("claude", debug=False, server_name="ida-pro-mcp")
        self.assertFalse(second.ok)
        self.assertEqual(2, mock_run_process.call_count)

    @patch("agent_runner._run_process_with_stream_capture")
    def test_success_cache_is_partitioned_by_server_name(self, mock_run_process) -> None:
        mock_run_process.side_effect = [
            subprocess.CompletedProcess(["claude", "mcp", "list"], 0, "ida-pro-mcp connected\n", ""),
            subprocess.CompletedProcess(["claude", "mcp", "list"], 0, "basic-memory connected\n", ""),
        ]

        self.assertTrue(agent_runner._perform_mcp_preflight("claude", debug=False, server_name="ida-pro-mcp").ok)
        self.assertTrue(agent_runner._perform_mcp_preflight("claude", debug=False, server_name="basic-memory").ok)
        self.assertTrue(agent_runner._perform_mcp_preflight("claude", debug=False, server_name="ida-pro-mcp").ok)
        self.assertTrue(agent_runner._perform_mcp_preflight("claude", debug=False, server_name="basic-memory").ok)
        self.assertEqual(2, mock_run_process.call_count)

    @patch("agent_runner._run_process_with_stream_capture")
    def test_run_skill_repreeflights_after_prior_failure(self, mock_run_process) -> None:
        mock_run_process.side_effect = [
            subprocess.CompletedProcess(["codex", "mcp", "list"], 0, "basic-memory connected\n", ""),
            subprocess.CompletedProcess(["codex", "mcp", "list"], 0, "ida-pro-mcp connected\n", ""),
            subprocess.CompletedProcess(["codex"], 0, "done\n", ""),
        ]
        progress: list[dict] = []

        with (
            patch.object(Path, "is_file", return_value=True),
            patch.object(Path, "read_text", return_value="sig finder prompt"),
        ):
            self.assertFalse(
                agent_runner.run_skill(
                    "find-symbol",
                    agent="codex",
                    progress_callback=lambda **event: progress.append(event),
                )
            )
            self.assertTrue(
                agent_runner.run_skill(
                    "find-symbol",
                    agent="codex",
                    progress_callback=lambda **event: progress.append(event),
                )
            )

        self.assertEqual("mcp_unavailable", progress[0]["reason"])
        self.assertEqual(["failed", "attempt_started", "succeeded"], [event["event"] for event in progress])
        self.assertEqual(3, mock_run_process.call_count)

    def test_pre_dispatch_failures_have_structured_reasons(self) -> None:
        cases = (
            ({"agent": "other"}, "unknown_agent"),
            ({"agent": "opencode", "model": "gpt-5"}, "invalid_agent_model"),
            ({"agent": "claude"}, "skill_file_missing"),
        )
        for options, expected_reason in cases:
            with self.subTest(expected_reason=expected_reason):
                progress: list[dict] = []
                result = agent_runner.run_skill(
                    "missing-skill",
                    progress_callback=lambda progress=progress, **event: progress.append(event),
                    **options,
                )
                self.assertFalse(result)
                self.assertEqual(expected_reason, progress[-1]["reason"])

    @patch("agent_runner.uuid.uuid4", return_value="fixed-session")
    @patch("agent_runner._run_process_with_stream_capture")
    def test_claude_retries_same_generated_session(self, mock_run_process, _mock_uuid) -> None:
        mock_run_process.side_effect = [
            subprocess.CompletedProcess(["claude", "mcp", "list"], 0, "ida-pro-mcp connected\n", ""),
            subprocess.CompletedProcess(["claude"], 1, "", "retry"),
            subprocess.CompletedProcess(["claude"], 0, "done", ""),
        ]

        with patch.object(Path, "is_file", return_value=True):
            self.assertTrue(agent_runner.run_skill("find-symbol", agent="claude", max_retries=2))

        initial = mock_run_process.call_args_list[1].args[0]
        retry = mock_run_process.call_args_list[2].args[0]
        self.assertIn(["--session-id", "fixed-session"], _argument_pairs(initial))
        self.assertIn(["--resume", "fixed-session"], _argument_pairs(retry))

    @patch("agent_runner._run_process_with_stream_capture", side_effect=FileNotFoundError)
    def test_missing_agent_during_preflight_has_structured_reason(self, _mock_run_process) -> None:
        progress: list[dict] = []

        with patch.object(Path, "is_file", return_value=True):
            result = agent_runner.run_skill(
                "find-symbol",
                agent="codex",
                progress_callback=lambda **event: progress.append(event),
            )

        self.assertFalse(result)
        self.assertEqual("agent_not_found", progress[-1]["reason"])

    @patch("agent_runner._run_process_with_stream_capture")
    def test_opencode_retries_exact_session_and_reports_diagnostics(self, mock_run_process) -> None:
        mock_run_process.side_effect = [
            subprocess.CompletedProcess(["opencode", "mcp", "list"], 0, "ida-pro-mcp connected\n", ""),
            subprocess.CompletedProcess(
                ["opencode", "run"],
                1,
                '{"sessionID":"ses-exact"}\nfirst stdout\n',
                "first stderr\n",
            ),
            subprocess.CompletedProcess(["opencode", "run"], 0, '{"sessionID":"ses-exact"}\n', ""),
        ]
        progress: list[dict] = []

        with patch.object(Path, "is_file", return_value=True):
            result = agent_runner.run_skill(
                "find-symbol",
                agent="opencode",
                max_retries=2,
                progress_callback=lambda **event: progress.append(event),
            )

        self.assertTrue(result)
        retry_args = mock_run_process.call_args_list[2].args[0]
        self.assertIn(["--session", "ses-exact"], _argument_pairs(retry_args))
        failure = next(event for event in progress if event["event"] == "attempt_failed")
        self.assertEqual("returncode", failure["reason"])
        self.assertEqual(1, failure["returncode"])
        self.assertIn("first stdout", failure["stdout"])
        self.assertIn("first stderr", failure["stderr"])
        self.assertEqual(
            ["attempt_started", "attempt_failed", "attempt_started", "succeeded"],
            [event["event"] for event in progress],
        )

    @patch("agent_runner._run_process_with_stream_capture")
    def test_skill_error_retries_but_cybersecurity_block_stops(self, mock_run_process) -> None:
        progress: list[dict] = []
        mock_run_process.side_effect = [
            subprocess.CompletedProcess(["codex", "mcp", "list"], 0, "ida-pro-mcp connected\n", ""),
            subprocess.CompletedProcess(["codex"], 0, "<skill_error>lookup failed</skill_error>\n", ""),
            subprocess.CompletedProcess(["codex"], 0, "done\n", ""),
        ]

        with (
            patch.object(Path, "is_file", return_value=True),
            patch.object(Path, "read_text", return_value="sig finder prompt"),
        ):
            self.assertTrue(
                agent_runner.run_skill(
                    "find-symbol",
                    agent="codex",
                    max_retries=2,
                    progress_callback=lambda **event: progress.append(event),
                )
            )
        self.assertEqual("skill_error", progress[1]["reason"])
        self.assertEqual("lookup failed", progress[1]["error"])

        agent_runner._MCP_PREFLIGHT_CACHE.clear()
        progress.clear()
        mock_run_process.reset_mock(side_effect=True)
        mock_run_process.side_effect = [
            subprocess.CompletedProcess(["codex", "mcp", "list"], 0, "ida-pro-mcp connected\n", ""),
            subprocess.CompletedProcess(
                ["codex"],
                0,
                "This chat was flagged for possible cybersecurity risk\n",
                "",
            ),
        ]
        with (
            patch.object(Path, "is_file", return_value=True),
            patch.object(Path, "read_text", return_value="sig finder prompt"),
        ):
            self.assertFalse(
                agent_runner.run_skill(
                    "find-symbol",
                    agent="codex",
                    max_retries=3,
                    progress_callback=lambda **event: progress.append(event),
                )
            )
        self.assertEqual(2, mock_run_process.call_count)
        self.assertEqual("cybersecurity_block", progress[-1]["reason"])

    @patch("agent_runner._run_process_with_stream_capture")
    def test_missing_output_and_timeout_have_structured_reasons(self, mock_run_process) -> None:
        progress: list[dict] = []
        mock_run_process.side_effect = [
            subprocess.CompletedProcess(["claude", "mcp", "list"], 0, "ida-pro-mcp connected\n", ""),
            subprocess.CompletedProcess(["claude"], 0, "done\n", ""),
        ]
        with (
            patch.object(Path, "is_file", return_value=True),
            patch("agent_runner._missing_expected_outputs", return_value=["missing.yaml"]),
        ):
            self.assertFalse(
                agent_runner.run_skill(
                    "find-symbol",
                    agent="claude",
                    expected_yaml_paths=["missing.yaml"],
                    max_retries=1,
                    progress_callback=lambda **event: progress.append(event),
                )
            )
        missing = next(event for event in progress if event.get("reason") == "missing_expected_output")
        self.assertEqual(["missing.yaml"], missing["missing_outputs"])

        agent_runner._MCP_PREFLIGHT_CACHE.clear()
        progress.clear()
        timeout = subprocess.TimeoutExpired(["claude"], 9, output="partial out", stderr="partial err")
        mock_run_process.reset_mock(side_effect=True)
        mock_run_process.side_effect = [
            subprocess.CompletedProcess(["claude", "mcp", "list"], 0, "ida-pro-mcp connected\n", ""),
            timeout,
        ]
        with patch.object(Path, "is_file", return_value=True):
            self.assertFalse(
                agent_runner.run_skill(
                    "find-symbol",
                    agent="claude",
                    max_retries=1,
                    timeout=9,
                    progress_callback=lambda **event: progress.append(event),
                )
            )
        timed_out = next(event for event in progress if event.get("reason") == "timeout")
        self.assertEqual(9, timed_out["timeout_seconds"])
        self.assertEqual("partial out", timed_out["stdout"])
        self.assertEqual("partial err", timed_out["stderr"])


def _argument_pairs(args: list[str]) -> list[list[str]]:
    return [args[index : index + 2] for index in range(len(args) - 1)]


if __name__ == "__main__":
    unittest.main()
