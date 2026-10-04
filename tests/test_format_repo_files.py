from __future__ import annotations

import unittest
import subprocess
from contextlib import redirect_stdout
from io import StringIO
from types import SimpleNamespace
from unittest.mock import patch

import format_repo_files


class RepositoryFormatCommandTests(unittest.TestCase):
    def test_empty_file_list_does_not_launch_a_formatter(self) -> None:
        with patch.object(format_repo_files.subprocess, "run") as run:
            self.assertEqual(0, format_repo_files._run(["ruff", "format"], []))
        run.assert_not_called()

    def test_small_command_preserves_flags_and_file_arguments(self) -> None:
        command = ["ruff", "format", "--check"]
        paths = ["src/a.py", "src/file with spaces.py"]
        with patch.object(format_repo_files.subprocess, "run", return_value=SimpleNamespace(returncode=0)) as run:
            self.assertEqual(0, format_repo_files._run(command, paths))
        run.assert_called_once_with([*command, *paths], check=False)
        self.assertEqual(["ruff", "format", "--check"], command)

    def _run_with_budget(self, command, paths, budget, returncodes=None):
        completed = [SimpleNamespace(returncode=code) for code in returncodes] if returncodes is not None else None
        with (
            patch.object(format_repo_files, "MAX_COMMAND_LINE_UNITS", budget, create=True),
            patch.object(
                format_repo_files.subprocess,
                "run",
                side_effect=completed,
                return_value=SimpleNamespace(returncode=0),
            ) as run,
        ):
            result = format_repo_files._run(command, paths)
        calls = [call.args[0] for call in run.call_args_list]
        self.assertEqual(paths, [path for call in calls for path in call[len(command) :]])
        for call in calls:
            self.assertEqual(command, call[: len(command)])
            self.assertTrue(call[len(command) :])
            units = len(subprocess.list2cmdline(call).encode("utf-16-le")) // 2 + 1
            self.assertLessEqual(units, budget)
        return result, calls

    def test_long_file_list_is_split_without_losing_or_reordering_files(self) -> None:
        paths = ["src/" + str(index) + "_" + "x" * 70 + ".py" for index in range(100)]
        result, calls = self._run_with_budget(["ruff", "format", "--check"], paths, 250)
        self.assertEqual(0, result)
        self.assertGreater(len(calls), 1)

    def test_budget_includes_command_prefix_and_windows_quoting(self) -> None:
        command = ["C:/Program Files/tool.exe", "--check"]
        paths = ["folder with spaces/a.py", 'folder/quoted"name.py', "folder with spaces/trailing\\"]
        budget = max(len(subprocess.list2cmdline([*command, path]).encode("utf-16-le")) // 2 + 1 for path in paths)
        result, calls = self._run_with_budget(command, paths, budget)
        self.assertEqual(0, result)
        self.assertGreater(len(calls), 1)

    def test_budget_counts_utf16_units_for_non_bmp_paths(self) -> None:
        command = ["ruff"]
        paths = ["😀" * 8 + ".py", "😀" * 8 + ".py"]
        budget = len(subprocess.list2cmdline([*command, *paths])) + 1
        result, calls = self._run_with_budget(command, paths, budget)
        self.assertEqual(0, result)
        self.assertEqual(2, len(calls))

    def test_exact_budget_boundary_fits_one_command(self) -> None:
        command = ["ruff", "format"]
        paths = ["a.py", "b.py"]
        budget = len(subprocess.list2cmdline([*command, *paths]).encode("utf-16-le")) // 2 + 1
        result, calls = self._run_with_budget(command, paths, budget)
        self.assertEqual(0, result)
        self.assertEqual(1, len(calls))

    def test_later_success_does_not_hide_a_failed_batch(self) -> None:
        result, calls = self._run_with_budget(["ruff"], ["a.py", "b.py", "c.py"], 10, [7, 0, 2])
        self.assertEqual(7, result)
        self.assertEqual(3, len(calls))

    def test_single_argument_over_budget_is_rejected_before_launch(self) -> None:
        with (
            patch.object(format_repo_files, "MAX_COMMAND_LINE_UNITS", 10, create=True),
            patch.object(format_repo_files.subprocess, "run") as run,
        ):
            with self.assertRaisesRegex(RuntimeError, "command-line budget"):
                format_repo_files._run(["ruff"], ["x" * 20 + ".py"])
        run.assert_not_called()

    def test_main_reports_unsplittable_command_as_an_error(self) -> None:
        output = StringIO()
        with (
            patch.object(format_repo_files, "repository_format_files", return_value=(["a.py"], [])),
            patch.object(format_repo_files, "_run", side_effect=RuntimeError("command-line budget exceeded")),
            redirect_stdout(output),
        ):
            self.assertEqual(1, format_repo_files.main(["--check"]))
        self.assertIn("command-line budget exceeded", output.getvalue())


class RepositoryFormatFileDiscoveryTests(unittest.TestCase):
    def test_excludes_claude_and_codex_trees_from_all_formatters(self) -> None:
        git_output = (
            ".claude/skills/example/tool.py\n"
            ".claude/skills/example/agents/openai.yaml\n"
            ".codex/scripts/tool.py\n"
            ".codex/config.yml\n"
            "src/app.py\n"
            "config.yaml\n"
            "bin_artifacts/hl-10210/engine/generated.yaml\n"
            "gamesymbols/generated.yaml"
        )
        completed = SimpleNamespace(returncode=0, stdout=git_output, stderr="")

        with (
            patch.object(format_repo_files.subprocess, "run", return_value=completed),
            patch.object(format_repo_files.Path, "is_file", return_value=True),
        ):
            python_files, yaml_files = format_repo_files.repository_format_files()

        self.assertEqual(["src/app.py"], python_files)
        self.assertEqual(["config.yaml"], yaml_files)

    def test_excludes_ida_preprocessor_references_yaml(self) -> None:
        git_output = (
            "ida_preprocessor_scripts/references/hl-10210/engine/CBaseUI__Initialize.linux.yaml\n"
            "ida_preprocessor_scripts/references/hl-10210/engine/CBaseUI__Initialize.windows.yaml\n"
            "ida_preprocessor_scripts/references/hl-10210/engine/ClientDLL_HudInit.yaml\n"
            "ida_preprocessor_scripts/other/references/keep.yaml\n"
            "ida_preprocessor_scripts/references/hl-10210/engine/not_a_yaml.txt\n"
            "src/engine/config.yaml\n"
            "src/engine/tool.py\n"
        )
        completed = SimpleNamespace(returncode=0, stdout=git_output, stderr="")

        with (
            patch.object(format_repo_files.subprocess, "run", return_value=completed),
            patch.object(format_repo_files.Path, "is_file", return_value=True),
        ):
            python_files, yaml_files = format_repo_files.repository_format_files()

        self.assertEqual(["src/engine/tool.py"], python_files)
        self.assertEqual(
            [
                "ida_preprocessor_scripts/other/references/keep.yaml",
                "src/engine/config.yaml",
            ],
            yaml_files,
        )

    def test_excluded_prefixes_are_separator_and_case_insensitive(self) -> None:
        for path in (
            ".claude/SKILL.md",
            ".CLAUDE\\skills\\tool.py",
            ".codex/config.yaml",
            ".CODEX\\agents\\openai.yaml",
        ):
            with self.subTest(path=path):
                self.assertTrue(format_repo_files._is_excluded_format_path(path))

        self.assertFalse(format_repo_files._is_excluded_format_path("src/.claude/tool.py"))


if __name__ == "__main__":
    unittest.main()
