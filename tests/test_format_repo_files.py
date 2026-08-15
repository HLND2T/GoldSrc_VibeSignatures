from __future__ import annotations

import unittest
from types import SimpleNamespace
from unittest.mock import patch

import format_repo_files


class RepositoryFormatFileDiscoveryTests(unittest.TestCase):
    def test_excludes_claude_and_codex_trees_from_all_formatters(self) -> None:
        git_output = (
            ".claude/skills/example/tool.py\n"
            ".claude/skills/example/agents/openai.yaml\n"
            ".codex/scripts/tool.py\n"
            ".codex/config.yml\n"
            "src/app.py\n"
            "config.yaml\n"
            "gamesymbols/generated.yaml\n"
            ".serena/project.yml"
        )
        completed = SimpleNamespace(returncode=0, stdout=git_output, stderr="")

        with (
            patch.object(format_repo_files.subprocess, "run", return_value=completed),
            patch.object(format_repo_files.Path, "is_file", return_value=True),
        ):
            python_files, yaml_files = format_repo_files.repository_format_files()

        self.assertEqual(["src/app.py"], python_files)
        self.assertEqual(["config.yaml"], yaml_files)

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
