from __future__ import annotations

import hashlib
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from artifact_diagnostics import append_artifact_diagnostics, render_artifact_diff


class ArtifactDiagnosticsTests(unittest.TestCase):
    def test_diff_facts_and_truncation(self):
        expected = b"".join(f"field{i}: old\n".encode() for i in range(80))
        actual = expected.replace(b"old", b"new")
        message = render_artifact_diff("game-1/engine/demo.yaml", expected, actual, expected_source="merge Git blob")
        self.assertIn(f"size={len(expected)} sha256={hashlib.sha256(expected).hexdigest()}", message)
        self.assertIn(f"size={len(actual)} sha256={hashlib.sha256(actual).hexdigest()}", message)
        self.assertIn("diff truncated after 40 lines", message)
        lines = message.split("content diff (expected -> actual):\n", 1)[1].splitlines()
        self.assertEqual(41, len(lines))

    def test_non_utf8_and_line_ending_only_changes_keep_byte_facts(self):
        for actual, reason in ((b"\xff\n", "not UTF-8"), (b"a\r\n", "line endings")):
            with self.subTest(actual=actual):
                message = render_artifact_diff(
                    "game-1/engine/demo.yaml", b"a\n", actual, expected_source="tracked checkout"
                )
                self.assertIn(reason, message)
                self.assertIn(hashlib.sha256(actual).hexdigest(), message)

    def test_diagnostic_failure_preserves_original_error(self):
        with tempfile.TemporaryDirectory() as temporary:
            with patch("artifact_diagnostics.iter_yaml_paths", side_effect=OSError("read failed")):
                message = append_artifact_diagnostics(
                    "original contract failure",
                    tag="game-1",
                    actual_root=Path(temporary),
                    load_expected=lambda: {},
                    expected_source="merge Git blob",
                )
        self.assertTrue(message.startswith("original contract failure"))
        self.assertIn("diagnostics unavailable", message)

    def test_diagnostic_refuses_links_without_reading_target(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            module = root / "game-1" / "engine"
            module.mkdir(parents=True)
            (module / "demo.yaml").write_bytes(b"secret: value\n")
            with patch("gamesymbol_snapshot_lib.paths.is_reparse_point", return_value=True):
                message = append_artifact_diagnostics(
                    "original",
                    tag="game-1",
                    actual_root=root,
                    load_expected=lambda: {},
                    expected_source="merge Git blob",
                )
            self.assertIn("diagnostics unavailable", message)
            self.assertNotIn("secret", message)

    def test_read_and_render_errors_preserve_original_failure(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            module = root / "game-1" / "engine"
            module.mkdir(parents=True)
            (module / "demo.yaml").write_bytes(b"a: new\n")
            for target, error in (
                ("pathlib.Path.read_bytes", OSError("cannot read")),
                ("artifact_diagnostics.render_artifact_diff", RuntimeError("cannot render")),
            ):
                with self.subTest(target=target), patch(target, side_effect=error):
                    message = append_artifact_diagnostics(
                        "original contract failure",
                        tag="game-1",
                        actual_root=root,
                        load_expected=lambda: {"engine/demo.yaml": b"a: old\n"},
                        expected_source="merge Git blob",
                    )
                self.assertTrue(message.startswith("original contract failure"))
                self.assertIn("diagnostics unavailable", message)

    def test_nested_paths_are_rejected_before_any_content_is_read(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            nested = root / "game-1" / "engine" / "nested"
            nested.mkdir(parents=True)
            (nested / "demo.yaml").write_bytes(b"a: new\n")
            with patch("pathlib.Path.read_bytes") as read:
                message = append_artifact_diagnostics(
                    "original",
                    tag="game-1",
                    actual_root=root,
                    load_expected=lambda: {},
                    expected_source="merge Git blob",
                )
            read.assert_not_called()
            self.assertIn("diagnostics unavailable", message)

    def test_limits_changed_file_details(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            module = root / "game-1" / "engine"
            module.mkdir(parents=True)
            expected = {}
            for index in range(7):
                name = f"demo{index}.yaml"
                expected[f"engine/{name}"] = b"a: old\n"
                (module / name).write_bytes(b"a: new\n")
            message = append_artifact_diagnostics(
                "original",
                tag="game-1",
                actual_root=root,
                load_expected=lambda: expected,
                expected_source="merge Git blob",
            )
            self.assertEqual(5, message.count("content diff (expected -> actual)"))
            self.assertIn("2 changed artifact details omitted", message)
