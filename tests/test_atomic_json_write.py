import tempfile
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from unittest.mock import call, patch

from release_workflow_lib import hashing


def _windows_error(winerror: int) -> OSError:
    error = OSError(f"simulated WinError {winerror}")
    error.winerror = winerror
    return error


class TestAtomicJsonWrite(unittest.TestCase):
    def test_retries_transient_windows_replace_errors(self):
        with tempfile.TemporaryDirectory() as temporary:
            target = Path(temporary) / "READY.json"
            with (
                patch.object(
                    hashing.os,
                    "replace",
                    side_effect=[_windows_error(5), _windows_error(32), None],
                ) as replace,
                patch.object(hashing.random, "uniform", return_value=0.0),
                patch.object(hashing.time, "sleep") as sleep,
            ):
                hashing.write_canonical_json(target, {"state": "ready"})
            self.assertEqual(3, replace.call_count)
            self.assertEqual([call(0.05), call(0.1)], sleep.call_args_list)
            temporary_paths = {arguments.args[0] for arguments in replace.call_args_list}
            self.assertEqual(1, len(temporary_paths))
            self.assertRegex(next(iter(temporary_paths)).name, r"^\.READY\.json\.[0-9a-f]{32}\.tmp$")
            self.assertEqual([], list(Path(temporary).glob(".READY.json.*.tmp")))

    def test_accepts_matching_target_written_by_another_writer(self):
        with tempfile.TemporaryDirectory() as temporary:
            target = Path(temporary) / "READY.json"
            payload = hashing.canonical_json_bytes({"state": "ready"})

            def concurrent_replace(_source, destination):
                Path(destination).write_bytes(payload)
                raise _windows_error(32)

            with (
                patch.object(hashing.os, "replace", side_effect=concurrent_replace) as replace,
                patch.object(hashing.time, "sleep") as sleep,
            ):
                hashing.write_canonical_json(target, {"state": "ready"})
            replace.assert_called_once()
            sleep.assert_not_called()
            self.assertEqual(payload, target.read_bytes())
            self.assertEqual([], list(Path(temporary).glob(".READY.json.*.tmp")))

    def test_matching_target_success_ignores_temporary_cleanup_failure(self):
        with tempfile.TemporaryDirectory() as temporary:
            target = Path(temporary) / "READY.json"
            payload = hashing.canonical_json_bytes({"state": "ready"})

            def concurrent_replace(_source, destination):
                Path(destination).write_bytes(payload)
                raise _windows_error(32)

            with (
                patch.object(hashing.os, "replace", side_effect=concurrent_replace),
                patch.object(Path, "unlink", side_effect=OSError("temporary cleanup failed")),
            ):
                hashing.write_canonical_json(target, {"state": "ready"})
            self.assertEqual(payload, target.read_bytes())

    def test_reports_retry_exhaustion_and_removes_temporary_file(self):
        with tempfile.TemporaryDirectory() as temporary:
            target = Path(temporary) / "READY.json"
            with (
                patch.object(hashing.os, "replace", side_effect=_windows_error(5)) as replace,
                patch.object(hashing.random, "uniform", return_value=0.0),
                patch.object(hashing.time, "sleep") as sleep,
                self.assertRaisesRegex(OSError, r"after 7 attempts with WinError 5"),
            ):
                hashing.write_canonical_json(target, {"state": "ready"})
            self.assertEqual(7, replace.call_count)
            self.assertEqual(6, sleep.call_count)
            self.assertEqual([], list(Path(temporary).glob(".READY.json.*.tmp")))

    def test_does_not_retry_non_windows_replace_error(self):
        with tempfile.TemporaryDirectory() as temporary:
            target = Path(temporary) / "READY.json"
            with (
                patch.object(hashing.os, "replace", side_effect=OSError("permanent failure")) as replace,
                patch.object(hashing.time, "sleep") as sleep,
                self.assertRaisesRegex(OSError, "permanent failure"),
            ):
                hashing.write_canonical_json(target, {"state": "ready"})
            replace.assert_called_once()
            sleep.assert_not_called()
            self.assertEqual([], list(Path(temporary).glob(".READY.json.*.tmp")))

    def test_cleanup_failure_does_not_mask_replace_failure(self):
        with tempfile.TemporaryDirectory() as temporary:
            target = Path(temporary) / "READY.json"
            replacement_failure = OSError("replacement failed")
            with (
                patch.object(hashing.os, "replace", side_effect=replacement_failure),
                patch.object(Path, "unlink", side_effect=OSError("cleanup failed")),
                self.assertRaises(OSError) as raised,
            ):
                hashing.write_canonical_json(target, {"state": "ready"})
            self.assertIs(replacement_failure, raised.exception)

    def test_uses_distinct_temporary_paths_for_sequential_writes(self):
        with tempfile.TemporaryDirectory() as temporary:
            target = Path(temporary) / "READY.json"
            sources = []
            with patch.object(hashing.os, "replace", side_effect=lambda source, _target: sources.append(source)):
                hashing.write_canonical_json(target, {"sequence": 1})
                hashing.write_canonical_json(target, {"sequence": 2})
            self.assertEqual(2, len(sources))
            self.assertNotEqual(sources[0], sources[1])

    def test_concurrent_writers_leave_one_complete_payload(self):
        with tempfile.TemporaryDirectory() as temporary:
            target = Path(temporary) / "READY.json"
            payloads = [{"sequence": sequence, "value": "x" * 1024} for sequence in range(16)]
            with ThreadPoolExecutor(max_workers=8) as executor:
                list(executor.map(lambda payload: hashing.write_canonical_json(target, payload), payloads))
            self.assertIn(hashing.load_json_object(target), payloads)
            self.assertEqual([], list(Path(temporary).glob(".READY.json.*.tmp")))

    def test_canonical_bytes_and_str_path_api_are_unchanged(self):
        with tempfile.TemporaryDirectory() as temporary:
            target = Path(temporary) / "nested" / "READY.json"
            document = {"b": 1, "a": ["x", {"z": None}]}
            hashing.write_canonical_json(str(target), document)
            self.assertEqual(hashing.canonical_json_bytes(document), target.read_bytes())
            self.assertTrue(target.read_bytes().endswith(b"}\n"))


if __name__ == "__main__":
    unittest.main()
