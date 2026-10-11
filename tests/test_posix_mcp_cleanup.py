import asyncio
import os
import signal
import subprocess
import sys
import time
import unittest
from unittest.mock import Mock, patch

import ida_analyze_bin as analysis


@unittest.skipUnless(os.name == "posix", "POSIX process groups")
class PosixMcpCleanupTests(unittest.TestCase):
    def run_tree(self, *, ignore_term=False, parent_exits=False):
        port = analysis._allocate_local_port()
        child = (
            "import signal,socket,time; "
            + ("signal.signal(signal.SIGTERM, signal.SIG_IGN); " if ignore_term else "")
            + f"s=socket.socket(); s.bind(('127.0.0.1',{port})); s.listen(); time.sleep(60)"
        )
        parent = (
            "import subprocess,sys,time; "
            + f"subprocess.Popen([sys.executable,'-c',{child!r}]); "
            + ("sys.exit(0)" if parent_exits else "time.sleep(60)")
        )
        process = subprocess.Popen([sys.executable, "-c", parent], start_new_session=True)
        process._gsvibe_pgid = process.pid
        unrelated = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(60)"])
        try:
            deadline = time.monotonic() + 5
            while not analysis.is_port_in_use("127.0.0.1", port):
                if time.monotonic() >= deadline:
                    self.fail("test worker did not start")
                time.sleep(0.02)
            if parent_exits:
                process.wait(timeout=5)
            with patch.object(analysis, "MCP_SHUTDOWN_TIMEOUT", 0.2):
                analysis.stop_idalib_mcp_process(process)
                analysis.stop_idalib_mcp_process(process)
            self.assertFalse(analysis.is_port_in_use("127.0.0.1", port))
            self.assertIsNone(process._gsvibe_pgid)
            self.assertIsNone(unrelated.poll())
        finally:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            process.wait(timeout=5)
            unrelated.kill()
            unrelated.wait(timeout=5)

    def test_descendant_listener_is_reclaimed(self):
        self.run_tree()

    def test_sigterm_ignoring_worker_is_reclaimed(self):
        self.run_tree(ignore_term=True)

    def test_exited_supervisor_does_not_hide_live_worker(self):
        self.run_tree(ignore_term=True, parent_exits=True)

    def test_start_failure_and_cancellation_clean_owned_group(self):
        for failure in (RuntimeError("failed readiness"), KeyboardInterrupt()):
            process = Mock(pid=12345)
            with (
                patch.object(analysis, "is_port_in_use", return_value=False),
                patch.object(analysis.subprocess, "Popen", return_value=process) as launch,
                patch.object(analysis, "wait_for_mcp_ready", side_effect=failure),
                patch.object(analysis, "stop_idalib_mcp_process") as stop,
                patch.object(analysis, "wait_for_port_release", return_value=True),
            ):
                with self.assertRaises(type(failure)):
                    analysis.start_idalib_mcp("dummy")
                self.assertTrue(launch.call_args.kwargs["start_new_session"])
                self.assertEqual(12345, stop.call_args.args[0]._gsvibe_pgid)

    def test_permission_failure_is_not_reported_as_success(self):
        process = Mock(pid=12345, _gsvibe_pgid=12345)
        with (
            patch.object(os, "killpg", side_effect=PermissionError("denied")),
            self.assertRaises(analysis.McpLifecycleError),
        ):
            analysis.stop_idalib_mcp_process(process)
        self.assertEqual(12345, process._gsvibe_pgid)


class McpCancellationTests(unittest.TestCase):
    def test_async_cancellation_still_stops_process_and_releases_port(self):
        process = Mock()
        process.poll.return_value = None
        with (
            patch.object(analysis, "quit_ida_via_mcp", side_effect=asyncio.CancelledError()),
            patch.object(analysis, "stop_idalib_mcp_process") as stop,
            patch.object(analysis, "wait_for_port_release", return_value=True) as release,
        ):
            with self.assertRaises(asyncio.CancelledError):
                asyncio.run(analysis.quit_ida_gracefully_async(process, "127.0.0.1", 12345, expected_binary="dummy"))
            stop.assert_called_once()
            release.assert_called_once()

    def test_unreleased_port_fails_cleanup(self):
        process = Mock()
        process.poll.return_value = 0
        with (
            patch.object(analysis, "stop_idalib_mcp_process"),
            patch.object(analysis, "wait_for_port_release", return_value=False),
            self.assertRaises(analysis.McpLifecycleError),
        ):
            analysis.quit_ida_gracefully(process, "127.0.0.1", 12345, expected_binary="dummy")
