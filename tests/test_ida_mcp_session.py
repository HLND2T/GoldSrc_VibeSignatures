from __future__ import annotations

import asyncio
import hashlib
import json
import socket
import tempfile
import threading
import unittest
from contextlib import asynccontextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

from ida_mcp_session import (
    DatabaseBoundSession,
    McpConnectionError,
    McpContractError,
    McpDatabaseBinding,
    McpDatabaseSelectionError,
    McpDatabaseUnavailableError,
    McpToolCallError,
    _split_streamable_http_result,
    _tool_result_is_error,
    _tool_result_payload,
    check_ida_mcp_supervisor_health,
    detect_database_requirement,
    normalize_binary_identity_path,
    open_ida_mcp_session,
    select_database_session,
)
from mcp_worker_client import WorkerMcpClient, run_mcp_operation

ACTIVE_SERVER = {
    "session_id": "server-db",
    "input_path": r"D:\repo\bin\server.dll.i64",
    "backend": "worker",
    "owned": True,
    "is_active": True,
    "pid": 101,
    "worker_pid": 202,
}

ACTIVE_ENGINE = {
    "session_id": "engine-db",
    "input_path": r"D:\repo\bin\engine.dll.i64",
    "backend": "worker",
    "owned": False,
    "is_active": True,
}


class WorkerMcpClientTests(unittest.TestCase):
    def test_operations_share_loop_and_owner_task_and_close_on_that_task(self):
        events = []

        @asynccontextmanager
        async def transport(*args):
            events.append(("open", asyncio.get_running_loop(), asyncio.current_task()))
            yield SimpleNamespace()
            events.append(("close", asyncio.get_running_loop(), asyncio.current_task()))

        async def operation():
            client = WorkerMcpClient.current()
            await client.raw_session("localhost", 1234, 10, 300)
            events.append(("call", asyncio.get_running_loop(), asyncio.current_task()))

        with patch("ida_mcp_session._open_raw_ida_mcp_session", transport):
            with WorkerMcpClient("test.dll") as client:
                run_mcp_operation(operation())
                run_mcp_operation(operation())
            self.assertFalse(client.thread.is_alive())
        self.assertEqual(["open", "call", "call", "close"], [event[0] for event in events])
        self.assertEqual(1, len({id(event[1]) for event in events}))
        self.assertEqual(1, len({id(event[2]) for event in events}))

    def test_exception_is_not_replayed_and_next_operation_fails_closed(self):
        calls = []

        async def mutation():
            calls.append("mutation")
            raise OSError("connection lost after write")

        with WorkerMcpClient("test.dll") as client:
            with self.assertRaisesRegex(OSError, "connection lost"):
                run_mcp_operation(mutation())
            self.assertEqual(["mutation"], calls)
            self.assertTrue(client.invalid)
        self.assertFalse(client.thread.is_alive())

    def test_timeout_cancels_operation_and_closes_thread(self):
        cancelled = []

        async def stalled():
            try:
                await asyncio.Event().wait()
            finally:
                cancelled.append(True)

        with WorkerMcpClient("test.dll") as client:
            with self.assertRaises(TimeoutError):
                run_mcp_operation(stalled(), timeout=0.05)
            self.assertEqual([True], cancelled)
        self.assertFalse(client.thread.is_alive())

    def test_loop_construction_timeout_does_not_wait_for_loop_timer(self):
        release = threading.Event()
        original = asyncio.new_event_loop

        def delayed_loop():
            release.wait(2.0)
            return original()

        client = WorkerMcpClient("test.dll")
        with patch("mcp_worker_client.START_TIMEOUT", 0.02), patch("asyncio.new_event_loop", delayed_loop):
            try:
                with self.assertRaises(TimeoutError):
                    client.__enter__()
            finally:
                release.set()
                client.thread.join(2.0)
        self.assertFalse(client.thread.is_alive())

    def test_cancellation_closes_resources_without_replaying(self):
        async def cancel():
            raise asyncio.CancelledError()

        with WorkerMcpClient("test.dll") as client:
            with self.assertRaises(asyncio.CancelledError):
                run_mcp_operation(cancel())
            self.assertTrue(client.invalid)
        self.assertFalse(client.thread.is_alive())

    def test_workers_have_isolated_event_loops(self):
        async def loop():
            return asyncio.get_running_loop()

        with WorkerMcpClient("first.dll"):
            first = run_mcp_operation(loop())
            with WorkerMcpClient("second.dll"):
                second = run_mcp_operation(loop())
            self.assertIs(first, run_mcp_operation(loop()))
        self.assertIsNot(first, second)


class _McpHttpServer(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self):
        super().__init__(("127.0.0.1", 0), _McpHttpHandler)
        self.initializations = 0
        self.connections = 0
        self.calls = []
        self.database = dict(ACTIVE_SERVER)
        self.sha256 = None

    def get_request(self):
        request = super().get_request()
        self.connections += 1
        return request


class _McpHttpHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *args):
        pass

    def do_GET(self):
        self.send_response(405)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def do_POST(self):
        request = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
        method = request["method"]
        result = {}
        if method == "initialize":
            self.server.initializations += 1
            result = {
                "protocolVersion": request["params"]["protocolVersion"],
                "capabilities": {"tools": {}},
                "serverInfo": {"name": "test", "version": "1"},
            }
        elif method == "tools/list":
            result = {
                "tools": [
                    {"name": "idb_list", "inputSchema": {"type": "object"}},
                    {"name": "survey_binary", "inputSchema": {"type": "object", "required": ["database"]}},
                    {
                        "name": "py_eval",
                        "inputSchema": {
                            "type": "object",
                            "properties": {},
                            "required": ["database"],
                        },
                    },
                ]
            }
        elif method == "tools/call":
            params = request["params"]
            self.server.calls.append(params)
            if params.get("arguments", {}).get("code") == "disconnect":
                self.connection.shutdown(socket.SHUT_RDWR)
                self.close_connection = True
                return
            payload = {"sessions": [self.server.database]} if params["name"] == "idb_list" else {"result": "1"}
            if params["name"] == "survey_binary":
                payload = {"metadata": {"path": self.server.database["input_path"], "sha256": self.server.sha256}}
            result = {"content": [{"type": "text", "text": json.dumps(payload)}], "isError": False}
        if "id" not in request:
            self.send_response(202)
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        body = json.dumps({"jsonrpc": "2.0", "id": request["id"], "result": result}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


class PersistentHttpSessionTests(unittest.TestCase):
    def setUp(self):
        self.server = _McpHttpServer()
        self.thread = threading.Thread(target=self.server.serve_forever)
        self.thread.start()
        self.addCleanup(self.thread.join)
        self.addCleanup(self.server.server_close)
        self.addCleanup(self.server.shutdown)

    async def phase(self, code="1", **kwargs):
        async with open_ida_mcp_session(
            "127.0.0.1", self.server.server_port, expected_binary=r"D:\repo\bin\server.dll", **kwargs
        ) as session:
            await session.call_tool("py_eval", {"code": code})
            return session.binding

    def test_real_handshake_and_tcp_reuse_across_phases(self):
        with WorkerMcpClient(r"D:\repo\bin\server.dll") as client:
            self.assertTrue(run_mcp_operation(check_ida_mcp_supervisor_health("127.0.0.1", self.server.server_port)))
            first = run_mcp_operation(self.phase("preprocess"))
            connections_after_first_phase = self.server.connections
            second = run_mcp_operation(self.phase("validate"))
            third = run_mcp_operation(self.phase("health"))
            self.assertEqual(first, second)
            self.assertEqual(second, third)
            self.assertEqual(1, self.server.initializations)
            self.assertLessEqual(self.server.connections, 2)
            self.assertEqual(connections_after_first_phase, self.server.connections)
        self.assertFalse(client.thread.is_alive())
        mutations = [call for call in self.server.calls if call["name"] == "py_eval"]
        self.assertEqual(["preprocess", "validate", "health"], [call["arguments"]["code"] for call in mutations])
        self.assertTrue(all(call["arguments"]["database"] == "server-db" for call in mutations))

    def test_replacement_same_endpoint_invalidates_before_mutation(self):
        with WorkerMcpClient(r"D:\repo\bin\server.dll") as client:
            run_mcp_operation(self.phase("first"))
            self.server.database["worker_pid"] += 1
            with self.assertRaisesRegex(McpDatabaseUnavailableError, "instance changed"):
                run_mcp_operation(self.phase("must not run"))
            self.assertTrue(client.invalid)
            client.run(client.reset())
            run_mcp_operation(self.phase("new generation"))
        self.assertEqual(2, self.server.initializations)
        mutations = [call["arguments"]["code"] for call in self.server.calls if call["name"] == "py_eval"]
        self.assertEqual(["first", "new generation"], mutations)

    def test_rebuild_binding_to_wrong_binary_fails(self):
        with WorkerMcpClient(r"D:\repo\bin\server.dll") as client:
            run_mcp_operation(self.phase())
            client.run(client.reset())
            self.server.database["input_path"] = "wrong.dll"
            with self.assertRaises(McpDatabaseSelectionError):
                run_mcp_operation(self.phase("must not run"))
        self.assertEqual(2, self.server.initializations)
        self.assertEqual(1, sum(call["name"] == "py_eval" for call in self.server.calls))

    def test_retained_session_cannot_be_used_after_reset_or_on_another_loop(self):
        async def borrow():
            async with open_ida_mcp_session("127.0.0.1", self.server.server_port) as session:
                return session

        with WorkerMcpClient(r"D:\repo\bin\server.dll") as client:
            retained = run_mcp_operation(borrow())
            with self.assertRaisesRegex(McpConnectionError, "different worker"):
                asyncio.run(retained.call_tool("py_eval", {"code": "wrong loop"}))
            client.run(client.reset())
            run_mcp_operation(self.phase("current"))
            with self.assertRaisesRegex(McpConnectionError, "expired generation"):
                run_mcp_operation(retained.call_tool("py_eval", {"code": "stale"}))
        self.assertEqual(1, sum(call["name"] == "py_eval" for call in self.server.calls))

    def test_real_disconnect_does_not_replay_mutation_and_closes_transport(self):
        with WorkerMcpClient(r"D:\repo\bin\server.dll") as client:
            with self.assertRaises(McpConnectionError):
                run_mcp_operation(self.phase("disconnect"), timeout=2.0)
            self.assertTrue(client.invalid)
        self.assertFalse(client.thread.is_alive())
        self.assertEqual(1, sum(call["name"] == "py_eval" for call in self.server.calls))

    def test_lifecycle_restart_revalidates_hash_and_rejects_mismatch(self):
        import ida_analyze_bin as analyzer

        with tempfile.TemporaryDirectory() as directory:
            binary = Path(directory) / "test.dll"
            binary.write_bytes(b"original binary")
            self.server.database["input_path"] = str(binary)
            self.server.sha256 = hashlib.sha256(binary.read_bytes()).hexdigest()
            process = MagicMock()
            process.poll.return_value = None

            def restart(*args, **kwargs):
                process.poll.return_value = None
                self.server.database["session_id"] = "replacement-db"
                self.server.sha256 = "0" * 64
                return process

            with (
                patch.object(analyzer, "_has_ida_database", return_value=True),
                patch.object(analyzer, "start_idalib_mcp", return_value=process) as start,
                patch.object(analyzer, "quit_ida_gracefully"),
                patch.object(analyzer, "is_port_in_use", return_value=False),
                patch.object(analyzer, "wait_for_port_release", return_value=True),
            ):
                with analyzer.IdaMcpLifecycle(
                    binary,
                    "windows",
                    "127.0.0.1",
                    self.server.server_port,
                    [],
                    database_policy=analyzer.DATABASE_POLICY_RESTORED_STRICT,
                    save_on_success=False,
                ) as lifecycle:
                    client = lifecycle._client
                    self.assertEqual("server-db", lifecycle.runtime.binding.session_id)
                    process.poll.return_value = 1
                    start.side_effect = restart
                    with self.assertRaisesRegex(analyzer.McpLifecycleError, "identity verification failed"):
                        lifecycle.ensure_ready()
                self.assertFalse(client.thread.is_alive())
        self.assertEqual(2, self.server.initializations)
        surveys = [call["arguments"]["database"] for call in self.server.calls if call["name"] == "survey_binary"]
        self.assertEqual(["server-db", "replacement-db"], surveys)


class _TransportCloseError(Exception):
    def __init__(self, exception: Exception) -> None:
        self.exceptions = (exception,)


@asynccontextmanager
async def _async_context(value):
    yield value


@asynccontextmanager
async def _grouping_context(value):
    try:
        yield value
    except Exception as exc:  # noqa: BLE001 - emulate an AnyIO-style grouped transport close.
        raise _TransportCloseError(exc) from None


def _tool_result(payload: dict, *, is_error: bool = False) -> SimpleNamespace:
    return SimpleNamespace(isError=is_error, content=[], structuredContent=payload)


class NormalizeAndContractTests(unittest.TestCase):
    def test_accepts_two_and_three_item_streamable_http_results(self):
        self.assertEqual(("read", "write"), _split_streamable_http_result(("read", "write")))
        self.assertEqual(("read", "write"), _split_streamable_http_result(("read", "write", "session")))
        with self.assertRaisesRegex(McpContractError, "unsupported stream tuple"):
            _split_streamable_http_result(("read",))

    def test_tool_result_payload_accepts_sdk_snake_case_structured_content(self):
        payload = {"metadata": {"module": "hw.dll", "arch": "32"}}
        result = SimpleNamespace(structuredContent=None, structured_content=payload, content=[])
        self.assertEqual(payload, _tool_result_payload(result))

    def test_normalizes_database_suffix_case_and_wsl_mount(self):
        self.assertEqual(
            "d:/repo/bin/server.dll",
            normalize_binary_identity_path(r"D:\Repo\bin\server.dll.i64"),
        )
        self.assertEqual(
            "d:/repo/bin/server.so",
            normalize_binary_identity_path("/mnt/d/repo/bin/server.so.idb"),
        )

    def test_detects_legacy_supervisor_and_mixed_contracts(self):
        legacy = [SimpleNamespace(name="py_eval", inputSchema={"required": ["code"]})]
        supervisor = [SimpleNamespace(name="py_eval", inputSchema={"required": ["code", "database"]})]
        mixed = [*supervisor, SimpleNamespace(name="find_bytes", inputSchema={"required": ["patterns"]})]

        self.assertFalse(detect_database_requirement(legacy))
        self.assertTrue(detect_database_requirement(supervisor))
        with self.assertRaisesRegex(McpContractError, "Inconsistent database requirement"):
            detect_database_requirement(mixed)

    def test_detects_sdk_snake_case_input_schema(self):
        supervisor = [SimpleNamespace(name="py_eval", input_schema={"required": ["code", "database"]})]
        self.assertTrue(detect_database_requirement(supervisor))

    def test_detects_sdk_snake_case_tool_errors(self):
        self.assertTrue(_tool_result_is_error(SimpleNamespace(isError=None, is_error=True)))
        self.assertFalse(_tool_result_is_error(SimpleNamespace(isError=False, is_error=False)))


class DatabaseSelectionTests(unittest.TestCase):
    def test_explicit_database_has_priority(self):
        selected = select_database_session(
            [ACTIVE_SERVER, ACTIVE_ENGINE],
            expected_binary=r"D:\repo\bin\server.dll",
            explicit_database="engine-db",
        )
        self.assertEqual("engine-db", selected["session_id"])

    def test_expected_binary_matches_database_suffix(self):
        selected = select_database_session(
            [ACTIVE_SERVER, ACTIVE_ENGINE],
            expected_binary=r"D:\repo\bin\server.dll",
        )
        self.assertEqual("server-db", selected["session_id"])

    def test_inactive_database_reports_candidate_details(self):
        inactive = {**ACTIVE_SERVER, "is_active": False}
        with self.assertRaises(McpDatabaseUnavailableError) as raised:
            select_database_session([inactive], expected_binary=r"D:\repo\bin\server.dll")
        message = str(raised.exception)
        self.assertIn("inactive or unreachable", message)
        self.assertIn("session_id='server-db'", message)
        self.assertIn("worker_pid=202", message)

    def test_multiple_or_blank_sessions_fail_closed(self):
        with self.assertRaisesRegex(McpDatabaseSelectionError, "multiple active MCP databases"):
            select_database_session([ACTIVE_SERVER, ACTIVE_ENGINE])
        blank = {**ACTIVE_SERVER, "session_id": "   "}
        with self.assertRaisesRegex(McpDatabaseSelectionError, "no active routable MCP database"):
            select_database_session([blank])


class DatabaseBoundSessionTests(unittest.IsolatedAsyncioTestCase):
    async def test_binding_only_auto_quits_owned_auto_started_worker(self):
        owned = McpDatabaseBinding(True, "server-db", "server.dll", "worker", True, True)
        unowned = McpDatabaseBinding(True, "server-db", "server.dll", "worker", False, True)
        external = McpDatabaseBinding(True, "server-db", "server.dll", "worker", True, False)
        supervisor = McpDatabaseBinding(True, "server-db", "server.dll", "supervisor", True, True)
        self.assertTrue(owned.should_auto_quit)
        self.assertFalse(unowned.should_auto_quit)
        self.assertFalse(external.should_auto_quit)
        self.assertFalse(supervisor.should_auto_quit)

    async def test_injects_database_and_preserves_management_calls(self):
        raw = MagicMock()
        raw.call_tool = AsyncMock(return_value=_tool_result({"ok": True}))
        bound = DatabaseBoundSession(
            raw,
            McpDatabaseBinding(True, "server-db", "server.dll", "worker", True, True),
        )

        await bound.call_tool("py_eval", {"code": "1"})
        await bound.call_tool("idb_list", {})

        self.assertEqual(
            [
                unittest.mock.call(name="py_eval", arguments={"code": "1", "database": "server-db"}),
                unittest.mock.call(name="idb_list", arguments={}),
            ],
            raw.call_tool.await_args_list,
        )

    async def test_conflicting_database_is_rejected(self):
        raw = MagicMock()
        raw.call_tool = AsyncMock()
        bound = DatabaseBoundSession(
            raw,
            McpDatabaseBinding(True, "server-db", "server.dll", "worker", True, True),
        )
        with self.assertRaisesRegex(McpDatabaseSelectionError, "conflicts with bound database"):
            await bound.call_tool("py_eval", {"code": "1", "database": "engine-db"})
        raw.call_tool.assert_not_awaited()

    async def test_tool_error_includes_server_body(self):
        raw = MagicMock()
        raw.call_tool = AsyncMock(
            return_value=SimpleNamespace(
                isError=True,
                structuredContent=None,
                content=[SimpleNamespace(text='{"error":"database is required"}')],
            )
        )
        bound = DatabaseBoundSession(raw, McpDatabaseBinding(False, None, None, "worker", True, True))
        with self.assertRaisesRegex(McpToolCallError, "py_eval.*database is required"):
            await bound.call_tool("py_eval", {"code": "1"})

    async def test_snake_case_tool_error_includes_server_body(self):
        raw = MagicMock()
        raw.call_tool = AsyncMock(
            return_value=SimpleNamespace(
                isError=None,
                is_error=True,
                structuredContent=None,
                structured_content=None,
                content=[SimpleNamespace(text='{"error":"database is required"}')],
            )
        )
        bound = DatabaseBoundSession(raw, McpDatabaseBinding(False, None, None, "worker", True, True))
        with self.assertRaisesRegex(McpToolCallError, "py_eval.*database is required"):
            await bound.call_tool("py_eval", {"code": "1"})


class OpenIdaMcpSessionTests(unittest.IsolatedAsyncioTestCase):
    async def test_legacy_contract_uses_owned_worker_fallback(self):
        raw = MagicMock()
        raw.list_tools = AsyncMock(
            return_value=SimpleNamespace(tools=[SimpleNamespace(name="py_eval", inputSchema={"required": ["code"]})])
        )
        raw.call_tool = AsyncMock()
        with patch("ida_mcp_session._open_raw_ida_mcp_session", return_value=_async_context(raw)):
            async with open_ida_mcp_session("127.0.0.1", 13337, auto_started=True) as session:
                self.assertFalse(session.binding.database_required)
                self.assertEqual("worker", session.binding.backend)
                self.assertTrue(session.binding.should_auto_quit)
        raw.call_tool.assert_not_awaited()

    async def test_supervisor_contract_selects_expected_database(self):
        raw = MagicMock()
        raw.list_tools = AsyncMock(
            return_value=SimpleNamespace(
                tools=[SimpleNamespace(name="py_eval", inputSchema={"required": ["code", "database"]})]
            )
        )
        raw.call_tool = AsyncMock(return_value=_tool_result({"sessions": [ACTIVE_SERVER]}))
        with patch("ida_mcp_session._open_raw_ida_mcp_session", return_value=_async_context(raw)):
            async with open_ida_mcp_session(
                "127.0.0.1",
                13337,
                expected_binary=r"D:\repo\bin\server.dll",
                auto_started=True,
            ) as session:
                self.assertEqual("server-db", session.binding.session_id)
                self.assertTrue(session.binding.should_auto_quit)
        raw.call_tool.assert_awaited_once_with(name="idb_list", arguments={})

    async def test_idb_list_error_keeps_server_body(self):
        raw = MagicMock()
        raw.list_tools = AsyncMock(
            return_value=SimpleNamespace(
                tools=[SimpleNamespace(name="py_eval", inputSchema={"required": ["code", "database"]})]
            )
        )
        raw.call_tool = AsyncMock(return_value=_tool_result({"error": "supervisor unavailable"}, is_error=True))
        with (
            patch("ida_mcp_session._open_raw_ida_mcp_session", return_value=_async_context(raw)),
            self.assertRaisesRegex(McpToolCallError, "idb_list.*supervisor unavailable"),
        ):
            async with open_ida_mcp_session("127.0.0.1", 13337):
                self.fail("idb_list failure must prevent session yield")

    async def test_nested_selection_error_is_unwrapped(self):
        raw = MagicMock()
        raw.list_tools = AsyncMock(
            return_value=SimpleNamespace(
                tools=[SimpleNamespace(name="py_eval", inputSchema={"required": ["code", "database"]})]
            )
        )
        raw.call_tool = AsyncMock(return_value=_tool_result({"sessions": [ACTIVE_SERVER, ACTIVE_ENGINE]}))
        with (
            patch("ida_mcp_session._open_raw_ida_mcp_session", return_value=_grouping_context(raw)),
            self.assertRaisesRegex(McpDatabaseSelectionError, "multiple active MCP databases"),
        ):
            async with open_ida_mcp_session("127.0.0.1", 13337):
                self.fail("database selection must fail before session yield")

    async def test_transport_errors_are_wrapped_but_body_errors_are_not(self):
        with (
            patch("ida_mcp_session._open_raw_ida_mcp_session", side_effect=RuntimeError("offline")),
            self.assertRaisesRegex(McpConnectionError, "Unable to open IDA MCP session.*offline"),
        ):
            async with open_ida_mcp_session("127.0.0.1", 13337):
                pass

        raw = MagicMock()
        raw.list_tools = AsyncMock(
            return_value=SimpleNamespace(tools=[SimpleNamespace(name="py_eval", inputSchema={"required": ["code"]})])
        )
        with (
            patch("ida_mcp_session._open_raw_ida_mcp_session", return_value=_async_context(raw)),
            self.assertRaises(RuntimeError) as raised,
        ):
            async with open_ida_mcp_session("127.0.0.1", 13337):
                raise RuntimeError("session body failure")
        self.assertIs(RuntimeError, type(raised.exception))
        self.assertEqual("session body failure", str(raised.exception))

    async def test_supervisor_health_lists_tools(self):
        raw = MagicMock()
        raw.list_tools = AsyncMock()
        with patch("ida_mcp_session._open_raw_ida_mcp_session", return_value=_async_context(raw)):
            self.assertTrue(await check_ida_mcp_supervisor_health("127.0.0.1", 13337))
        raw.list_tools.assert_awaited_once_with()


if __name__ == "__main__":
    unittest.main()
