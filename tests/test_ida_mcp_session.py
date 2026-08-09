from __future__ import annotations

import unittest
from contextlib import asynccontextmanager
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
    check_ida_mcp_supervisor_health,
    detect_database_requirement,
    normalize_binary_identity_path,
    open_ida_mcp_session,
    select_database_session,
)

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
