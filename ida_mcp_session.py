"""Bind one MCP client session to the exact IDA database for a binary."""

from __future__ import annotations

import json
import os
import re
from collections.abc import Mapping, Sequence
from contextlib import AsyncExitStack, asynccontextmanager
from dataclasses import dataclass
from typing import Any

WORKER_TOOL_NAMES = frozenset(
    {"py_eval", "survey_binary", "find_bytes", "rename", "define_func", "set_comments", "get_int"}
)
MANAGEMENT_TOOL_NAMES = frozenset({"idb_open", "idb_list"})
IDA_DATABASE_SUFFIXES = (".i64", ".idb")


class McpContractError(RuntimeError):
    pass


class McpDatabaseSelectionError(RuntimeError):
    pass


class McpDatabaseUnavailableError(McpDatabaseSelectionError):
    pass


class McpConnectionError(RuntimeError):
    pass


class McpToolCallError(RuntimeError):
    pass


def normalize_binary_identity_path(path: str | os.PathLike[str]) -> str:
    if not isinstance(path, (str, os.PathLike)) or not str(path).strip():
        return ""
    value = str(path).strip().replace("\\", "/")
    for suffix in IDA_DATABASE_SUFFIXES:
        if value.lower().endswith(suffix):
            value = value[: -len(suffix)]
            break
    mount = re.match(r"^/mnt/([A-Za-z])/(.*)$", value)
    if mount:
        value = f"{mount.group(1)}:/{mount.group(2)}"
    if not re.match(r"^[A-Za-z]:/", value) and not value.startswith("/"):
        value = os.path.abspath(os.path.normpath(value)).replace("\\", "/")
    else:
        value = os.path.normpath(value).replace("\\", "/")
    return value.rstrip("/").casefold()


def detect_database_requirement(tools: Sequence[Any]) -> bool:
    requirements = {}
    for tool in tools:
        name = getattr(tool, "name", None)
        if name in WORKER_TOOL_NAMES:
            schema = getattr(tool, "inputSchema", {})
            requirements[name] = "database" in (schema.get("required", []) if isinstance(schema, dict) else [])
    if not requirements:
        raise McpContractError("MCP tools/list returned no known IDA worker tools")
    if len(set(requirements.values())) != 1:
        raise McpContractError(f"Inconsistent database requirement across worker tools: {requirements}")
    return next(iter(requirements.values()))


def select_database_session(
    sessions: Sequence[Mapping[str, Any]],
    *,
    expected_binary: str | os.PathLike[str] | None = None,
    explicit_database: str | None = None,
) -> Mapping[str, Any]:
    routable = [
        session
        for session in sessions
        if session.get("is_active") is True and isinstance(session.get("session_id"), str) and session["session_id"]
    ]
    if explicit_database:
        matches = [session for session in routable if session["session_id"] == explicit_database]
    elif expected_binary:
        expected = normalize_binary_identity_path(expected_binary)
        matches = [
            session for session in routable if normalize_binary_identity_path(session.get("input_path", "")) == expected
        ]
    else:
        matches = routable
    if len(matches) == 1:
        return matches[0]
    inactive_match = bool(
        expected_binary
        and any(
            normalize_binary_identity_path(session.get("input_path", ""))
            == normalize_binary_identity_path(expected_binary)
            and session.get("is_active") is not True
            for session in sessions
        )
    )
    if inactive_match:
        raise McpDatabaseUnavailableError("The matching IDA database is inactive or unreachable")
    raise McpDatabaseSelectionError(f"Expected exactly one active IDA database, found {len(matches)}")


@dataclass(frozen=True)
class McpDatabaseBinding:
    database_required: bool
    session_id: str | None
    input_path: str | None
    backend: str | None
    owned: bool
    auto_started: bool


class DatabaseBoundSession:
    def __init__(self, raw_session: Any, binding: McpDatabaseBinding) -> None:
        self.raw_session = raw_session
        self.binding = binding

    async def call_tool(self, name: str, arguments: Mapping[str, Any] | None = None, **kwargs):
        routed = dict(arguments or {})
        if self.binding.database_required and name not in MANAGEMENT_TOOL_NAMES:
            supplied = routed.get("database")
            if supplied not in {None, self.binding.session_id}:
                raise McpDatabaseSelectionError(f"Tool {name} conflicts with the bound database")
            routed["database"] = self.binding.session_id
        result = await self.raw_session.call_tool(name=name, arguments=routed, **kwargs)
        if getattr(result, "isError", False):
            raise McpToolCallError(f"MCP tool {name} failed")
        return result

    def __getattr__(self, name):
        return getattr(self.raw_session, name)


def _result_payload(result: Any) -> dict:
    structured = getattr(result, "structuredContent", None)
    if isinstance(structured, dict):
        return structured
    content = getattr(result, "content", None) or []
    text = getattr(content[0], "text", "") if content else ""
    try:
        parsed = json.loads(text)
    except (TypeError, json.JSONDecodeError):
        return {}
    return parsed if isinstance(parsed, dict) else {}


@asynccontextmanager
async def open_ida_mcp_session(
    host: str,
    port: int,
    *,
    expected_binary=None,
    explicit_database=None,
    auto_started=False,
    connect_timeout=10.0,
    read_timeout=300.0,
):
    try:
        import httpx
        from mcp import ClientSession
        from mcp.client.streamable_http import streamable_http_client

        async with AsyncExitStack() as stack:
            client = await stack.enter_async_context(
                httpx.AsyncClient(
                    follow_redirects=True,
                    timeout=httpx.Timeout(connect_timeout, read=read_timeout),
                    trust_env=False,
                )
            )
            streams = await stack.enter_async_context(
                streamable_http_client(f"http://{host}:{port}/mcp", http_client=client, terminate_on_close=False)
            )
            raw = await stack.enter_async_context(ClientSession(streams[0], streams[1]))
            await raw.initialize()
            tools = (await raw.list_tools()).tools
            required = detect_database_requirement(tools)
            if required:
                listed = await raw.call_tool(name="idb_list", arguments={})
                selected = select_database_session(
                    _result_payload(listed).get("sessions", []),
                    expected_binary=expected_binary,
                    explicit_database=explicit_database,
                )
                binding = McpDatabaseBinding(
                    True,
                    selected["session_id"],
                    selected.get("input_path"),
                    selected.get("backend"),
                    bool(selected.get("owned")),
                    auto_started,
                )
            else:
                binding = McpDatabaseBinding(False, None, str(expected_binary or ""), None, auto_started, auto_started)
            yield DatabaseBoundSession(raw, binding)
    except (McpContractError, McpDatabaseSelectionError, McpToolCallError):
        raise
    except Exception as exc:
        raise McpConnectionError(f"Unable to open IDA MCP session at {host}:{port}: {exc}") from exc
