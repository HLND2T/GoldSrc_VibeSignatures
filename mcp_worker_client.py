"""Serial, lifecycle-owned MCP execution with one loop and one transport owner task.

The synchronous scope routes existing analysis phases to its executor. The async
scope is private to the executor: SDK transports never cross tasks or loops.
An outer batch process deadline remains necessary for uninterruptible Python/OS
calls, including event-loop construction on Windows.
"""

from __future__ import annotations

import asyncio
import concurrent.futures
import logging
import threading
from contextlib import AsyncExitStack
from contextvars import ContextVar
from types import TracebackType

START_TIMEOUT = 10.0
CLOSE_TIMEOUT = 10.0
OPERATION_TIMEOUT = 3600.0
_sync_client = ContextVar("sync_mcp_client", default=None)
_async_client = ContextVar("async_mcp_client", default=None)


def _detach_executor_tracebacks(exception):
    """Keep caller-side traceback cleanup away from the suspended owner task."""
    seen = set()

    def detach(error):
        if id(error) in seen:
            return
        seen.add(id(error))
        frames = []
        current = error.__traceback__
        while current is not None:
            if current.tb_frame.f_code is not WorkerMcpClient._serve.__code__:
                frames.append(current)
            current = current.tb_next
        detached = None
        for frame in reversed(frames):
            detached = TracebackType(detached, frame.tb_frame, frame.tb_lasti, frame.tb_lineno)
        error.__traceback__ = detached
        for nested in (error.__cause__, error.__context__, *getattr(error, "exceptions", ())):
            if isinstance(nested, BaseException):
                detach(nested)

    detach(exception)
    return exception


def run_mcp_operation(coroutine, *, timeout=OPERATION_TIMEOUT):
    client = _sync_client.get()
    if client is None:
        return asyncio.run(coroutine)
    return client.run(coroutine, timeout=timeout)


def invalidate_mcp_client():
    client = _sync_client.get()
    if client is not None:
        client.run(client.reset(), timeout=CLOSE_TIMEOUT)


class WorkerMcpClient:
    def __init__(self, expected_binary):
        self.expected_binary = str(expected_binary)
        self.thread = None
        self.loop = None
        self.queue = None
        self.invalid = False
        self.generation = 0
        self._closed = False
        self._token = None
        self._ready = concurrent.futures.Future()
        self._stack = None
        self._raw = None
        self._bound = None
        self._endpoint = None
        self._failure = None
        self._inflight = None
        self._task = None
        self._run_lock = threading.Lock()

    @staticmethod
    def current():
        return _async_client.get()

    def __enter__(self):
        if self.thread is not None:
            raise RuntimeError("MCP client cannot be entered twice")
        self.thread = threading.Thread(target=self._thread_main, name="mcp-client", daemon=True)
        self.thread.start()
        try:
            self._ready.result(timeout=START_TIMEOUT)
        except BaseException:
            self._closed = True
            raise
        self._token = _sync_client.set(self)
        return self

    def _thread_main(self):
        try:
            # Construct on the owned thread so the caller's startup deadline also
            # covers synchronous socketpair creation, before a loop can run timers.
            self.loop = asyncio.new_event_loop()
            asyncio.set_event_loop(self.loop)
            if not self._closed:
                self.loop.run_until_complete(self._serve())
        except BaseException as exc:  # noqa: BLE001 - transfer thread failures to the synchronous caller.
            self._failure = exc
            if not self._ready.done():
                self._ready.set_exception(exc)
            if self._inflight is not None and not self._inflight.done():
                self._inflight.set_exception(exc)
        finally:
            if self.loop is not None:
                pending = asyncio.all_tasks(self.loop)
                for task in pending:
                    task.cancel()
                self.loop.run_until_complete(asyncio.gather(*pending, return_exceptions=True))
                self.loop.run_until_complete(self.loop.shutdown_asyncgens())
                self.loop.run_until_complete(self.loop.shutdown_default_executor())
                self.loop.close()

    async def _serve(self):
        _async_client.set(self)
        self._task = asyncio.current_task()
        self.queue = asyncio.Queue()
        self._stack = AsyncExitStack()
        self._ready.set_result(None)
        try:
            while True:
                try:
                    coroutine, result, timeout = await self.queue.get()
                except asyncio.CancelledError:
                    # An SDK task may discover a dead stream between phases.
                    # Leave its cancellation scopes before accepting recovery.
                    self.invalid = True
                    await self._discard()
                    continue
                if coroutine is None:
                    break
                task = asyncio.current_task()
                expired = False

                def cancel_overdue(task=task):
                    nonlocal expired
                    expired = True
                    task.cancel()

                timer = self.loop.call_later(timeout, cancel_overdue)
                failure = None
                try:
                    value = await coroutine
                except BaseException as exc:  # noqa: BLE001 - cancellation must settle the waiting caller too.
                    self.invalid = True
                    failure = exc
                finally:
                    timer.cancel()
                if self.invalid:
                    close_error = await self._discard()
                    if isinstance(failure, asyncio.CancelledError) and close_error is not None:
                        from ida_mcp_session import McpConnectionError

                        failure = McpConnectionError(f"MCP transport failed: {close_error}")
                if expired:
                    failure = TimeoutError(f"MCP operation exceeded {timeout:g}s")
                if failure is not None:
                    # assertRaises/logging consumers can clear traceback frames.
                    # On Python 3.12 clearing a suspended coroutine frame closes
                    # it, so never export this long-lived task's frame.
                    result.set_exception(_detach_executor_tracebacks(failure))
                else:
                    result.set_result(value)
        finally:
            await self._stack.aclose()

    def run(self, coroutine, *, timeout=OPERATION_TIMEOUT):
        if self._closed or self.thread is None or not self.thread.is_alive():
            coroutine.close()
            raise RuntimeError("MCP executor is closed")
        if threading.current_thread() is self.thread:
            coroutine.close()
            raise RuntimeError("MCP executor cannot synchronously call itself")
        result = concurrent.futures.Future()
        if not self._run_lock.acquire(blocking=False):
            coroutine.close()
            raise RuntimeError("Another MCP operation is already running")
        try:
            self._inflight = result
            if self._failure is not None:
                coroutine.close()
                raise RuntimeError("MCP executor failed") from self._failure
            self.loop.call_soon_threadsafe(self.queue.put_nowait, (coroutine, result, timeout))
            return result.result(timeout=timeout + CLOSE_TIMEOUT)
        except concurrent.futures.TimeoutError:
            self.invalid = True
            raise
        except BaseException:
            self.invalid = True
            if not result.done() and not self.loop.is_closed():
                self.loop.call_soon_threadsafe(self._task.cancel)
            raise
        finally:
            self._inflight = None
            self._run_lock.release()

    async def _discard(self):
        error = None
        try:
            await self._stack.aclose()
        except BaseException as exc:  # noqa: BLE001 - unwind all SDK scopes before recovery on this task.
            error = exc
            logging.getLogger(__name__).debug("MCP transport close reported: %s", exc)
        finally:
            self._stack = AsyncExitStack()
            self._raw = self._bound = self._endpoint = None
            self.generation += 1
        return error

    async def reset(self):
        await self._discard()
        self.invalid = False

    async def raw_session(self, host, port, connect_timeout, read_timeout):
        from ida_mcp_session import McpConnectionError, _open_raw_ida_mcp_session

        if self.current() is not self or asyncio.get_running_loop() is not self.loop:
            raise McpConnectionError("MCP client cannot be used outside its owning event loop")
        if self.invalid:
            raise McpConnectionError("MCP session is invalid; lifecycle recovery is required")
        if self._endpoint is not None and self._endpoint != (host, port):
            raise McpConnectionError("MCP endpoint changed without lifecycle invalidation")
        if self._raw is None:
            try:
                self._raw = await self._stack.enter_async_context(
                    _open_raw_ida_mcp_session(host, port, connect_timeout, read_timeout)
                )
                self._endpoint = (host, port)
            except BaseException:
                self.invalid = True
                raise
        return self._raw

    async def bound_session(self, host, port, **kwargs):
        from ida_mcp_session import (
            McpDatabaseSelectionError,
            McpDatabaseUnavailableError,
            _open_bound_ida_mcp_session,
            _tool_result_payload,
            normalize_binary_identity_path,
            select_database_session,
        )

        expected = kwargs.get("expected_binary")
        if expected and normalize_binary_identity_path(expected) != normalize_binary_identity_path(
            self.expected_binary
        ):
            raise McpDatabaseSelectionError("MCP client belongs to a different binary")
        kwargs["expected_binary"] = self.expected_binary
        kwargs["auto_started"] = True
        await self.raw_session(host, port, kwargs.get("connect_timeout", 10.0), kwargs.get("read_timeout", 300.0))
        if self._bound is None:
            self._bound = await self._stack.enter_async_context(_open_bound_ida_mcp_session(host, port, **kwargs))
        else:
            explicit = kwargs.get("explicit_database")
            if explicit and explicit != self._bound.binding.session_id:
                raise McpDatabaseSelectionError("MCP phase refers to a stale database binding")
            if self._bound.binding.database_required:
                listed = await self._bound.call_tool("idb_list", {})
                selected = select_database_session(
                    (_tool_result_payload(listed) or {}).get("sessions", []),
                    expected_binary=self.expected_binary,
                    explicit_database=self._bound.binding.session_id,
                )
                if selected != self._bound.database_instance:
                    # Compare stable identity fields only; activity timestamps are
                    # expected to change as the database is used.
                    keys = ("session_id", "input_path", "backend", "owned", "pid", "worker_pid")
                    if any(selected.get(key) != self._bound.database_instance.get(key) for key in keys):
                        self.invalid = True
                        raise McpDatabaseUnavailableError(
                            "MCP database instance changed; identity verification required"
                        )
        return self._bound

    def __exit__(self, *exc):
        if self._token is not None:
            _sync_client.reset(self._token)
            self._token = None
        try:
            if self.thread is not None and self.thread.is_alive():
                self.run(self.reset(), timeout=CLOSE_TIMEOUT)
        finally:
            self._closed = True
            if self.loop is not None and not self.loop.is_closed():
                self.loop.call_soon_threadsafe(self.queue.put_nowait, (None, None, None))
            if self.thread is not None:
                self.thread.join(CLOSE_TIMEOUT)
                if self.thread.is_alive():
                    raise TimeoutError("MCP executor did not stop; outer worker process timeout remains required")
