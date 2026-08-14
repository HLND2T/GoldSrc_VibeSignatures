#!/usr/bin/env python3
"""Validate x86 binaries and execute the preprocessor/agent analysis DAG."""

from __future__ import annotations

import argparse
import asyncio
import hashlib
import json
import os
import re
import socket
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path, PurePosixPath

import yaml
from dotenv import load_dotenv

import agent_runner
from analysis_config import AnalysisConfigError, resolve_analysis_config, validated_tag
from analysis_planner import (
    AnalysisPlanError,
    ExecutionPlan,
    build_process_execution_plan,
    load_config,
    parse_config_document,
    symbol_artifact_filename,
    validate_artifact_path,
)
from analysis_planner import (
    build_execution_plan as _build_execution_plan,
)
from binary_format import BinaryFormatError, validate_binary
from ida_analyze_util import SymbolArtifactError, normalize_symbol_artifact
from ida_llm_utils import validated_temperature
from ida_mcp_session import (
    IDA_DATABASE_SUFFIXES,
    McpConnectionError,
    McpContractError,
    McpDatabaseBinding,
    McpDatabaseSelectionError,
    McpDatabaseUnavailableError,
    McpToolCallError,
    check_ida_mcp_supervisor_health,
    normalize_binary_identity_path,
    open_ida_mcp_session,
)
from ida_skill_preprocessor import (
    PREPROCESS_STATUS_ABSENT_OK,
    PREPROCESS_STATUS_FAILED,
    PREPROCESS_STATUS_NO_SCRIPT,
    PREPROCESS_STATUS_SUCCESS,
    _emit_diagnostic,
    _normalize_preprocess_status,
    preprocess_single_skill_via_mcp,
)
from process_reporter import (
    BestEffortProcessReporter,
    NullProcessReporter,
    ProcessEvent,
    ProcessEventType,
    ProcessPhase,
    ProcessReason,
    ProcessReporter,
    ProcessReporterConfigurationError,
    RunStatus,
    TaskStatus,
    is_valid_task_transition,
)
from process_reporter import (
    ExecutionPlan as ProcessExecutionPlan,
)
from process_reporter_factory import DEFAULT_REDIS_PREFIX, DEFAULT_REDIS_URL, create_process_reporter
from trusted_yaml import load_yaml_file

load_dotenv()

PLATFORMS = ("windows", "linux")
ANALYSIS_STAGES = ("preprocessor", "agent")
DEFAULT_BIN_DIR = "bin"
DEFAULT_PLATFORM = "windows,linux"
DEFAULT_MODULES = "*"
DEFAULT_AGENT = "claude"
DEFAULT_AGENT_MODEL = ""
DEFAULT_LLM_MODEL = "gpt-4o"
DEFAULT_DOWNLOAD_FILE = "download.yaml"
DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 13337
MCP_STARTUP_TIMEOUT = 1200.0
MCP_SHUTDOWN_TIMEOUT = 10.0
OPENED_BINARY_VERIFY_TIMEOUT = 60.0
OPENED_BINARY_VERIFY_RETRY_INTERVAL = 2.0
QEXIT_CONNECTION_RESET_MARKER = "[WinError 10054]"
LLM_EFFORTS = frozenset({"none", "minimal", "low", "medium", "high", "xhigh"})
RUN_ID_RE = re.compile(r"^[A-Za-z0-9_.:-]{1,160}$", re.ASCII)
REMOVED_CLI_OPTIONS = frozenset({"-config", "-plan-only", "-vcall_finder", "-rename", "-console-events"})
UNAVAILABLE_HASH_VALUES = frozenset({"", "unavailable", "unknown", "none", "null"})
IDA_DATABASE_SIDE_SUFFIXES = (".id1", ".id2", ".nam", ".til")


class AnalysisRunError(RuntimeError):
    pass


class PipelineFailure(AnalysisRunError):
    def __init__(self, reason: str, message: str, payload: dict | None = None) -> None:
        super().__init__(message)
        self.reason = reason
        self.payload = dict(payload or {})


class ArtifactValidationUnavailable(RuntimeError):
    pass


class McpLifecycleError(AnalysisRunError):
    pass


@dataclass
class AnalysisSummary:
    successful: int = 0
    failed: int = 0
    skipped: int = 0


@dataclass(frozen=True)
class PipelineResult:
    status: str
    stage: str
    reason: str | None = None


@dataclass(frozen=True)
class McpRuntime:
    host: str
    port: int
    expected_binary: str
    binding: McpDatabaseBinding

    def as_context(self) -> dict:
        return {
            "host": self.host,
            "port": self.port,
            "expected_binary": self.expected_binary,
            "database": self.binding.session_id,
            "backend": self.binding.backend,
            "owned": self.binding.owned,
            "auto_started": self.binding.auto_started,
        }


class McpRecoveryBudget:
    """Limit lifecycle-owner MCP restarts for one binary processing run."""

    def __init__(self, restart_limit: int = 1) -> None:
        self.remaining_restarts = max(0, int(restart_limit))

    def consume_restart(self) -> bool:
        if self.remaining_restarts <= 0:
            return False
        self.remaining_restarts -= 1
        return True


class AnalysisReporting:
    """Track local lifecycle state while forwarding typed process events."""

    def __init__(self, reporter: ProcessReporter, run_id: str, plan) -> None:
        self.reporter = (
            reporter if isinstance(reporter, BestEffortProcessReporter) else BestEffortProcessReporter(reporter)
        )
        self.run_id = run_id
        self._node_ids = {node.id for node in plan.nodes}
        self._nodes_by_job = {job.id: [] for job in plan.jobs}
        self._planner_to_task = {}
        self._planner_to_job = {}
        for node in plan.nodes:
            self._nodes_by_job[node.job_id].append(node.id)
            planner_node_id = node.data.get("planner_node_id")
            if planner_node_id:
                self._planner_to_task[planner_node_id] = node.id
                self._planner_to_job[planner_node_id] = node.job_id
        self._states = {task_id: TaskStatus.PENDING for task_id in self._node_ids}
        self._states.update({job.id: TaskStatus.PENDING for job in plan.jobs})

    def task_id_for(self, planner_node_id: str) -> str:
        return self._planner_to_task[planner_node_id]

    def job_id_for(self, planner_node_id: str) -> str:
        return self._planner_to_job[planner_node_id]

    def emit_run_status(self, status: RunStatus, *, message: str | None = None) -> None:
        self.reporter.emit(
            ProcessEvent(
                run_id=self.run_id,
                event_type=ProcessEventType.RUN_STATUS_CHANGED,
                status=status,
                message=message,
            )
        )

    def emit_task_status(
        self,
        task_id: str,
        status: TaskStatus,
        phase: ProcessPhase,
        *,
        reason: ProcessReason | None = None,
        message: str | None = None,
        error: str | None = None,
        payload: dict | None = None,
    ) -> None:
        current = self._states.get(task_id, TaskStatus.PENDING)
        if current in {TaskStatus.SUCCEEDED, TaskStatus.FAILED, TaskStatus.SKIPPED, TaskStatus.ABORTED}:
            return
        if not is_valid_task_transition(current, status):
            return
        self.reporter.emit(
            ProcessEvent(
                run_id=self.run_id,
                event_type=ProcessEventType.TASK_STATUS_CHANGED,
                task_id=task_id,
                status=status,
                phase=phase,
                reason=reason,
                message=message,
                error=error,
                payload=payload or {},
            )
        )
        self._states[task_id] = status

    def emit_progress(self, task_id: str, phase: ProcessPhase, **progress) -> None:
        self.reporter.emit(
            ProcessEvent(
                run_id=self.run_id,
                event_type=ProcessEventType.SKILL_PROGRESS,
                task_id=task_id,
                status=TaskStatus.RUNNING,
                phase=phase,
                payload=progress,
            )
        )

    def finish_job_tasks(
        self,
        job_id: str,
        status: TaskStatus,
        reason: ProcessReason,
        message: str,
    ) -> None:
        for task_id in self._nodes_by_job.get(job_id, []):
            self.emit_task_status(task_id, status, ProcessPhase.FINISHED, reason=reason, message=message)

    def abort_pending(self, reason: ProcessReason, message: str) -> None:
        for task_id in list(self._states):
            self.emit_task_status(task_id, TaskStatus.ABORTED, ProcessPhase.FINISHED, reason=reason, message=message)

    def summary(self) -> dict[str, int]:
        counts = {status.value: 0 for status in TaskStatus}
        for task_id in self._node_ids:
            counts[self._states[task_id].value] += 1
        counts["total"] = len(self._node_ids)
        return counts


def parse_config(config_path, config_document=None):
    if config_document is not None:
        return parse_config_document(config_document)
    return load_config(config_path)[1]


def _skill_runs_on_platform(skill, platform):
    return skill.get("platform") in {None, platform}


def resolve_artifact_path(binary_dir, artifact_path, platform):
    filename = validate_artifact_path(artifact_path, "artifact", platform)
    module_root = Path(binary_dir).resolve()
    result = (module_root / filename).resolve()
    if result.parent != module_root:
        raise ValueError(f"Artifact path escapes module directory: {artifact_path}")
    return str(result)


def expand_expected_paths(binary_dir, paths, platform):
    return [resolve_artifact_path(binary_dir, path, platform) for path in paths]


def expand_skill_output_paths(binary_dir, skill, platform):
    common = list(skill.get("expected_output", []) or [])
    common.extend(skill.get(f"expected_output_{platform}", []) or [])
    required = expand_expected_paths(binary_dir, common, platform)
    optional = expand_expected_paths(binary_dir, skill.get("optional_output", []) or [], platform)
    return required, optional, required + optional


def all_expected_outputs_exist(expected_outputs):
    return bool(expected_outputs) and all(Path(path).is_file() for path in expected_outputs)


def should_skip_skill_for_existing_outputs(required_outputs, optional_outputs):
    return all_expected_outputs_exist(required_outputs or optional_outputs)


def get_binary_path(bin_dir, gamever, module_name, configured_path):
    return str(Path(bin_dir) / gamever / module_name / Path(configured_path).name)


def build_execution_plan(
    modules,
    *,
    platforms,
    bin_dir,
    gamever,
    default_max_retries=3,
    vcall_finder_selector=None,
    include_post_process=False,
) -> ExecutionPlan:
    if vcall_finder_selector is not None:
        raise ValueError("GoldSrc does not provide a generic vtable/vcall finder")
    if include_post_process:
        raise ValueError("GoldSrc analysis has no implicit Source2 post-process stage")
    return _build_execution_plan(
        modules,
        platforms=platforms,
        bin_dir=bin_dir,
        tag=gamever,
        default_max_retries=default_max_retries,
    )


def topological_sort_skills(skills, platform=None):
    selected = platform or "windows"
    module = {
        "stage_index": 0,
        "name": "module",
        "path_windows": "game/module.dll",
        "path_linux": "game/module.so",
        "skills": list(skills),
        "symbols": [],
    }
    plan = _build_execution_plan([module], platforms=[selected], bin_dir=".analysis-plan", tag="contract-0")
    return [node.skill for node in plan.nodes]


def validate_module_skill_dependencies(modules):
    for platform in PLATFORMS:
        _build_execution_plan(modules, platforms=[platform], bin_dir=".analysis-plan", tag="contract-0")


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _md5(path: Path) -> str:
    digest = hashlib.md5()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


SURVEY_CURRENT_IDB_PATH_PY_EVAL = (
    "import json\n"
    "path = ''\n"
    "input_sha256 = ''\n"
    "try:\n"
    "    import idaapi\n"
    "    path = idaapi.get_path(idaapi.PATH_TYPE_IDB) or ''\n"
    "except Exception:\n"
    "    pass\n"
    "if not path:\n"
    "    try:\n"
    "        import idc\n"
    "        path = idc.get_idb_path() or ''\n"
    "    except Exception:\n"
    "        pass\n"
    "try:\n"
    "    import ida_nalt\n"
    "    raw_sha256 = ida_nalt.retrieve_input_file_sha256()\n"
    "    if isinstance(raw_sha256, (bytes, bytearray)):\n"
    "        input_sha256 = bytes(raw_sha256).hex()\n"
    "    elif isinstance(raw_sha256, str):\n"
    "        input_sha256 = raw_sha256.strip()\n"
    "except Exception:\n"
    "    pass\n"
    "metadata = {'path': path}\n"
    "if input_sha256:\n"
    "    metadata['input_sha256'] = input_sha256\n"
    "result = json.dumps({'metadata': metadata})\n"
)


def _parse_mcp_tool_json(result):
    structured = getattr(result, "structuredContent", None)
    if not isinstance(structured, dict):
        structured = getattr(result, "structured_content", None)
    if isinstance(structured, dict):
        return structured
    content = getattr(result, "content", None) or []
    raw = getattr(content[0], "text", None) if content else None
    if not isinstance(raw, str):
        return None
    try:
        parsed = json.loads(raw)
    except (TypeError, json.JSONDecodeError):
        return None
    return parsed if isinstance(parsed, dict) else None


def _parse_py_eval_json(result):
    payload = _parse_mcp_tool_json(result)
    if not isinstance(payload, dict):
        return None
    result_text = payload.get("result")
    if not isinstance(result_text, str) or not result_text:
        return None
    try:
        parsed = json.loads(result_text)
    except (TypeError, json.JSONDecodeError):
        return None
    return parsed if isinstance(parsed, dict) else None


def _merge_survey_path(payload, path_payload):
    if not isinstance(path_payload, dict):
        return payload
    path_metadata = path_payload.get("metadata")
    if not isinstance(path_metadata, dict):
        return payload
    current_path = path_metadata.get("path")
    if not isinstance(current_path, str) or not current_path:
        return payload
    merged = dict(payload) if isinstance(payload, dict) else {}
    metadata = merged.get("metadata")
    merged_metadata = dict(metadata) if isinstance(metadata, dict) else {}
    merged_metadata["path"] = current_path
    input_sha256 = path_metadata.get("input_sha256")
    if isinstance(input_sha256, str) and input_sha256.strip():
        merged_metadata["input_sha256"] = input_sha256.strip()
    merged["metadata"] = merged_metadata
    return merged


async def survey_binary_via_session(session, detail_level: str = "minimal"):
    payload = None
    try:
        payload = _parse_mcp_tool_json(await session.call_tool("survey_binary", {"detail_level": detail_level}))
    except (McpConnectionError, McpContractError, McpDatabaseSelectionError, McpToolCallError):
        raise
    except Exception:  # noqa: BLE001 - survey_binary is optional when py_eval can supply identity.
        payload = None

    try:
        current_path = _parse_py_eval_json(
            await session.call_tool("py_eval", {"code": SURVEY_CURRENT_IDB_PATH_PY_EVAL})
        )
    except (McpConnectionError, McpContractError, McpDatabaseSelectionError, McpToolCallError):
        raise
    except Exception:  # noqa: BLE001 - the path fallback is optional across MCP server versions.
        current_path = None
    return _merge_survey_path(payload, current_path)


async def _survey_opened_binary_via_mcp(host, port, expected_binary, *, auto_started=False):
    async with open_ida_mcp_session(
        host,
        port,
        expected_binary=expected_binary,
        auto_started=auto_started,
    ) as session:
        return await survey_binary_via_session(session), session.binding


def _metadata_hash(metadata, key):
    value = metadata.get(key)
    if not isinstance(value, str):
        return ""
    normalized = value.strip().casefold()
    return "" if normalized in UNAVAILABLE_HASH_VALUES else normalized


def _is_ida_database_path(path):
    return isinstance(path, str) and path.strip().casefold().endswith(IDA_DATABASE_SUFFIXES)


def validate_opened_binary_identity(binary_path, platform, survey_payload):
    if not isinstance(survey_payload, dict):
        return False, ["survey_binary returned no metadata"]
    metadata = survey_payload.get("metadata")
    if not isinstance(metadata, dict):
        return False, ["survey_binary returned no metadata"]

    reasons = []
    architecture = str(metadata.get("arch", "")).strip().casefold()
    if architecture and "64" in architecture:
        reasons.append(f"unexpected 64-bit opened database architecture: {architecture}")
    format_label = " ".join(
        str(metadata.get(key, "")).strip().casefold() for key in ("format", "filetype", "file_type")
    )
    if platform == "linux" and ("portable executable" in format_label or " pe " in f" {format_label} "):
        reasons.append(f"PE database opened for linux target: {format_label.strip()}")
    if platform == "windows" and "elf" in format_label:
        reasons.append(f"ELF database opened for windows target: {format_label.strip()}")

    expected = Path(binary_path)
    opened_path = metadata.get("path")
    opened_sha256 = _metadata_hash(metadata, "sha256")
    input_sha256 = _metadata_hash(metadata, "input_sha256")
    opened_is_ida_database = _is_ida_database_path(opened_path)
    if opened_is_ida_database and not input_sha256:
        reasons.append("IDB input sha256 is unavailable")
    effective_sha256 = input_sha256 if opened_is_ida_database else (opened_sha256 or input_sha256)
    opened_md5 = _metadata_hash(metadata, "md5")
    if effective_sha256:
        expected_sha256 = _sha256(expected)
        if effective_sha256 != expected_sha256:
            source = "IDB input" if opened_is_ida_database else "opened"
            reasons.append(f"sha256 mismatch: expected {expected_sha256}, {source} {effective_sha256}")
        return not reasons, reasons
    if opened_md5:
        expected_md5 = _md5(expected)
        if opened_md5 != expected_md5:
            reasons.append(f"md5 mismatch: expected {expected_md5}, opened {opened_md5}")
        return not reasons, reasons

    expected_path = normalize_binary_identity_path(os.path.abspath(os.path.normpath(os.fspath(expected))))
    normalized_opened_path = normalize_binary_identity_path(opened_path) if isinstance(opened_path, str) else ""
    if not normalized_opened_path:
        reasons.append("path mismatch: opened metadata path is missing")
    elif normalized_opened_path != expected_path:
        reasons.append(f"path mismatch: expected {expected_path}, opened {normalized_opened_path}")
    return not reasons, reasons


def verify_opened_binary_via_mcp(
    binary_path,
    platform,
    host=DEFAULT_HOST,
    port=DEFAULT_PORT,
    *,
    debug=False,
    verify_timeout=OPENED_BINARY_VERIFY_TIMEOUT,
    retry_interval=OPENED_BINARY_VERIFY_RETRY_INTERVAL,
):
    deadline = time.monotonic() + max(0.0, verify_timeout)
    last_reasons = ["survey_binary returned no metadata"]
    while True:
        try:
            survey, binding = asyncio.run(_survey_opened_binary_via_mcp(host, port, binary_path, auto_started=True))
        except McpDatabaseUnavailableError:
            raise
        except (McpConnectionError, McpContractError, McpDatabaseSelectionError, McpToolCallError) as exc:
            if debug:
                print(f"  Opened binary verification failed: {exc}")
            return None
        ok, last_reasons = validate_opened_binary_identity(binary_path, platform, survey)
        if ok:
            return McpRuntime(host, port, str(binary_path), binding)
        retryable = last_reasons in (
            ["survey_binary returned no metadata"],
            ["path mismatch: opened metadata path is missing"],
        )
        if not retryable or time.monotonic() >= deadline:
            break
        if debug:
            print("  Opened binary metadata is not ready; retrying verification...")
        time.sleep(max(0.0, retry_interval))
    if debug:
        for reason in last_reasons:
            print(f"  Opened binary verification failed: {reason}")
    return None


async def check_mcp_worker_health(host, port, expected_binary):
    try:
        async with open_ida_mcp_session(host, port, expected_binary=expected_binary) as session:
            await session.call_tool("py_eval", {"code": "1"})
            return True
    except Exception:  # noqa: BLE001 - health probes must collapse transport failures to False.
        return False


def is_port_in_use(host, port):
    try:
        with socket.create_connection((host, port), timeout=1):
            return True
    except OSError:
        return False


def wait_for_port_release(host, port, timeout=MCP_SHUTDOWN_TIMEOUT, retry_interval=0.1):
    deadline = time.monotonic() + max(0.0, timeout)
    while is_port_in_use(host, port):
        if time.monotonic() >= deadline:
            return False
        time.sleep(max(0.0, retry_interval))
    return True


def wait_for_mcp_ready(process, host, port, timeout=MCP_STARTUP_TIMEOUT, retry_interval=0.5):
    deadline = time.monotonic() + max(0.0, timeout)
    while True:
        if process.poll() is not None:
            return False
        if is_port_in_use(host, port) and asyncio.run(check_ida_mcp_supervisor_health(host, port)):
            return True
        if time.monotonic() >= deadline:
            return False
        time.sleep(max(0.0, retry_interval))


def stop_idalib_mcp_process(process, debug=False):
    if process is None or process.poll() is not None:
        return
    if debug:
        print("  Stopping the current idalib-mcp process...")
    try:
        process.terminate()
        process.wait(timeout=MCP_SHUTDOWN_TIMEOUT)
        return
    except (OSError, subprocess.TimeoutExpired):
        pass
    if process.poll() is None:
        try:
            process.kill()
            process.wait(timeout=5.0)
        except (OSError, subprocess.TimeoutExpired):
            pass


def _ida_database_primary_paths(binary_path):
    base = os.fspath(binary_path)
    return [f"{base}{suffix}" for suffix in IDA_DATABASE_SUFFIXES]


def _ida_database_paths(binary_path):
    base = os.fspath(binary_path)
    primary_paths = _ida_database_primary_paths(binary_path)
    side_bases = [base, *primary_paths]
    side_paths = [f"{side_base}{suffix}" for side_base in side_bases for suffix in IDA_DATABASE_SIDE_SUFFIXES]
    return [*primary_paths, *side_paths]


def _ida_database_lock_paths(binary_path):
    base = os.fspath(binary_path)
    return [f"{base}.id0", *(f"{path}.id0" for path in _ida_database_primary_paths(binary_path))]


def _existing_ida_database_lock(binary_path):
    return next((path for path in _ida_database_lock_paths(binary_path) if os.path.isfile(path)), None)


def _raise_for_active_ida_database(binary_path):
    lock_file = _existing_ida_database_lock(binary_path)
    if lock_file is not None:
        raise McpLifecycleError(f"IDB lock file detected ({lock_file}); another IDA instance has this database open")


def _invalidate_ida_database(binary_path, debug=False):
    _raise_for_active_ida_database(binary_path)
    removed = []
    for database_path in dict.fromkeys(_ida_database_paths(binary_path)):
        try:
            if os.path.isfile(database_path):
                os.remove(database_path)
                removed.append(database_path)
        except OSError as exc:
            raise McpLifecycleError(f"Unable to remove stale IDA database file {database_path}: {exc}") from exc
    if debug and removed:
        print(f"  Removed stale IDA database files: {', '.join(removed)}")
    return removed


def _has_ida_database(binary_path):
    return any(os.path.isfile(path) for path in _ida_database_primary_paths(binary_path))


def start_idalib_mcp(
    binary_path,
    host=DEFAULT_HOST,
    port=DEFAULT_PORT,
    ida_args="",
    debug=False,
    stdout=None,
    stderr=None,
):
    if is_port_in_use(host, port):
        return None
    command = ["idalib-mcp", "--unsafe", "--host", host, "--port", str(port)]
    if ida_args:
        command.extend(str(ida_args).split())
    command.append(str(binary_path))
    if debug:
        print(f"  Starting idalib-mcp: {' '.join(command)}")
    process = None
    try:
        output = stdout if stdout is not None else (None if debug else subprocess.DEVNULL)
        errors = stderr if stderr is not None else (None if debug else subprocess.DEVNULL)
        creationflags = getattr(subprocess, "CREATE_NO_WINDOW", 0) if os.name == "nt" and not debug else 0
        process = subprocess.Popen(command, stdout=output, stderr=errors, creationflags=creationflags)
        if wait_for_mcp_ready(process, host, port):
            return process
    except OSError as exc:
        if debug:
            print(f"  Unable to start idalib-mcp: {exc}")
    stop_idalib_mcp_process(process, debug=debug)
    wait_for_port_release(host, port)
    return None


async def quit_ida_via_mcp(host, port, *, expected_binary, auto_started):
    try:
        async with open_ida_mcp_session(
            host,
            port,
            expected_binary=expected_binary,
            auto_started=auto_started,
        ) as session:
            if not session.binding.should_auto_quit:
                return False
            try:
                await session.call_tool("py_eval", {"code": "import idc; idc.qexit(0)"})
            except Exception as exc:  # noqa: BLE001 - qexit commonly closes the transport mid-response.
                return QEXIT_CONNECTION_RESET_MARKER in str(exc)
            return True
    except Exception:  # noqa: BLE001 - shutdown is best-effort and still stops the owned supervisor.
        return False


async def quit_ida_gracefully_async(process, host, port, *, expected_binary, debug=False):
    if process is None or process.poll() is not None:
        return
    try:
        await asyncio.wait_for(
            quit_ida_via_mcp(host, port, expected_binary=expected_binary, auto_started=True),
            timeout=5.0,
        )
    except Exception as exc:  # noqa: BLE001 - local supervisor cleanup must run after any qexit failure.
        if debug:
            print(f"  Graceful IDA worker shutdown failed: {exc}")
    await asyncio.to_thread(stop_idalib_mcp_process, process, debug=debug)
    released = await asyncio.to_thread(wait_for_port_release, host, port, MCP_SHUTDOWN_TIMEOUT)
    if debug and not released:
        print(f"  MCP port {host}:{port} remained in use after shutdown")


def quit_ida_gracefully(process, host, port, *, expected_binary, debug=False):
    if process is None or process.poll() is not None:
        return
    try:
        asyncio.get_running_loop()
    except RuntimeError:
        asyncio.run(
            quit_ida_gracefully_async(
                process,
                host,
                port,
                expected_binary=expected_binary,
                debug=debug,
            )
        )
        return
    raise RuntimeError(
        "quit_ida_gracefully() cannot run inside an active event loop; use await quit_ida_gracefully_async() instead"
    )


def ensure_mcp_available(process, binary_path, host, port, ida_args, debug, *, recovery_budget):
    if process is not None and process.poll() is not None:
        process = None
    if process is not None and asyncio.run(check_mcp_worker_health(host, port, binary_path)):
        return process, True
    if not recovery_budget.consume_restart():
        return process, False
    if process is not None:
        quit_ida_gracefully(process, host, port, expected_binary=binary_path, debug=debug)
        process = None
    if is_port_in_use(host, port) and not wait_for_port_release(host, port):
        return None, False
    restarted = start_idalib_mcp(binary_path, host, port, ida_args, debug)
    return restarted, restarted is not None


def verify_owned_mcp_with_single_recovery(
    process,
    binary_path,
    platform,
    host,
    port,
    ida_args,
    debug,
    *,
    recovery_budget,
):
    try:
        return process, verify_opened_binary_via_mcp(binary_path, platform, host, port, debug=debug)
    except McpDatabaseUnavailableError:
        process, available = ensure_mcp_available(
            process,
            binary_path,
            host,
            port,
            ida_args,
            debug,
            recovery_budget=recovery_budget,
        )
        if not available:
            return process, None
        try:
            return process, verify_opened_binary_via_mcp(binary_path, platform, host, port, debug=debug)
        except McpDatabaseUnavailableError:
            return process, None


class IdaMcpLifecycle:
    """Own one idalib-mcp supervisor and its selected worker for a binary."""

    def __init__(self, binary_path, platform, host, port, ida_args, debug=False) -> None:
        self.binary_path = Path(binary_path)
        self.platform = platform
        self.host = host
        self.port = port
        self.ida_args = ida_args
        self.debug = debug
        self.process = None
        self.runtime = None
        self.recovery_budget = McpRecoveryBudget()
        self._force_local_stop = True

    def _rebuild_stale_database(self) -> None:
        if not self.recovery_budget.consume_restart():
            return
        process = self.process
        if process is not None:
            stop_idalib_mcp_process(process, debug=self.debug)
            self.process = None
        if not wait_for_port_release(self.host, self.port):
            raise McpLifecycleError(f"MCP port {self.host}:{self.port} remained in use before IDB rebuild")
        _invalidate_ida_database(self.binary_path, debug=self.debug)
        self.process = start_idalib_mcp(
            self.binary_path,
            self.host,
            self.port,
            self.ida_args,
            self.debug,
        )
        if self.process is None:
            return
        self.process, self.runtime = verify_owned_mcp_with_single_recovery(
            self.process,
            self.binary_path,
            self.platform,
            self.host,
            self.port,
            self.ida_args,
            self.debug,
            recovery_budget=self.recovery_budget,
        )

    def __enter__(self):
        _raise_for_active_ida_database(self.binary_path)
        try:
            self.process = start_idalib_mcp(
                self.binary_path,
                self.host,
                self.port,
                self.ida_args,
                self.debug,
            )
            if self.process is None:
                raise McpLifecycleError(f"Unable to start idalib-mcp for {self.binary_path}")
            self.process, self.runtime = verify_owned_mcp_with_single_recovery(
                self.process,
                self.binary_path,
                self.platform,
                self.host,
                self.port,
                self.ida_args,
                self.debug,
                recovery_budget=self.recovery_budget,
            )
            if self.runtime is None and _has_ida_database(self.binary_path):
                self._rebuild_stale_database()
            if self.runtime is None:
                raise McpLifecycleError(f"Opened IDA database identity verification failed for {self.binary_path}")
            self._force_local_stop = False
            return self
        except McpLifecycleError:
            self._cleanup()
            raise
        except Exception as exc:
            self._cleanup()
            raise McpLifecycleError(f"Unable to initialize IDA MCP lifecycle for {self.binary_path}: {exc}") from exc

    def ensure_ready(self):
        try:
            self.process, available = ensure_mcp_available(
                self.process,
                self.binary_path,
                self.host,
                self.port,
                self.ida_args,
                self.debug,
                recovery_budget=self.recovery_budget,
            )
            if not available:
                raise McpLifecycleError(f"MCP worker is unavailable for {self.binary_path}")
            self.process, self.runtime = verify_owned_mcp_with_single_recovery(
                self.process,
                self.binary_path,
                self.platform,
                self.host,
                self.port,
                self.ida_args,
                self.debug,
                recovery_budget=self.recovery_budget,
            )
            if self.runtime is None and _has_ida_database(self.binary_path):
                self._rebuild_stale_database()
            if self.runtime is None:
                raise McpLifecycleError(f"Opened IDA database identity verification failed for {self.binary_path}")
            return self.runtime
        except McpLifecycleError:
            self._force_local_stop = True
            raise
        except Exception as exc:
            self._force_local_stop = True
            raise McpLifecycleError(f"Unable to verify IDA MCP lifecycle for {self.binary_path}: {exc}") from exc

    def _cleanup(self):
        process = self.process
        if process is None:
            return
        try:
            if self._force_local_stop:
                stop_idalib_mcp_process(process, debug=self.debug)
            else:
                quit_ida_gracefully(
                    process,
                    self.host,
                    self.port,
                    expected_binary=self.binary_path,
                    debug=self.debug,
                )
            wait_for_port_release(self.host, self.port)
        finally:
            self.process = None

    def __exit__(self, exc_type, exc, traceback):
        self._cleanup()
        return False


def _split_gamever(gamever: str) -> tuple[str, int]:
    normalized = validated_tag(gamever)
    family, build = normalized.rsplit("-", 1)
    return family, int(build)


def resolve_oldgamever(gamever: str, bin_dir: str | Path) -> str | None:
    family, current_build = _split_gamever(gamever)
    root = Path(bin_dir)
    try:
        children = tuple(root.iterdir())
    except OSError:
        return None
    candidates: list[tuple[int, str]] = []
    for child in children:
        if not child.is_dir():
            continue
        try:
            candidate_family, candidate_build = _split_gamever(child.name)
        except (AnalysisConfigError, ValueError):
            continue
        if candidate_family == family and candidate_build < current_build:
            candidates.append((candidate_build, child.name))
    return max(candidates)[1] if candidates else None


def _is_major_update_gamever(gamever: str, download_path: str | Path = DEFAULT_DOWNLOAD_FILE) -> bool:
    path = Path(download_path)
    if not path.is_absolute():
        path = Path(__file__).resolve().parent / path
    try:
        document = yaml.safe_load(path.read_bytes()) or {}
    except (OSError, yaml.YAMLError):
        return False
    downloads = document.get("downloads")
    if not isinstance(downloads, list):
        return False
    for entry in downloads:
        if isinstance(entry, dict) and str(entry.get("tag", "")).strip() == gamever:
            return bool(entry.get("major_update", False))
    return False


def _outputs(node, root: Path) -> tuple[list[Path], list[Path]]:
    return (
        [root / Path(*PurePosixPath(name).parts) for name in node.required_outputs],
        [root / Path(*PurePosixPath(name).parts) for name in node.optional_outputs],
    )


def _node_existing_output_reason(node, game_root: Path) -> ProcessReason | None:
    required, optional = _outputs(node, game_root)
    if should_skip_skill_for_existing_outputs(required, optional):
        return ProcessReason.EXISTING_OUTPUTS
    skip_paths = [game_root / Path(*PurePosixPath(name).parts) for name in node.skip_if_exists]
    if skip_paths and all(path.is_file() for path in skip_paths):
        return ProcessReason.SKIP_IF_EXISTS
    return None


def _artifact_path_key(path: str | Path) -> str:
    return os.path.normcase(os.fspath(Path(path).resolve()))


def _symbol_alias_map_from_document(document: dict) -> dict[str, tuple[str, ...]]:
    aliases: dict[str, tuple[str, ...]] = {}
    for module in document.get("modules", []) if isinstance(document, dict) else ():
        if not isinstance(module, dict):
            continue
        for symbol in module.get("symbols", []) or ():
            if not isinstance(symbol, dict):
                continue
            name = str(symbol.get("name", "")).strip()
            if not name:
                continue
            values = symbol.get("alias")
            raw_aliases = values if isinstance(values, (list, tuple)) else (values,)
            aliases[name] = tuple(alias for value in raw_aliases if (alias := str(value or "").strip()))
    return aliases


def _artifact_type_map(modules: list[dict], game_root: Path) -> dict[str, str]:
    result: dict[str, str] = {}
    for module in modules:
        for platform in PLATFORMS:
            if not module.get(f"path_{platform}"):
                continue
            for symbol in module.get("symbols", ()):
                if symbol.get("platform") not in {None, platform}:
                    continue
                if symbol["category"] == "struct":
                    continue
                filenames = [symbol_artifact_filename(symbol, platform)]
                filenames.extend(f"{alias}.{platform}.yaml" for alias in symbol.get("source_alias", ()))
                for filename in filenames:
                    result[_artifact_path_key(game_root / module["name"] / filename)] = symbol["category"]
    return result


def _parse_artifact_integer(value: object, field: str) -> int:
    if isinstance(value, bool):
        raise TypeError(f"{field} must be a non-negative integer")
    if isinstance(value, int):
        parsed = value
    elif isinstance(value, str):
        parsed = int(value, 0)
    else:
        raise TypeError(f"{field} must be a non-negative integer")
    if parsed < 0:
        raise ValueError(f"{field} must be a non-negative integer")
    return parsed


def _load_runtime_artifact(path: Path, expected_type: str | None):
    try:
        payload = load_yaml_file(path)
    except Exception as exc:  # noqa: BLE001 - runtime validation reports a stable artifact issue.
        return None, [f"{path}: unable to read YAML ({exc})"], []
    if not isinstance(payload, dict):
        return None, [f"{path}: YAML top level must be a mapping"], []

    issues: list[str] = []
    inspections: list[dict] = []
    if any(field in payload for field in ("name", "type", "kind")):
        issues.append(f"{path}: legacy name/type/kind fields are not accepted")
    symbol_type = expected_type
    identity_fields = {"func_name", "gv_name", "patch_name", "vtable_class", "member_name", "struct_name"}
    if symbol_type is not None or identity_fields.intersection(payload):
        try:
            normalized = normalize_symbol_artifact(payload, category=symbol_type)
            if normalized != payload:
                raise SymbolArtifactError("symbol fields are not normalized")
        except SymbolArtifactError as exc:
            issues.append(f"{path}: invalid symbol artifact ({exc})")

    if symbol_type == "func" and not any(field in payload for field in ("func_va", "func_addr")):
        issues.append(f"{path}: func artifact requires func_va or func_addr")

    for field, raw_value in payload.items():
        if not (field.endswith("_va") or field in {"func_addr", "gv_addr", "patch_addr", "vtable_addr"}):
            continue
        try:
            address = _parse_artifact_integer(raw_value, field)
        except (TypeError, ValueError) as exc:
            issues.append(f"{path}: {exc}")
            continue
        rva_field = f"{field[:-3]}_rva" if field.endswith("_va") else None
        rva = None
        if rva_field and rva_field in payload:
            try:
                rva = _parse_artifact_integer(payload[rva_field], rva_field)
            except (TypeError, ValueError) as exc:
                issues.append(f"{path}: {exc}")
        inspections.append(
            {
                "path": str(path),
                "field": field,
                "address": address,
                "rva_field": rva_field,
                "rva": rva,
                "require_function": symbol_type in {"func", "vfunc"} and field in {"func_va", "func_addr", "vfunc_va"},
            }
        )
    return payload, issues, inspections


async def _inspect_runtime_addresses(mcp_runtime: McpRuntime, inspections: list[dict]) -> list[str]:
    issues: list[str] = []
    try:
        async with open_ida_mcp_session(
            mcp_runtime.host,
            mcp_runtime.port,
            expected_binary=mcp_runtime.expected_binary,
            explicit_database=mcp_runtime.binding.session_id,
        ) as session:
            for inspection in inspections:
                code = (
                    "import ida_funcs, ida_segment, idaapi, json\n"
                    f"ea = {inspection['address']}\n"
                    "seg = ida_segment.getseg(ea)\n"
                    "func = ida_funcs.get_func(ea)\n"
                    "result = json.dumps({\n"
                    "  'has_segment': seg is not None,\n"
                    "  'segment_name': ida_segment.get_segm_name(seg) if seg is not None else '',\n"
                    "  'image_base': hex(int(idaapi.get_imagebase())),\n"
                    "  'has_function': func is not None,\n"
                    "  'function_start': hex(int(func.start_ea)) if func is not None else '',\n"
                    "  'is_function_start': bool(func is not None and int(func.start_ea) == ea),\n"
                    "})\n"
                )
                payload = _parse_py_eval_json(await session.call_tool("py_eval", {"code": code}))
                if not isinstance(payload, dict):
                    raise ArtifactValidationUnavailable("py_eval returned no address inspection payload")
                label = f"{inspection['path']}: {inspection['field']}={hex(inspection['address'])}"
                if not payload.get("has_segment"):
                    issues.append(f"{label} is not mapped to any segment")
                    continue
                if inspection["require_function"]:
                    segment_name = str(payload.get("segment_name", ""))
                    if segment_name != ".text":
                        issues.append(f"{label} resolves to segment {segment_name!r} instead of '.text'")
                    elif not payload.get("has_function"):
                        issues.append(f"{label} does not resolve to a function")
                    elif not payload.get("is_function_start"):
                        issues.append(
                            f"{label} resolves inside function {payload.get('function_start') or '<unknown>'}"
                        )
                if inspection["rva"] is not None:
                    try:
                        image_base = _parse_artifact_integer(payload.get("image_base"), "image_base")
                    except (TypeError, ValueError) as exc:
                        raise ArtifactValidationUnavailable(str(exc)) from exc
                    if inspection["address"] - image_base != inspection["rva"]:
                        issues.append(
                            f"{inspection['path']}: {inspection['rva_field']} does not match "
                            f"{inspection['field']} - image_base"
                        )
    except ArtifactValidationUnavailable:
        raise
    except Exception as exc:
        raise ArtifactValidationUnavailable(str(exc)) from exc
    return issues


def validate_runtime_artifacts(
    paths,
    *,
    module_dir: Path,
    artifact_types: dict[str, str],
    mcp_runtime: McpRuntime | None,
) -> list[str]:
    issues: list[str] = []
    inspections: list[dict] = []
    module_root = module_dir.resolve()
    for raw_path in paths:
        path = Path(raw_path).resolve()
        _payload, artifact_issues, artifact_inspections = _load_runtime_artifact(
            path,
            artifact_types.get(_artifact_path_key(path)),
        )
        issues.extend(artifact_issues)
        if path.parent == module_root:
            inspections.extend(artifact_inspections)
    if inspections:
        if mcp_runtime is None:
            raise ArtifactValidationUnavailable("MCP runtime is required for current-binary address validation")
        issues.extend(asyncio.run(_inspect_runtime_addresses(mcp_runtime, inspections)))
    return issues


def _validate_artifacts_with_recovery(
    paths,
    *,
    module_dir: Path,
    artifact_types: dict[str, str],
    mcp_runtime: McpRuntime | None,
    ensure_mcp_ready=None,
):
    try:
        return validate_runtime_artifacts(
            paths,
            module_dir=module_dir,
            artifact_types=artifact_types,
            mcp_runtime=mcp_runtime,
        ), mcp_runtime
    except ArtifactValidationUnavailable as first_error:
        if ensure_mcp_ready is None:
            raise PipelineFailure("mcp_unavailable", str(first_error)) from first_error
        try:
            recovered_runtime = ensure_mcp_ready()
        except Exception as exc:
            raise PipelineFailure("mcp_unavailable", str(exc)) from exc
        try:
            return validate_runtime_artifacts(
                paths,
                module_dir=module_dir,
                artifact_types=artifact_types,
                mcp_runtime=recovered_runtime,
            ), recovered_runtime
        except ArtifactValidationUnavailable as exc:
            raise PipelineFailure("mcp_unavailable", str(exc)) from exc


def _run_preprocessor(**kwargs):
    return asyncio.run(preprocess_single_skill_via_mcp(**kwargs))


def run_analysis_pipeline(
    node,
    *,
    binary_path: Path,
    game_root: Path,
    old_game_root: Path | None,
    agent: str,
    reporting: AnalysisReporting | None = None,
    task_id: str | None = None,
    agent_model: str = DEFAULT_AGENT_MODEL,
    llm_config: dict | None = None,
    mcp_runtime: McpRuntime | None = None,
    ensure_mcp_ready=None,
    skip_preprocessors: bool = False,
    debug: bool = False,
    symbol_aliases: dict | None = None,
    artifact_types: dict[str, str] | None = None,
    preprocessor_runner=_run_preprocessor,
    agent_skill_runner=agent_runner.run_skill,
) -> PipelineResult:
    binary_path = Path(binary_path).resolve()
    game_root = Path(game_root).resolve()
    module_dir = (game_root / node.module).resolve()
    required, optional = _outputs(node, game_root)
    required = [path.resolve() for path in required]
    optional = [path.resolve() for path in optional]
    existing_reason = _node_existing_output_reason(node, game_root)
    if existing_reason is not None:
        return PipelineResult("skipped", "existing", existing_reason.value)

    if reporting is not None and task_id is not None:
        reporting.emit_task_status(task_id, TaskStatus.RUNNING, ProcessPhase.VALIDATING_INPUTS)

    required_inputs = [(game_root / Path(*PurePosixPath(name).parts)).resolve() for name in node.required_inputs]
    optional_inputs = [(game_root / Path(*PurePosixPath(name).parts)).resolve() for name in node.optional_inputs]
    overlap = sorted(
        {_artifact_path_key(path) for path in required_inputs} & {_artifact_path_key(path) for path in optional_inputs}
    )
    if overlap:
        raise PipelineFailure(
            "invalid_input",
            f"Skill {node.id} declares the same artifact as required and optional input",
            {"overlapping_inputs": overlap},
        )
    missing_inputs = [str(path) for path in required_inputs if not path.is_file()]
    if missing_inputs:
        raise PipelineFailure(
            "missing_input",
            f"Skill {node.id} is missing required inputs: {', '.join(Path(path).name for path in missing_inputs)}",
            {"missing_inputs": missing_inputs},
        )
    existing_optional_inputs = [path for path in optional_inputs if path.is_file()]
    missing_optional_inputs = [str(path) for path in optional_inputs if not path.is_file()]
    if missing_optional_inputs and reporting is not None and task_id is not None:
        reporting.emit_progress(
            task_id,
            ProcessPhase.VALIDATING_INPUTS,
            event="optional_input_missing",
            missing_optional_inputs=missing_optional_inputs,
        )

    runtime = mcp_runtime
    artifact_types = artifact_types or {}
    input_paths = [*required_inputs, *existing_optional_inputs]
    if input_paths:
        input_issues, runtime = _validate_artifacts_with_recovery(
            input_paths,
            module_dir=module_dir,
            artifact_types=artifact_types,
            mcp_runtime=runtime,
            ensure_mcp_ready=ensure_mcp_ready,
        )
        if input_issues:
            raise PipelineFailure(
                "invalid_input",
                f"Skill {node.id} has invalid input artifacts",
                {"invalid_inputs": input_issues},
            )

    expected_outputs = [str(path) for path in (*required, *optional)]
    old_yaml_map = None
    if old_game_root is not None:
        old_root = Path(old_game_root).resolve()
        old_yaml_map = {
            path: str((old_root / Path(path).resolve().relative_to(game_root)).resolve()) for path in expected_outputs
        }

    preprocess_status = PREPROCESS_STATUS_NO_SCRIPT
    if not skip_preprocessors:
        if reporting is not None and task_id is not None:
            reporting.emit_task_status(task_id, TaskStatus.RUNNING, ProcessPhase.PREPROCESSING)

        def report_preprocessor_diagnostic(payload):
            detail = {key: value for key, value in payload.items() if key != "skill"}
            if reporting is not None and task_id is not None:
                reporting.emit_progress(
                    task_id,
                    ProcessPhase.PREPROCESSING,
                    event="preprocessor_diagnostic",
                    **detail,
                )

        effective_llm_config = dict(llm_config or {})
        try:
            raw_preprocess_status = preprocessor_runner(
                host=runtime.host if runtime is not None else DEFAULT_HOST,
                port=runtime.port if runtime is not None else DEFAULT_PORT,
                skill_name=node.skill,
                expected_outputs=expected_outputs,
                expected_inputs=[str(path) for path in required_inputs],
                optional_inputs=[str(path) for path in optional_inputs],
                old_yaml_map=old_yaml_map,
                new_binary_dir=str(module_dir),
                platform=node.platform,
                expected_binary=str(binary_path),
                explicit_database=runtime.binding.session_id if runtime is not None else None,
                llm_model=effective_llm_config.get("model"),
                llm_apikey=effective_llm_config.get("api_key"),
                llm_baseurl=effective_llm_config.get("base_url"),
                llm_temperature=effective_llm_config.get("temperature"),
                llm_effort=effective_llm_config.get("effort"),
                llm_fake_as=effective_llm_config.get("fake_as"),
                llm_max_retries=node.max_retries,
                symbol_aliases=symbol_aliases,
                debug=debug,
                diagnostic_callback=report_preprocessor_diagnostic,
            )
        except Exception as exc:  # noqa: BLE001 - runner failures use the normal Agent fallback path.
            _emit_diagnostic(
                "runner_failed",
                node.skill,
                exc,
                diagnostic_callback=report_preprocessor_diagnostic,
                debug=debug,
                exception=exc,
                secrets=(effective_llm_config.get("api_key"),),
            )
            raw_preprocess_status = PREPROCESS_STATUS_FAILED
        preprocess_status = _normalize_preprocess_status(raw_preprocess_status)
        if reporting is not None and task_id is not None:
            reporting.emit_progress(
                task_id,
                ProcessPhase.PREPROCESSING,
                event="preprocessor_completed",
                status=str(preprocess_status),
            )

        if preprocess_status is PREPROCESS_STATUS_SUCCESS:
            missing_outputs = [str(path) for path in required if not path.is_file()]
            if missing_outputs:
                raise PipelineFailure(
                    "preprocess_contract_violation",
                    f"Preprocessor for {node.id} reported success but required outputs are missing",
                    {"missing_outputs": missing_outputs},
                )
            present_optional = [path for path in optional if path.is_file()]
            if not required and optional and not present_optional:
                return PipelineResult("skipped", "preprocessor", "optional_output_absent")
            output_paths = [*required, *present_optional]
            if output_paths:
                if reporting is not None and task_id is not None:
                    reporting.emit_task_status(task_id, TaskStatus.RUNNING, ProcessPhase.VALIDATING_OUTPUTS)
                output_issues, runtime = _validate_artifacts_with_recovery(
                    output_paths,
                    module_dir=module_dir,
                    artifact_types=artifact_types,
                    mcp_runtime=runtime,
                    ensure_mcp_ready=ensure_mcp_ready,
                )
                if output_issues:
                    raise PipelineFailure(
                        "preprocess_contract_violation",
                        f"Preprocessor for {node.id} produced invalid outputs",
                        {"invalid_outputs": output_issues},
                    )
            return PipelineResult("succeeded", "preprocessor")
        if preprocess_status is PREPROCESS_STATUS_ABSENT_OK:
            return PipelineResult("skipped", "preprocessor", "preprocess_absent")
        if not required and optional:
            return PipelineResult("skipped", "preprocessor", "optional_output_absent")

    if ensure_mcp_ready is not None:
        try:
            if reporting is not None and task_id is not None:
                reporting.emit_task_status(task_id, TaskStatus.RUNNING, ProcessPhase.WAITING_FOR_MCP)
            runtime = ensure_mcp_ready()
        except Exception as exc:
            raise PipelineFailure("mcp_unavailable", str(exc)) from exc
    if reporting is not None and task_id is not None:
        reporting.emit_task_status(task_id, TaskStatus.RUNNING, ProcessPhase.AGENT_FALLBACK)
    last_agent_failure = {}

    def report_agent_progress(*, event, **payload):
        if payload.get("reason"):
            last_agent_failure.clear()
            last_agent_failure.update(payload)
        if reporting is not None and task_id is not None:
            reporting.emit_progress(task_id, ProcessPhase.AGENT_FALLBACK, event=event, **payload)

    succeeded = agent_skill_runner(
        node.skill,
        agent=agent,
        expected_yaml_paths=[str(path) for path in required],
        max_retries=node.max_retries,
        model=agent_model,
        debug=debug,
        progress_callback=report_agent_progress,
    )
    if not succeeded:
        raise PipelineFailure(
            "agent_failed",
            f"Agent skill {node.id} failed",
            {"agent_failure": dict(last_agent_failure)},
        )
    missing_outputs = [str(path) for path in required if not path.is_file()]
    if missing_outputs:
        raise PipelineFailure(
            "agent_output_invalid",
            f"Agent skill {node.id} did not produce required outputs",
            {"missing_outputs": missing_outputs},
        )
    present_optional = [path for path in optional if path.is_file()]
    if not required and optional and not present_optional:
        return PipelineResult("skipped", "agent", "optional_output_absent")
    output_paths = [*required, *present_optional]
    if output_paths:
        if reporting is not None and task_id is not None:
            reporting.emit_task_status(task_id, TaskStatus.RUNNING, ProcessPhase.VALIDATING_OUTPUTS)
        output_issues, runtime = _validate_artifacts_with_recovery(
            output_paths,
            module_dir=module_dir,
            artifact_types=artifact_types,
            mcp_runtime=runtime,
            ensure_mcp_ready=ensure_mcp_ready,
        )
        if output_issues:
            raise PipelineFailure(
                "agent_output_invalid",
                f"Agent skill {node.id} produced invalid outputs",
                {"invalid_outputs": output_issues},
            )
    return PipelineResult("succeeded", "agent")


def _select_execution_modules(modules, modules_filter=None, skill_filter=None):
    selected = list(modules)
    if modules_filter is not None:
        requested = list(modules_filter)
        available = {module["name"] for module in selected}
        missing = [name for name in requested if name not in available]
        if missing:
            raise AnalysisRunError(f"Module(s) not found: {', '.join(missing)}")
        selected = [module for module in selected if module["name"] in requested]
    if skill_filter is None:
        return selected
    available_skills = sorted({skill["name"] for module in selected for skill in module["skills"]})
    filtered = []
    for module in selected:
        skills = [skill for skill in module["skills"] if skill["name"] == skill_filter]
        if skills:
            filtered.append({**module, "skills": skills})
    if not filtered:
        available_label = ", ".join(available_skills) or "(none)"
        raise AnalysisRunError(f"Skill '{skill_filter}' not found; available skills: {available_label}")
    return filtered


def _process_reason(value: str | None, default: ProcessReason = ProcessReason.UNKNOWN_ERROR) -> ProcessReason:
    if value is None:
        return default
    aliases = {
        "preprocess_contract_violation": ProcessReason.PREPROCESS_FAILED,
        "agent_output_invalid": ProcessReason.AGENT_FAILED,
        "invalid_pipeline_result": ProcessReason.UNKNOWN_ERROR,
        "runtime_error": ProcessReason.UNKNOWN_ERROR,
    }
    if value in aliases:
        return aliases[value]
    try:
        return ProcessReason(value)
    except ValueError:
        return default


def _execute_analysis_node(
    node,
    *,
    binary,
    root,
    old_root,
    agent,
    agent_model,
    llm_config,
    skip_preprocessors,
    debug,
    reporting: AnalysisReporting,
    run_summary,
    skip_error,
    mcp_runtime=None,
    ensure_mcp_ready=None,
    symbol_aliases=None,
    artifact_types=None,
):
    task_id = reporting.task_id_for(node.id)
    existing_reason = _node_existing_output_reason(node, root)
    if existing_reason is not None:
        run_summary.skipped += 1
        reporting.emit_task_status(
            task_id,
            TaskStatus.SKIPPED,
            ProcessPhase.FINISHED,
            reason=existing_reason,
            message=f"Skill {node.id} already has outputs that satisfy its skip contract",
        )
        return True

    reporting.emit_task_status(task_id, TaskStatus.RUNNING, ProcessPhase.PREFLIGHT)
    try:
        result = run_analysis_pipeline(
            node,
            binary_path=binary,
            game_root=root,
            old_game_root=old_root,
            agent=agent,
            agent_model=agent_model,
            llm_config=llm_config,
            mcp_runtime=mcp_runtime,
            ensure_mcp_ready=ensure_mcp_ready,
            skip_preprocessors=skip_preprocessors,
            debug=debug,
            symbol_aliases=symbol_aliases,
            artifact_types=artifact_types,
            reporting=reporting,
            task_id=task_id,
        )
        if result.status == "succeeded":
            run_summary.successful += 1
            reporting.emit_task_status(task_id, TaskStatus.SUCCEEDED, ProcessPhase.FINISHED)
        elif result.status == "skipped":
            run_summary.skipped += 1
            reporting.emit_task_status(
                task_id,
                TaskStatus.SKIPPED,
                ProcessPhase.FINISHED,
                reason=_process_reason(result.reason),
            )
        else:
            raise PipelineFailure(
                "invalid_pipeline_result",
                f"Skill {node.id} returned unsupported pipeline status {result.status!r}",
            )
    except PipelineFailure as exc:
        run_summary.failed += 1
        reporting.emit_task_status(
            task_id,
            TaskStatus.FAILED,
            ProcessPhase.FINISHED,
            reason=_process_reason(exc.reason),
            error=str(exc),
            payload={"raw_reason": exc.reason, **exc.payload},
        )
        message = f"Skill {node.id} failed [{exc.reason}]: {exc}"
        if not skip_error:
            raise AnalysisRunError(message) from exc
        print(f"Error: {message}; continuing (-skip_error)")
        return False
    except Exception as exc:
        run_summary.failed += 1
        reporting.emit_task_status(
            task_id,
            TaskStatus.FAILED,
            ProcessPhase.FINISHED,
            reason=ProcessReason.UNKNOWN_ERROR,
            error=str(exc),
        )
        message = f"Skill {node.id} failed: {exc}"
        if not skip_error:
            raise AnalysisRunError(message) from exc
        print(f"Error: {message}; continuing (-skip_error)")
        return False
    return True


def _record_lifecycle_failures(nodes, *, error, reporting, run_summary):
    for node in nodes:
        run_summary.failed += 1
        reporting.emit_task_status(
            reporting.task_id_for(node.id),
            TaskStatus.ABORTED,
            ProcessPhase.FINISHED,
            reason=ProcessReason.MCP_UNAVAILABLE,
            error=str(error),
        )


def analyze(
    *,
    gamever: str,
    config_path: str | Path,
    bindir: str | Path = DEFAULT_BIN_DIR,
    platforms=PLATFORMS,
    oldgamever: str | None = None,
    modules_filter=None,
    skill_filter: str | None = None,
    agent: str = DEFAULT_AGENT,
    agent_model: str = DEFAULT_AGENT_MODEL,
    llm_config: dict | None = None,
    max_retries: int = 3,
    skip_error: bool = False,
    skip_preprocessors: bool = False,
    debug: bool = False,
    host: str = DEFAULT_HOST,
    port: int = DEFAULT_PORT,
    ida_args: str = "",
    reporter: ProcessReporter | None = None,
    run_id: str | None = None,
    summary: AnalysisSummary | None = None,
) -> ExecutionPlan:
    process_reporter = BestEffortProcessReporter(reporter or NullProcessReporter())
    run_summary = summary if summary is not None else AnalysisSummary()
    try:
        tag = validated_tag(gamever)
        if oldgamever is not None:
            validated_tag(oldgamever)
            if _split_gamever(oldgamever)[0] != _split_gamever(tag)[0]:
                raise AnalysisRunError(f"Old game version must use the same game family as {tag}: {oldgamever}")
        document, all_modules = load_config(config_path)
        symbol_aliases = _symbol_alias_map_from_document(document)
        modules = _select_execution_modules(all_modules, modules_filter, skill_filter)
        plan = _build_execution_plan(
            modules,
            platforms=platforms,
            bin_dir=bindir,
            tag=tag,
            default_max_retries=max_retries,
            declared_modules=[module["name"] for module in all_modules],
        )
        process_plan = build_process_execution_plan(plan, modules, platforms=platforms, bin_dir=bindir)
        root = Path(bindir) / tag
        old_root = Path(bindir) / oldgamever if oldgamever else None
        artifact_types = _artifact_type_map(all_modules, root)
        validated_binaries: dict[tuple[str, str], Path] = {}
        module_map = {module["name"]: module for module in modules}
        nodes_by_binary: dict[tuple[str, str], list] = {}
        for node in plan.nodes:
            nodes_by_binary.setdefault((node.module, node.platform), []).append(node)
        initialized_run_id = process_reporter.initialize_run(process_plan.to_dict(), run_id=run_id)
        reporting = AnalysisReporting(process_reporter, initialized_run_id, process_plan)
    except BaseException:
        try:
            failed_plan = ProcessExecutionPlan(warnings=[ProcessReason.GRAPH_INVALID])
            failed_run_id = process_reporter.initialize_run(failed_plan.to_dict(), run_id=run_id)
            failed_reporting = AnalysisReporting(process_reporter, failed_run_id, failed_plan)
            failed_reporting.emit_run_status(RunStatus.FAILED)
            process_reporter.finalize_run(failed_run_id, RunStatus.FAILED, failed_reporting.summary())
        finally:
            process_reporter.flush()
            process_reporter.close()
        raise
    try:
        reporting.emit_run_status(RunStatus.RUNNING)
        process_reporter.heartbeat(initialized_run_id)
        for (module_name, platform), binary_nodes in nodes_by_binary.items():
            configured = module_map[module_name].get(f"path_{platform}")
            binary = Path(get_binary_path(bindir, tag, module_name, configured))
            job_id = reporting.job_id_for(binary_nodes[0].id)
            reporting.emit_task_status(job_id, TaskStatus.RUNNING, ProcessPhase.VALIDATING_BINARY)
            try:
                validate_binary(binary, platform)
                validated_binaries[(module_name, platform)] = binary
            except (BinaryFormatError, OSError) as exc:
                run_summary.failed += len(binary_nodes)
                reason = (
                    ProcessReason.MISSING_BINARY if not binary.is_file() else ProcessReason.BINARY_VERIFICATION_FAILED
                )
                reporting.emit_task_status(
                    job_id,
                    TaskStatus.FAILED,
                    ProcessPhase.FINISHED,
                    reason=reason,
                    error=str(exc),
                )
                reporting.finish_job_tasks(
                    job_id,
                    TaskStatus.ABORTED,
                    reason,
                    f"Binary validation failed for {module_name}:{platform}",
                )
                message = f"Binary validation failed for {module_name}:{platform}: {exc}"
                if not skip_error:
                    raise AnalysisRunError(message) from exc
                print(f"Error: {message}; continuing (-skip_error)")

        for binary_key, binary_nodes in nodes_by_binary.items():
            if binary_key not in validated_binaries:
                continue
            binary = validated_binaries[binary_key]
            job_id = reporting.job_id_for(binary_nodes[0].id)
            failures_before_job = run_summary.failed
            existing_nodes = [node for node in binary_nodes if _node_existing_output_reason(node, root) is not None]
            pending_nodes = [node for node in binary_nodes if node not in existing_nodes]
            for node in existing_nodes:
                _execute_analysis_node(
                    node,
                    binary=binary,
                    root=root,
                    old_root=old_root,
                    agent=agent,
                    agent_model=agent_model,
                    llm_config=llm_config,
                    skip_preprocessors=skip_preprocessors,
                    debug=debug,
                    reporting=reporting,
                    run_summary=run_summary,
                    skip_error=skip_error,
                    symbol_aliases=symbol_aliases,
                    artifact_types=artifact_types,
                )
            if pending_nodes:
                reporting.emit_task_status(job_id, TaskStatus.RUNNING, ProcessPhase.WAITING_FOR_MCP)
                try:
                    with IdaMcpLifecycle(binary, binary_key[1], host, port, ida_args, debug) as lifecycle:
                        for index, node in enumerate(pending_nodes):
                            if index:
                                try:
                                    lifecycle.ensure_ready()
                                except McpLifecycleError as exc:
                                    remaining = pending_nodes[index:]
                                    _record_lifecycle_failures(
                                        remaining,
                                        error=exc,
                                        reporting=reporting,
                                        run_summary=run_summary,
                                    )
                                    message = (
                                        f"MCP lifecycle failed for {node.module}:{node.platform}; "
                                        f"aborting {len(remaining)} remaining skill(s): {exc}"
                                    )
                                    if not skip_error:
                                        raise AnalysisRunError(message) from exc
                                    print(f"Error: {message}; continuing (-skip_error)")
                                    break
                            _execute_analysis_node(
                                node,
                                binary=binary,
                                root=root,
                                old_root=old_root,
                                agent=agent,
                                agent_model=agent_model,
                                llm_config=llm_config,
                                skip_preprocessors=skip_preprocessors,
                                debug=debug,
                                reporting=reporting,
                                run_summary=run_summary,
                                skip_error=skip_error,
                                mcp_runtime=lifecycle.runtime,
                                ensure_mcp_ready=lifecycle.ensure_ready,
                                symbol_aliases=symbol_aliases,
                                artifact_types=artifact_types,
                            )
                except McpLifecycleError as exc:
                    _record_lifecycle_failures(
                        pending_nodes,
                        error=exc,
                        reporting=reporting,
                        run_summary=run_summary,
                    )
                    message = f"MCP lifecycle failed for {binary_key[0]}:{binary_key[1]}: {exc}"
                    if not skip_error:
                        raise AnalysisRunError(message) from exc
                    print(f"Error: {message}; continuing (-skip_error)")
            reporting.emit_task_status(
                job_id,
                TaskStatus.FAILED if run_summary.failed > failures_before_job else TaskStatus.SUCCEEDED,
                ProcessPhase.FINISHED,
            )

        reporting.abort_pending(ProcessReason.UPSTREAM_ABORTED, "Task was not executed before run end")
        final_status = RunStatus.FAILED if run_summary.failed else RunStatus.SUCCEEDED
        reporting.emit_run_status(final_status)
        process_reporter.finalize_run(initialized_run_id, final_status, reporting.summary())
        return plan
    except BaseException:
        reporting.abort_pending(ProcessReason.UNKNOWN_ERROR, "Run terminated by an unexpected exception")
        reporting.emit_run_status(RunStatus.FAILED)
        process_reporter.finalize_run(initialized_run_id, RunStatus.FAILED, reporting.summary())
        raise
    finally:
        process_reporter.flush()
        process_reporter.close()


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Analyze PE32/ELF32 GoldSrc binaries", allow_abbrev=False)
    parser.add_argument(
        "-configyaml",
        default=None,
        help="Analysis config path; defaults to configs/<GAMEVER>.yaml",
    )
    parser.add_argument("-bindir", default=DEFAULT_BIN_DIR, help="Directory containing copied binaries")
    parser.add_argument(
        "-gamever",
        default=os.environ.get("GSVIBE_GAMEVER"),
        help="Game version tag (required, or set GSVIBE_GAMEVER)",
    )
    parser.add_argument(
        "-platform",
        default=DEFAULT_PLATFORM,
        help="Platforms to analyze, comma-separated (default: windows,linux)",
    )
    parser.add_argument(
        "-agent",
        default=os.environ.get("GSVIBE_AGENT", DEFAULT_AGENT),
        help="Agent executable (default: claude, or set GSVIBE_AGENT)",
    )
    parser.add_argument(
        "-agent_model",
        default=os.environ.get("GSVIBE_AGENT_MODEL", DEFAULT_AGENT_MODEL),
        help="Optional model for the selected Agent (or set GSVIBE_AGENT_MODEL)",
    )
    parser.add_argument(
        "-modules", default=DEFAULT_MODULES, help="Modules to analyze, comma-separated; '*' selects all"
    )
    parser.add_argument("-skill", default=None, help="Exact skill name to run")
    parser.add_argument(
        "-llm_model",
        default=os.environ.get("GSVIBE_LLM_MODEL", DEFAULT_LLM_MODEL),
        help="OpenAI-compatible model for LLM preprocessing (or set GSVIBE_LLM_MODEL)",
    )
    parser.add_argument(
        "-llm_apikey",
        default=os.environ.get("GSVIBE_LLM_APIKEY"),
        help="OpenAI-compatible API key (or set GSVIBE_LLM_APIKEY)",
    )
    parser.add_argument(
        "-llm_baseurl",
        default=os.environ.get("GSVIBE_LLM_BASEURL"),
        help="Optional OpenAI-compatible base URL (or set GSVIBE_LLM_BASEURL)",
    )
    parser.add_argument(
        "-llm_temperature",
        default=os.environ.get("GSVIBE_LLM_TEMPERATURE"),
        help="Optional LLM temperature from 0 through 2 (or set GSVIBE_LLM_TEMPERATURE)",
    )
    parser.add_argument(
        "-llm_fake_as",
        default=os.environ.get("GSVIBE_LLM_FAKE_AS"),
        help="Optional 'codex' compatibility override (or set GSVIBE_LLM_FAKE_AS)",
    )
    parser.add_argument(
        "-llm_effort",
        default=os.environ.get("GSVIBE_LLM_EFFORT"),
        help="LLM reasoning effort (default: medium, or set GSVIBE_LLM_EFFORT)",
    )
    parser.add_argument("-debug", action="store_true", help="Enable debug diagnostics and Agent output")
    parser.add_argument("-ida_args", default="", help="Additional arguments for idalib-mcp")
    parser.add_argument("-skip_error", action="store_true", help="Continue after runtime failures")
    parser.add_argument("-skip_pp", action="store_true", help="Skip the single preprocessor and run Agent directly")
    parser.add_argument("-maxretry", type=int, default=3, help="Default total attempts per skill (1-20)")
    parser.add_argument(
        "-oldgamever",
        default=None,
        help="Old version for analysis context; auto-selects the latest older same-family version, or 'none'",
    )
    parser.add_argument(
        "-process_reporter",
        choices=("none", "console", "redis"),
        default=os.environ.get("GSVIBE_PROCESS_REPORTER", "none"),
        help="Process reporter backend (default: none, or set GSVIBE_PROCESS_REPORTER)",
    )
    parser.add_argument(
        "-redis_url",
        default=os.environ.get("GSVIBE_REDIS_URL", DEFAULT_REDIS_URL),
        help="Redis URL for process reporting (or set GSVIBE_REDIS_URL)",
    )
    parser.add_argument(
        "-redis_prefix",
        default=os.environ.get("GSVIBE_REDIS_PREFIX", DEFAULT_REDIS_PREFIX),
        help="Redis key prefix for process reporting (or set GSVIBE_REDIS_PREFIX)",
    )
    parser.add_argument(
        "-run_id",
        default=os.environ.get("GSVIBE_RUN_ID"),
        help="Existing scheduler-created run ID (or set GSVIBE_RUN_ID)",
    )
    return parser


def _parse_csv(parser, value, option, *, allowed=None):
    raw = str(value)
    parts = [part.strip() for part in raw.split(",")]
    if not parts or any(not part for part in parts):
        parser.error(f"{option} must be a comma-separated list of non-empty values")
    normalized = [part.casefold() for part in parts]
    if len(set(normalized)) != len(normalized):
        parser.error(f"{option} cannot contain duplicate values")
    if allowed is not None:
        invalid = [part for part in parts if part not in allowed]
        if invalid:
            parser.error(f"Invalid {option.lstrip('-')}: {', '.join(invalid)}. Must be one of: {', '.join(allowed)}")
    return parts


def _optional_text(value):
    if value is None:
        return None
    return str(value).strip() or None


def parse_args(argv=None):
    parser = _parser()
    raw_argv = list(sys.argv[1:] if argv is None else argv)
    for token in raw_argv:
        option = token.split("=", 1)[0]
        if option in REMOVED_CLI_OPTIONS:
            parser.error(f"unrecognized arguments: {token}")
    args = parser.parse_args(raw_argv)
    args.gamever = _optional_text(args.gamever)
    if args.gamever is None:
        parser.error("-gamever is required, or set GSVIBE_GAMEVER")
    try:
        validated_tag(args.gamever)
    except AnalysisConfigError as exc:
        parser.error(str(exc))

    args.platforms = _parse_csv(parser, args.platform, "-platform", allowed=PLATFORMS)
    args.modules = str(args.modules).strip()
    if args.modules == "*":
        args.module_filter = None
    else:
        args.module_filter = _parse_csv(parser, args.modules, "-modules")
        if "*" in args.module_filter:
            parser.error("-modules '*' must be used alone")

    if args.skill is not None:
        args.skill = str(args.skill).strip()
        if not args.skill:
            parser.error("-skill cannot be empty")

    args.agent = str(args.agent).strip()
    if not args.agent or agent_runner.detect_agent_kind(args.agent) is None:
        parser.error("-agent must identify a claude, codex, or opencode executable")
    args.agent_model = str(args.agent_model or "").strip()
    args.llm_model = str(args.llm_model).strip()
    if not args.llm_model:
        parser.error("-llm_model cannot be empty")
    args.llm_apikey = _optional_text(args.llm_apikey)
    args.llm_baseurl = _optional_text(args.llm_baseurl)
    try:
        args.llm_temperature = validated_temperature(args.llm_temperature)
    except ValueError as exc:
        parser.error(str(exc))
    args.llm_fake_as = _optional_text(args.llm_fake_as)
    if args.llm_fake_as is not None:
        args.llm_fake_as = args.llm_fake_as.casefold()
        if args.llm_fake_as != "codex":
            parser.error("-llm_fake_as must be 'codex' when set")
        if args.llm_baseurl is None:
            parser.error("-llm_baseurl is required when -llm_fake_as=codex")
    args.llm_effort = (_optional_text(args.llm_effort) or "medium").casefold()
    if args.llm_effort not in LLM_EFFORTS:
        parser.error(f"-llm_effort must be one of: {', '.join(sorted(LLM_EFFORTS))}")
    if not 1 <= args.maxretry <= 20:
        parser.error("-maxretry must be an integer from 1 to 20")
    args.ida_args = str(args.ida_args or "").strip()
    args.run_id = _optional_text(args.run_id)
    if args.run_id is not None and not RUN_ID_RE.fullmatch(args.run_id):
        parser.error("-run_id must contain 1-160 letters, digits, '.', '_', ':', or '-'")
    args.redis_prefix = str(args.redis_prefix).strip().strip(":")
    if not args.redis_prefix:
        parser.error("-redis_prefix cannot be empty")

    if args.oldgamever is None:
        args.oldgamever = (
            None if _is_major_update_gamever(args.gamever) else resolve_oldgamever(args.gamever, args.bindir)
        )
    else:
        args.oldgamever = str(args.oldgamever).strip()
        if not args.oldgamever:
            parser.error("-oldgamever cannot be empty")
        if args.oldgamever.casefold() == "none":
            args.oldgamever = None
        else:
            try:
                old_family, _old_build = _split_gamever(args.oldgamever)
            except (AnalysisConfigError, ValueError) as exc:
                parser.error(str(exc))
            current_family, _current_build = _split_gamever(args.gamever)
            if old_family != current_family:
                parser.error("-oldgamever must use the same game family as -gamever")
    return args


def _llm_config_from_args(args) -> dict:
    return {
        "model": args.llm_model,
        "api_key": args.llm_apikey,
        "base_url": args.llm_baseurl,
        "temperature": args.llm_temperature,
        "effort": args.llm_effort,
        "fake_as": args.llm_fake_as,
        "max_retries": args.maxretry,
    }


def _print_main_configuration(args) -> None:
    print(f"Config file: {args.configyaml}")
    print(f"Binary directory: {args.bindir}")
    print(f"Game version: {args.gamever}")
    print(f"Old game version: {args.oldgamever or '(disabled)'}")
    print(f"Platforms: {', '.join(args.platforms)}")
    print(f"Modules filter: {args.modules}")
    if args.skill:
        print(f"Skill filter: {args.skill}")
    print(f"Agent: {args.agent}")
    print(f"Process reporter: {args.process_reporter}")
    if args.run_id:
        print(f"Run ID: {args.run_id}")
    if args.ida_args:
        print(f"IDA arguments: {args.ida_args}")
    if args.debug:
        print("Debug mode: enabled")
    if args.skip_error:
        print("Skip error mode: enabled")
    if args.skip_pp:
        print("Agent Skill only mode: enabled (-skip_pp)")


def _print_summary(summary: AnalysisSummary) -> None:
    print("\nSummary")
    print(f"  Successful: {summary.successful}")
    print(f"  Failed: {summary.failed}")
    print(f"  Skipped: {summary.skipped}")


def main(argv=None) -> int:
    args = parse_args(argv)
    summary = AnalysisSummary()
    try:
        args.configyaml = str(resolve_analysis_config(args.gamever, args.configyaml))
        _print_main_configuration(args)
        reporter = create_process_reporter(args)
        analyze(
            gamever=args.gamever,
            oldgamever=args.oldgamever,
            config_path=args.configyaml,
            bindir=args.bindir,
            platforms=args.platforms,
            modules_filter=args.module_filter,
            skill_filter=args.skill,
            agent=args.agent,
            agent_model=args.agent_model,
            llm_config=_llm_config_from_args(args),
            max_retries=args.maxretry,
            skip_error=args.skip_error,
            skip_preprocessors=args.skip_pp,
            debug=args.debug,
            ida_args=args.ida_args,
            reporter=reporter,
            run_id=args.run_id,
            summary=summary,
        )
    except (
        AnalysisConfigError,
        AnalysisPlanError,
        AnalysisRunError,
        BinaryFormatError,
        ProcessReporterConfigurationError,
        OSError,
        yaml.YAMLError,
    ) as exc:
        print(f"Error: {exc}")
        if summary.successful or summary.failed or summary.skipped:
            _print_summary(summary)
        return 1
    _print_summary(summary)
    return 1 if summary.failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
