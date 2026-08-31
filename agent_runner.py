"""Agent CLI execution, MCP preflight, retries, and output validation."""

from __future__ import annotations

import ipaddress
import json
import os
import re
import subprocess
import sys
import threading
import tempfile
import urllib.parse
import uuid
from collections.abc import Callable
from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import Path

SKILL_TIMEOUT = 1200
MCP_LIST_TIMEOUT = 30
PROCESS_KILL_WAIT_TIMEOUT = 1
DIAGNOSTIC_OUTPUT_LIMIT = 4000
SAFE_SKILL_RE = re.compile(r"^[A-Za-z0-9_.-]+$", re.ASCII)
SKILL_ERROR_RE = re.compile(r"<skill_error>\s*(.*?)\s*</skill_error>", re.IGNORECASE | re.DOTALL)
CYBERSECURITY_BLOCK_MARKERS = (
    "This chat was flagged for possible cybersecurity risk",
    "flagged this message for a cybersecurity topic",
)
ANSI_ESCAPE_RE = re.compile(r"\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])")
CLAUDE_SKILL_RUNNER_SETTINGS = ".claude/skill_runner.settings.json"
SKILL_RUNNER_SYSTEM_PROMPT = ".claude/SKILL_RUNNER.md"
OPENCODE_SKILL_RUNNER_CONFIG = ".opencode/skill_runner.config.json"
DEFAULT_AGENT_MODEL = ""
LOOPBACK_HOST_LITERALS = frozenset({"localhost", "127.0.0.1", "::1"})


@dataclass(frozen=True)
class AgentCommand:
    args: list[str]
    input_text: str | None
    retry_target_desc: str


@dataclass(frozen=True)
class McpPreflightResult:
    ok: bool
    reason: str | None = None
    detail: dict[str, object] = field(default_factory=dict)


_MCP_PREFLIGHT_CACHE: dict[tuple[str, str, str | None], McpPreflightResult] = {}


def detect_agent_kind(agent: str) -> str | None:
    lowered = str(agent).lower()
    return next((kind for kind in ("claude", "codex", "opencode") if kind in lowered), None)


def _is_loopback_host(host: str) -> bool:
    if host in LOOPBACK_HOST_LITERALS:
        return True
    try:
        return bool(ipaddress.ip_address(host).is_loopback)
    except ValueError:
        return False


def _normalize_mcp_url(mcp_url: str | None) -> str | None:
    """Validate and canonicalize an owned idalib-mcp HTTP endpoint URL."""
    if mcp_url is None:
        return None
    if not isinstance(mcp_url, str):
        raise ValueError("mcp_url must be a string")
    normalized = mcp_url.strip()
    if not normalized:
        raise ValueError("mcp_url must not be empty")
    try:
        parsed = urllib.parse.urlsplit(normalized)
    except ValueError as error:
        raise ValueError(f"invalid mcp_url: {error}") from error
    if parsed.scheme != "http":
        raise ValueError("mcp_url must use the http scheme")
    if parsed.username is not None or parsed.password is not None:
        raise ValueError("mcp_url must not contain credentials")
    if parsed.query or parsed.fragment:
        raise ValueError("mcp_url must not contain a query or fragment")
    if parsed.path != "/mcp":
        raise ValueError("mcp_url must use the /mcp path")
    host = parsed.hostname
    if not host:
        raise ValueError("mcp_url must include a host")
    if not _is_loopback_host(host):
        raise ValueError("mcp_url host must be a local loopback address")
    try:
        port = parsed.port
    except ValueError as error:
        raise ValueError(f"invalid mcp_url port: {error}") from error
    if port is None or not 1 <= port <= 65535:
        raise ValueError("mcp_url port must be between 1 and 65535")
    formatted_host = f"[{host}]" if ":" in host else host
    return f"http://{formatted_host}:{port}/mcp"


def mcp_endpoint_url(host: str, port: int) -> str:
    """Build the canonical analyzer-owned idalib-mcp endpoint URL from a verified runtime."""
    normalized_host = str(host).strip()
    if normalized_host.startswith("[") and normalized_host.endswith("]"):
        normalized_host = normalized_host[1:-1]
    formatted_host = f"[{normalized_host}]" if ":" in normalized_host else normalized_host
    return _normalize_mcp_url(f"http://{formatted_host}:{port}/mcp")


def _extract_opencode_session_id(output: str) -> str | None:
    for line in (output or "").splitlines():
        try:
            event = json.loads(line)
        except json.JSONDecodeError:
            continue
        if not isinstance(event, dict):
            continue
        session_id = event.get("sessionID")
        if isinstance(session_id, str) and session_id:
            return session_id
    return None


def _extract_skill_error(*texts: str) -> str | None:
    match = SKILL_ERROR_RE.search("\n".join(text for text in texts if text))
    return match.group(1).strip() if match is not None else None


def _extract_cybersecurity_block(*texts: str) -> str | None:
    merged_output = "\n".join(text for text in texts if text).casefold()
    return next((marker for marker in CYBERSECURITY_BLOCK_MARKERS if marker.casefold() in merged_output), None)


def _mcp_list_contains_server(output: str, server_name: str = "ida-pro-mcp") -> bool:
    if not output:
        return False
    normalized_output = ANSI_ESCAPE_RE.sub("", output)
    prefix = r"(?:[-*•●|│T—]\s*)*(?:[✓✗]\s*)?"
    return bool(re.search(rf"(?m)^\s*{prefix}{re.escape(server_name)}(?:\s|:|$)", normalized_output))


def _agent_mcp_override_args(agent_kind: str, mcp_url: str | None) -> list[str]:
    if not mcp_url:
        return []
    if agent_kind == "claude":
        config = {"mcpServers": {"ida-pro-mcp": {"type": "http", "url": mcp_url}}}
        return ["--mcp-config", json.dumps(config, separators=(",", ":")), "--strict-mcp-config"]
    if agent_kind == "codex":
        return [
            "-c",
            f"mcp_servers.ida-pro-mcp.url={json.dumps(mcp_url)}",
            "-c",
            "mcp_servers.ida-pro-mcp.required=true",
        ]
    return []


def _agent_process_env(agent_kind: str, mcp_url: str | None = None) -> dict[str, str] | None:
    if agent_kind != "opencode":
        return None
    env = os.environ.copy()
    env.update(
        {
            "OPENCODE_DISABLE_CLAUDE_CODE_PROMPT": "1",
            "OPENCODE_CONFIG": OPENCODE_SKILL_RUNNER_CONFIG,
        }
    )
    if mcp_url:
        env["OPENCODE_CONFIG_CONTENT"] = json.dumps(
            {
                "mcp": {
                    "ida-pro-mcp": {
                        "type": "remote",
                        "url": mcp_url,
                        "enabled": True,
                    }
                }
            },
            separators=(",", ":"),
        )
    return env


@contextmanager
def _claude_mcp_preflight_workspace(mcp_url: str | None):
    if mcp_url is None:
        yield None
        return
    with tempfile.TemporaryDirectory(prefix="gsvibe-claude-preflight-") as temporary_directory:
        config = {"mcpServers": {"ida-pro-mcp": {"type": "http", "url": mcp_url}}}
        (Path(temporary_directory) / ".mcp.json").write_text(
            json.dumps(config, separators=(",", ":")),
            encoding="utf-8",
        )
        yield temporary_directory


def _truncate_diagnostic(text: str | bytes | None) -> str | None:
    if text is None:
        return None
    if isinstance(text, bytes):
        normalized = text.decode(errors="replace")
    else:
        normalized = str(text)
    normalized = normalized.strip()
    if not normalized:
        return None
    if len(normalized) > DIAGNOSTIC_OUTPUT_LIMIT:
        return normalized[:DIAGNOSTIC_OUTPUT_LIMIT] + "... <truncated>"
    return normalized


def _diagnostic_payload(stdout: str | bytes | None, stderr: str | bytes | None) -> dict[str, str]:
    payload = {}
    normalized_stdout = _truncate_diagnostic(stdout)
    normalized_stderr = _truncate_diagnostic(stderr)
    if normalized_stdout is not None:
        payload["stdout"] = normalized_stdout
    if normalized_stderr is not None:
        payload["stderr"] = normalized_stderr
    return payload


def _notify_progress(progress_callback: Callable[..., None] | None, event: str, **payload) -> None:
    if progress_callback is None:
        return
    try:
        progress_callback(event=event, **payload)
    except Exception as error:  # noqa: BLE001 - reporter failures must not alter Agent execution.
        print(f"    Warning: Skill progress callback failed: {error}")


def _close_text_stream(stream) -> None:
    try:
        stream.close()
    except (OSError, ValueError):
        return


def _drain_text_stream(stream, chunks: list[str], forward_stream=None) -> None:
    try:
        for chunk in iter(stream.readline, ""):
            chunks.append(chunk)
            if forward_stream is not None:
                forward_stream.write(chunk)
                forward_stream.flush()
    finally:
        _close_text_stream(stream)


def _run_process_with_stream_capture(
    command: list[str],
    *,
    agent_input: str | None = None,
    debug: bool = False,
    timeout: int = SKILL_TIMEOUT,
    env: dict[str, str] | None = None,
    cwd: str | Path | None = None,
) -> subprocess.CompletedProcess[str]:
    process = subprocess.Popen(
        command,
        stdin=subprocess.PIPE if agent_input is not None else None,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        env=env,
        cwd=cwd,
    )
    if agent_input is not None and process.stdin is not None:
        process.stdin.write(agent_input)
        process.stdin.flush()
        process.stdin.close()

    stdout_chunks: list[str] = []
    stderr_chunks: list[str] = []
    stdout_thread = threading.Thread(
        target=_drain_text_stream,
        args=(process.stdout, stdout_chunks, sys.stdout if debug else None),
        daemon=True,
    )
    stderr_thread = threading.Thread(
        target=_drain_text_stream,
        args=(process.stderr, stderr_chunks, sys.stderr if debug else None),
        daemon=True,
    )
    stdout_thread.start()
    stderr_thread.start()
    try:
        process.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        process.kill()
        try:
            process.wait(timeout=PROCESS_KILL_WAIT_TIMEOUT)
        except (OSError, subprocess.TimeoutExpired) as error:
            print(f"    Warning: Agent process did not exit cleanly after kill: {error}", file=sys.stderr)
        stdout_thread.join(timeout=PROCESS_KILL_WAIT_TIMEOUT)
        stderr_thread.join(timeout=PROCESS_KILL_WAIT_TIMEOUT)
        raise subprocess.TimeoutExpired(
            command,
            timeout,
            output="".join(stdout_chunks),
            stderr="".join(stderr_chunks),
        ) from None

    stdout_thread.join()
    stderr_thread.join()
    return subprocess.CompletedProcess(
        command,
        process.returncode,
        "".join(stdout_chunks),
        "".join(stderr_chunks),
    )


def _strip_optional_frontmatter(prompt: str) -> str:
    stripped = prompt.strip()
    if not stripped.startswith("---"):
        return stripped
    lines = stripped.splitlines()
    for index, line in enumerate(lines[1:], start=1):
        if line.strip() == "---":
            return "\n".join(lines[index + 1 :]).strip()
    return stripped


def _load_codex_developer_instructions(
    system_prompt_path: Path = Path(".claude/agents/sig-finder.md"),
) -> str | None:
    try:
        raw_prompt = system_prompt_path.read_text(encoding="utf-8")
    except FileNotFoundError:
        print(f"    Error: Codex system prompt file not found: {system_prompt_path}")
        return None
    except OSError as error:
        print(f"    Error: Failed to read Codex system prompt from {system_prompt_path}: {error}")
        return None
    prompt = _strip_optional_frontmatter(raw_prompt)
    if not prompt:
        print(f"    Error: Codex system prompt is empty in {system_prompt_path}")
        return None
    return f"developer_instructions={json.dumps(prompt)}"


def _agent_model_args(agent_kind: str, agent_model: str = DEFAULT_AGENT_MODEL) -> list[str]:
    if agent_kind not in {"claude", "codex", "opencode"}:
        raise ValueError(f"Unsupported agent kind: {agent_kind!r}")
    model = str(agent_model or "").strip()
    if not model:
        return []
    if model.startswith("-") or any(character.isspace() for character in model):
        raise ValueError(f"Invalid {agent_kind} model identifier: {model!r}")
    if agent_kind == "opencode":
        provider, separator, model_name = model.partition("/")
        if not separator or not provider or not model_name:
            raise ValueError("OpenCode model must use provider/model format")
    return ["--model" if agent_kind == "claude" else "-m", model]


def _agent_permission_args(agent_kind: str) -> list[str]:
    if agent_kind == "claude":
        return ["--permission-mode", "auto"]
    if agent_kind == "opencode":
        return ["--auto"]
    return []


def _artifact_context_prompt(artifact_context: dict) -> str:
    return (
        "Invocation artifact contract (JSON). Use these exact paths; do not derive YAML paths from the binary: "
        f"{json.dumps(artifact_context, ensure_ascii=False, sort_keys=True)}"
    )


def _skill_prompt(skill_name: str, artifact_context: dict | None = None) -> str:
    prompt = f"Run SKILL: .claude/skills/{skill_name}/SKILL.md"
    return prompt if artifact_context is None else f"{prompt}\n\n{_artifact_context_prompt(artifact_context)}"


def _build_claude_command(
    agent: str,
    skill_name: str,
    session_id: str,
    is_retry: bool,
    agent_model: str = DEFAULT_AGENT_MODEL,
    mcp_url: str | None = None,
    artifact_context: dict | None = None,
) -> AgentCommand:
    prompt = f"/{skill_name}"
    if artifact_context is not None:
        prompt = f"{prompt}\n\n{_artifact_context_prompt(artifact_context)}"
    args = [agent, "-p", prompt, "--agent", "sig-finder"]
    args.extend(_agent_mcp_override_args("claude", mcp_url))
    args.extend(_agent_model_args("claude", agent_model))
    args.extend(["--settings", CLAUDE_SKILL_RUNNER_SETTINGS])
    args.extend(["--append-system-prompt-file", SKILL_RUNNER_SYSTEM_PROMPT])
    args.extend(_agent_permission_args("claude"))
    args.extend(["--resume" if is_retry else "--session-id", session_id])
    return AgentCommand(args, None, f"Claude session {session_id}")


def _build_codex_command(
    agent: str,
    skill_name: str,
    developer_instructions: str,
    is_retry: bool,
    agent_model: str = DEFAULT_AGENT_MODEL,
    mcp_url: str | None = None,
    artifact_context: dict | None = None,
) -> AgentCommand:
    args = [agent, "--profile", "skill_runner", "-c", developer_instructions]
    args.extend(_agent_mcp_override_args("codex", mcp_url))
    args.extend(_agent_model_args("codex", agent_model))
    args.append("exec")
    if is_retry:
        args.extend(["resume", "--last"])
    args.append("-")
    prompt = _skill_prompt(skill_name, artifact_context)
    return AgentCommand(args, prompt, "the latest Codex session (--last)")


def _build_opencode_command(
    agent: str,
    skill_name: str,
    is_retry: bool,
    session_id: str | None,
    agent_model: str = DEFAULT_AGENT_MODEL,
    artifact_context: dict | None = None,
) -> AgentCommand:
    args = [agent, "run", "--format", "json"]
    args.extend(_agent_model_args("opencode", agent_model))
    args.extend(_agent_permission_args("opencode"))
    if is_retry and session_id:
        args.extend(["--session", session_id])
    elif is_retry:
        args.append("--continue")
    args.extend(["--agent", "sig-finder", _skill_prompt(skill_name, artifact_context)])
    retry_target = f"OpenCode session {session_id}" if session_id else "the latest OpenCode session (--continue)"
    return AgentCommand(args, None, retry_target)


def _build_agent_command(
    *,
    agent: str,
    agent_kind: str,
    skill_name: str,
    session_id: str,
    opencode_session_id: str | None,
    developer_instructions: str | None,
    is_retry: bool,
    agent_model: str = DEFAULT_AGENT_MODEL,
    mcp_url: str | None = None,
    artifact_context: dict | None = None,
) -> AgentCommand:
    if agent_kind == "claude":
        return _build_claude_command(agent, skill_name, session_id, is_retry, agent_model, mcp_url, artifact_context)
    if agent_kind == "opencode":
        return _build_opencode_command(agent, skill_name, is_retry, opencode_session_id, agent_model, artifact_context)
    if developer_instructions is None:
        raise ValueError("Codex developer instructions are required")
    return _build_codex_command(
        agent, skill_name, developer_instructions, is_retry, agent_model, mcp_url, artifact_context
    )


def build_agent_command(
    agent: str,
    skill_name: str,
    *,
    retry: bool = False,
    model: str = DEFAULT_AGENT_MODEL,
    session_id: str | None = None,
    opencode_session_id: str | None = None,
) -> list[str]:
    """Build one Agent CLI argv list for callers that need command inspection."""
    if not SAFE_SKILL_RE.fullmatch(skill_name):
        raise ValueError(f"Unsafe skill name: {skill_name!r}")
    agent_kind = detect_agent_kind(agent)
    if agent_kind is None:
        raise ValueError(f"Unsupported agent executable: {agent!r}")
    developer_instructions = _load_codex_developer_instructions() if agent_kind == "codex" else None
    command = _build_agent_command(
        agent=agent,
        agent_kind=agent_kind,
        skill_name=skill_name,
        session_id=session_id or str(uuid.uuid4()),
        opencode_session_id=opencode_session_id,
        developer_instructions=developer_instructions,
        is_retry=retry,
        agent_model=model,
    )
    return command.args


def _perform_mcp_preflight(
    agent: str, *, debug: bool, server_name: str, mcp_url: str | None = None
) -> McpPreflightResult:
    try:
        mcp_url = _normalize_mcp_url(mcp_url)
    except ValueError as error:
        return McpPreflightResult(False, "invalid_mcp_url", {"error": str(error)})
    cache_key = (agent, server_name, mcp_url)
    cached = _MCP_PREFLIGHT_CACHE.get(cache_key)
    if cached is not None:
        return cached
    agent_kind = detect_agent_kind(agent) or ""
    command = [agent, *_agent_mcp_override_args(agent_kind, mcp_url), "mcp", "list"]
    try:
        with _claude_mcp_preflight_workspace(mcp_url if agent_kind == "claude" else None) as preflight_cwd:
            completed = _run_process_with_stream_capture(
                command,
                debug=debug,
                timeout=MCP_LIST_TIMEOUT,
                env=_agent_process_env(agent_kind, mcp_url),
                cwd=preflight_cwd,
            )
    except subprocess.TimeoutExpired as error:
        result = McpPreflightResult(
            False,
            "mcp_preflight_timeout",
            {"timeout_seconds": MCP_LIST_TIMEOUT, **_diagnostic_payload(error.output, error.stderr)},
        )
    except FileNotFoundError:
        result = McpPreflightResult(False, "agent_not_found", {"agent": agent})
    except OSError as error:
        result = McpPreflightResult(False, "mcp_preflight_error", {"error": str(error)})
    except (TypeError, ValueError) as error:
        result = McpPreflightResult(False, "mcp_preflight_error", {"error": str(error)})
    else:
        output = "\n".join(text for text in (completed.stdout, completed.stderr) if text)
        if _mcp_list_contains_server(output, server_name):
            result = McpPreflightResult(True)
        else:
            result = McpPreflightResult(
                False,
                "mcp_unavailable",
                {
                    "server": server_name,
                    "returncode": completed.returncode,
                    **_diagnostic_payload(completed.stdout, completed.stderr),
                },
            )
    if result.ok:
        _MCP_PREFLIGHT_CACHE[cache_key] = result
    return result


def has_required_mcp_server(
    agent: str,
    server_name: str = "ida-pro-mcp",
    *,
    debug: bool = False,
    mcp_url: str | None = None,
) -> bool:
    return _perform_mcp_preflight(agent, debug=debug, server_name=server_name, mcp_url=mcp_url).ok


def _missing_expected_outputs(expected_yaml_paths) -> list[str]:
    return [str(path) for path in (expected_yaml_paths or ()) if not Path(path).is_file()]


def _result_failure(completed: subprocess.CompletedProcess[str], expected_yaml_paths) -> tuple[str, dict] | None:
    diagnostics = _diagnostic_payload(completed.stdout, completed.stderr)
    if completed.returncode != 0:
        return "returncode", {"returncode": completed.returncode, **diagnostics}
    cybersecurity_block = _extract_cybersecurity_block(completed.stdout, completed.stderr)
    if cybersecurity_block is not None:
        return "cybersecurity_block", {"error": cybersecurity_block, **diagnostics}
    skill_error = _extract_skill_error(completed.stdout, completed.stderr)
    if skill_error is not None:
        return "skill_error", {"error": skill_error, **diagnostics}
    missing_outputs = _missing_expected_outputs(expected_yaml_paths)
    if missing_outputs:
        return "missing_expected_output", {"missing_outputs": missing_outputs, **diagnostics}
    return None


def _report_attempt_failure(reason: str, payload: dict, debug: bool) -> None:
    if reason == "returncode":
        print(f"    Skill failed with return code: {payload['returncode']}")
        if not debug and payload.get("stderr"):
            print(f"    stderr: {payload['stderr']}")
    elif reason == "skill_error":
        print(f"    Error: Skill reported: {payload['error']}")
    elif reason == "cybersecurity_block":
        print(f"    Error: Skill blocked by cybersecurity filter: {payload['error']}")
    elif reason == "missing_expected_output":
        print(f"    Error: Expected YAML files not generated: {payload['missing_outputs']}")


def _run_skill_attempts(
    *,
    skill_name: str,
    agent: str,
    agent_kind: str,
    session_id: str,
    developer_instructions: str | None,
    expected_yaml_paths,
    max_retries: int,
    agent_model: str,
    timeout: int,
    debug: bool,
    progress_callback: Callable[..., None] | None,
    mcp_url: str | None = None,
    artifact_context: dict | None = None,
) -> bool:
    opencode_session_id = None
    process_env = _agent_process_env(agent_kind, mcp_url)
    last_failure: dict[str, object] | None = None
    for attempt_index in range(max_retries):
        attempt = attempt_index + 1
        _notify_progress(progress_callback, "attempt_started", attempt=attempt, max_attempts=max_retries)
        command = _build_agent_command(
            agent=agent,
            agent_kind=agent_kind,
            skill_name=skill_name,
            session_id=session_id,
            opencode_session_id=opencode_session_id,
            developer_instructions=developer_instructions,
            is_retry=attempt_index > 0,
            agent_model=agent_model,
            mcp_url=mcp_url,
            artifact_context=artifact_context,
        )
        try:
            completed = _run_process_with_stream_capture(
                command.args,
                agent_input=command.input_text,
                debug=debug,
                timeout=timeout,
                env=process_env,
            )
        except subprocess.TimeoutExpired as error:
            last_failure = {
                "reason": "timeout",
                "timeout_seconds": timeout,
                **_diagnostic_payload(error.output, error.stderr),
            }
        except FileNotFoundError:
            _notify_progress(
                progress_callback,
                "failed",
                attempt=attempt,
                max_attempts=max_retries,
                reason="agent_not_found",
                agent=agent,
            )
            return False
        except OSError as error:
            last_failure = {"reason": "execution_error", "error": str(error)}
        else:
            if agent_kind == "opencode" and opencode_session_id is None:
                opencode_session_id = _extract_opencode_session_id(completed.stdout)
            failure = _result_failure(completed, expected_yaml_paths)
            if failure is None:
                _notify_progress(progress_callback, "succeeded", attempt=attempt, max_attempts=max_retries)
                return True
            reason, payload = failure
            last_failure = {"reason": reason, **payload}
            _report_attempt_failure(reason, payload, debug)
            if reason == "cybersecurity_block":
                _notify_progress(
                    progress_callback,
                    "failed",
                    attempt=attempt,
                    max_attempts=max_retries,
                    **last_failure,
                )
                return False

        _notify_progress(
            progress_callback,
            "attempt_failed",
            attempt=attempt,
            max_attempts=max_retries,
            will_retry=attempt_index < max_retries - 1,
            **last_failure,
        )

    _notify_progress(
        progress_callback,
        "failed",
        attempt=max_retries,
        max_attempts=max_retries,
        reason="retries_exhausted",
        last_failure=last_failure,
    )
    return False


def run_skill(
    skill_name: str,
    *,
    agent: str = "codex",
    expected_yaml_paths=None,
    max_retries: int = 3,
    model: str = DEFAULT_AGENT_MODEL,
    timeout: int = SKILL_TIMEOUT,
    progress_callback: Callable[..., None] | None = None,
    mcp_preflight: bool = True,
    debug: bool = False,
    agent_model: str | None = None,
    mcp_url: str | None = None,
    artifact_context: dict | None = None,
) -> bool:
    """Execute a skill with bounded retries and structured progress events."""
    agent_kind = detect_agent_kind(agent)
    if agent_kind is None:
        _notify_progress(progress_callback, "failed", reason="unknown_agent", agent=agent)
        return False
    if not SAFE_SKILL_RE.fullmatch(skill_name):
        _notify_progress(progress_callback, "failed", reason="unsafe_skill_name", skill=skill_name)
        return False
    if not 1 <= max_retries <= 20:
        _notify_progress(progress_callback, "failed", reason="invalid_max_retries", max_retries=max_retries)
        return False
    if timeout <= 0:
        _notify_progress(progress_callback, "failed", reason="invalid_timeout", timeout_seconds=timeout)
        return False

    effective_model = model if agent_model is None else agent_model
    if agent_model is not None and str(model or "").strip() and str(model).strip() != str(agent_model).strip():
        _notify_progress(progress_callback, "failed", reason="invalid_agent_model", error="Conflicting model arguments")
        return False
    try:
        _agent_model_args(agent_kind, effective_model)
    except ValueError as error:
        _notify_progress(progress_callback, "failed", reason="invalid_agent_model", error=str(error))
        return False
    try:
        mcp_url = _normalize_mcp_url(mcp_url)
    except ValueError as error:
        _notify_progress(progress_callback, "failed", reason="invalid_mcp_url", error=str(error))
        return False
    if artifact_context is not None:
        try:
            if not isinstance(artifact_context, dict):
                raise TypeError("artifact context must be an object")
            _artifact_context_prompt(artifact_context)
        except (TypeError, ValueError) as error:
            _notify_progress(progress_callback, "failed", reason="invalid_artifact_context", error=str(error))
            return False

    skill_path = Path(".claude") / "skills" / skill_name / "SKILL.md"
    if not skill_path.is_file():
        _notify_progress(progress_callback, "failed", reason="skill_file_missing", path=str(skill_path))
        return False
    if mcp_preflight:
        preflight = _perform_mcp_preflight(agent, debug=debug, server_name="ida-pro-mcp", mcp_url=mcp_url)
        if not preflight.ok:
            _notify_progress(progress_callback, "failed", reason=preflight.reason, **preflight.detail)
            return False

    developer_instructions = _load_codex_developer_instructions() if agent_kind == "codex" else None
    if agent_kind == "codex" and developer_instructions is None:
        _notify_progress(progress_callback, "failed", reason="developer_instructions_unavailable")
        return False
    return _run_skill_attempts(
        skill_name=skill_name,
        agent=agent,
        agent_kind=agent_kind,
        session_id=str(uuid.uuid4()) if agent_kind == "claude" else "",
        developer_instructions=developer_instructions,
        expected_yaml_paths=expected_yaml_paths,
        max_retries=max_retries,
        agent_model=effective_model,
        timeout=timeout,
        debug=debug,
        progress_callback=progress_callback,
        mcp_url=mcp_url,
        artifact_context=artifact_context,
    )
