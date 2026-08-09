"""Run a configured analysis skill with bounded retries and output validation."""

from __future__ import annotations

import re
import subprocess
from collections.abc import Callable
from pathlib import Path

SKILL_TIMEOUT = 1200
SAFE_SKILL_RE = re.compile(r"^[A-Za-z0-9_.-]+$", re.ASCII)


def detect_agent_kind(agent: str) -> str | None:
    lowered = str(agent).lower()
    return next((kind for kind in ("claude", "codex", "opencode") if kind in lowered), None)


def build_agent_command(agent: str, skill_name: str, *, retry: bool = False, model: str = "") -> list[str]:
    if not SAFE_SKILL_RE.fullmatch(skill_name):
        raise ValueError(f"Unsafe skill name: {skill_name!r}")
    kind = detect_agent_kind(agent)
    if kind is None:
        raise ValueError(f"Unsupported agent executable: {agent!r}")
    if kind == "codex":
        command = [agent]
        if model:
            command.extend(["-m", model])
        command.extend(["exec"])
        if retry:
            command.extend(["resume", "--last"])
        command.append(f"Run SKILL: .claude/skills/{skill_name}/SKILL.md")
        return command
    if kind == "opencode":
        command = [agent, "run", "--format", "json", "--agent", "sig-finder"]
        if retry:
            command.append("--continue")
        if model:
            command.extend(["-m", model])
        command.append(f"Run SKILL: .claude/skills/{skill_name}/SKILL.md")
        return command
    command = [agent, "-p", f"/{skill_name}", "--agent", "sig-finder"]
    if model:
        command.extend(["--model", model])
    if retry:
        command.append("--continue")
    return command


def has_required_mcp_server(agent: str, server_name: str = "ida-pro-mcp") -> bool:
    try:
        result = subprocess.run(
            [agent, "mcp", "list"],
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return False
    output = f"{result.stdout}\n{result.stderr}"
    return result.returncode == 0 and any(
        line.strip().lstrip("-*|✓✗ ").startswith(server_name) for line in output.splitlines()
    )


def run_skill(
    skill_name: str,
    *,
    agent: str = "codex",
    expected_yaml_paths=None,
    max_retries: int = 3,
    model: str = "",
    timeout: int = SKILL_TIMEOUT,
    progress_callback: Callable[..., None] | None = None,
    mcp_preflight: bool = True,
) -> bool:
    skill_path = Path(".claude") / "skills" / skill_name / "SKILL.md"
    if not skill_path.is_file() or not 1 <= max_retries <= 20:
        return False
    if mcp_preflight and not has_required_mcp_server(agent):
        if progress_callback:
            progress_callback(event="failed", reason="mcp_unavailable")
        return False
    expected = [Path(path) for path in (expected_yaml_paths or ())]
    for attempt in range(max_retries):
        if progress_callback:
            progress_callback(event="attempt_started", attempt=attempt + 1, max_attempts=max_retries)
        command = build_agent_command(agent, skill_name, retry=attempt > 0, model=model)
        try:
            result = subprocess.run(command, capture_output=True, text=True, timeout=timeout, check=False)
        except (OSError, subprocess.TimeoutExpired):
            continue
        if result.returncode == 0 and all(path.is_file() for path in expected):
            if progress_callback:
                progress_callback(event="succeeded", attempt=attempt + 1, max_attempts=max_retries)
            return True
    if progress_callback:
        progress_callback(event="failed", attempt=max_retries, max_attempts=max_retries)
    return False
