"""Construct process reporter backends from CLI and environment settings."""

from __future__ import annotations

import os

from process_reporter import (
    ConsoleProcessReporter,
    NullProcessReporter,
    ProcessReporter,
    ProcessReporterConfigurationError,
)

DEFAULT_REDIS_URL = "redis://127.0.0.1:6379/0"
DEFAULT_REDIS_PREFIX = "gsvibe:analysis:v1"


def _configured_value(args, attribute: str, environment_name: str, default=None):
    value = getattr(args, attribute, None)
    if value is not None:
        return value
    return os.environ.get(environment_name, default)


def create_process_reporter(args) -> ProcessReporter:
    """Create the selected backend without importing Redis unless requested."""
    backend = str(_configured_value(args, "process_reporter", "GSVIBE_PROCESS_REPORTER", "none")).strip().lower()
    if backend == "none":
        return NullProcessReporter()
    if backend == "console":
        return ConsoleProcessReporter()
    if backend != "redis":
        raise ProcessReporterConfigurationError(f"Unsupported process reporter backend: {backend}")

    try:
        from process_reporter_redis import RedisProcessReporter
    except ImportError as exc:
        raise ProcessReporterConfigurationError(
            "Redis process reporter is not available; install the project Redis dependencies"
        ) from exc

    return RedisProcessReporter(
        redis_url=_configured_value(args, "redis_url", "GSVIBE_REDIS_URL", DEFAULT_REDIS_URL),
        prefix=_configured_value(args, "redis_prefix", "GSVIBE_REDIS_PREFIX", DEFAULT_REDIS_PREFIX),
        run_metadata={
            "gamever": getattr(args, "gamever", None),
            "agent": getattr(args, "agent", None),
            "config_path": getattr(args, "configyaml", None),
        },
    )
