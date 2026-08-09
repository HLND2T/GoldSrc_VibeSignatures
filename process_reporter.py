"""In-memory and console-only analysis progress reporting."""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any, Protocol


@dataclass(frozen=True)
class ProgressEvent:
    event: str
    timestamp: str
    tag: str | None = None
    module: str | None = None
    platform: str | None = None
    skill: str | None = None
    detail: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def create(cls, event: str, **payload):
        fields = {key: payload.pop(key, None) for key in ("tag", "module", "platform", "skill")}
        return cls(event, datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"), **fields, detail=payload)


class ProcessReporter(Protocol):
    def emit(self, event: ProgressEvent) -> None: ...


class InMemoryReporter:
    def __init__(self) -> None:
        self.events: list[ProgressEvent] = []

    def emit(self, event: ProgressEvent) -> None:
        self.events.append(event)


class ConsoleReporter:
    def emit(self, event: ProgressEvent) -> None:
        print(json.dumps(asdict(event), ensure_ascii=False, sort_keys=True))


class NullReporter:
    def emit(self, event: ProgressEvent) -> None:
        del event
