"""The detector seam.

Everything that can find something sensitive implements this protocol, which is what lets
ADR 0004's deferred ML detectors arrive later without touching the engine.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from typing import Protocol, runtime_checkable

from traceshield.core.model import DetectionSpan


@dataclass(frozen=True, slots=True)
class DetectionContext:
    """What a detector knows about where a string came from.

    ``key_name`` is the nearest enclosing object key, which is the signal that makes tool
    call arguments tractable: the value may be opaque, but the key often states its intent.
    """

    attribute_key: str
    path: str
    key_name: str


@runtime_checkable
class Detector(Protocol):
    """Finds sensitive regions in a string.

    Implementations must be pure, deterministic and free of I/O. They run on the
    OpenTelemetry batch export worker thread.
    """

    @property
    def name(self) -> str:
        """Stable identifier recorded on every finding this detector produces."""
        ...

    def detect(self, text: str, context: DetectionContext) -> Iterable[DetectionSpan]:
        """Return spans of ``text`` believed to be sensitive. May be empty."""
        ...
