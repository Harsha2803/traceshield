"""Key-name heuristics for structured payloads.

This is the signal that makes tool call arguments tractable. A value such as
``"c5f2a1b8e4"`` matches no pattern and carries little entropy, but under the key
``api_key`` its intent is unambiguous. Without this detector the most dangerous field in
agent telemetry is also the least detectable.
"""

from __future__ import annotations

import re
from collections.abc import Iterable
from dataclasses import dataclass

from traceshield.core.detectors.base import DetectionContext
from traceshield.core.model import Category, Confidence, DetectionSpan, RuleId, Severity

SENSITIVE_KEY_RULE_ID = RuleId("secret.generic.sensitive_key")

_SENSITIVE_KEY_RE = re.compile(
    r"(?:^|[_\-.])(?:api[_\-]?key|secret|passwd|password|token|credential|credentials"
    r"|authorization|auth|private[_\-]?key|access[_\-]?key|secret[_\-]?key|session[_\-]?id"
    r"|cookie|bearer|signature|salt|pin|otp)(?:$|[_\-.])",
    re.IGNORECASE,
)

# Keys whose names contain a sensitive word but whose values are metadata about a secret
# rather than the secret. Redacting these removes debuggability for no security gain.
_BENIGN_KEY_RE = re.compile(
    r"(?:count|length|size|type|kind|name|scheme|enabled|required|expires?[_\-]?(?:in|at)"
    r"|created[_\-]?at|updated[_\-]?at|version|format|algorithm|alg|prefix|masked|redacted)$",
    re.IGNORECASE,
)


@dataclass(frozen=True, slots=True)
class KeyNameSettings:
    """Tunables for key-name escalation."""

    min_value_length: int = 8
    confidence: float = 0.9

    def __post_init__(self) -> None:
        if self.min_value_length < 1:
            raise ValueError("key-name min_value_length must be positive")


class KeyNameDetector:
    """Treats a whole value as sensitive when its enclosing key says it is.

    Emits a span covering the entire string rather than a region of it, because when the key
    is ``password`` the value is the secret, not a substring of it.
    """

    __slots__ = ("_settings",)

    def __init__(self, settings: KeyNameSettings | None = None) -> None:
        self._settings = settings or KeyNameSettings()

    @property
    def name(self) -> str:
        return "keyname"

    def detect(self, text: str, context: DetectionContext) -> Iterable[DetectionSpan]:
        key = context.key_name
        if not key or len(text) < self._settings.min_value_length:
            return ()
        if _BENIGN_KEY_RE.search(key):
            return ()
        if not _SENSITIVE_KEY_RE.search(key):
            return ()
        return (
            DetectionSpan(
                start=0,
                end=len(text),
                rule_id=SENSITIVE_KEY_RULE_ID,
                category=Category.SECRET,
                severity=Severity.HIGH,
                confidence=Confidence(self._settings.confidence),
                detector=self.name,
            ),
        )
