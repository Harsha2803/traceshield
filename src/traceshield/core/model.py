"""Immutable domain types.

The central rule of this module: nothing here may carry a detected value. A Finding is
evidence that a redaction happened, and evidence that leaks the thing it redacted is worse
than no evidence at all. See docs/Architecture.md invariant 3.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import NewType

RuleId = NewType("RuleId", str)
"""Dotted identifier of a detection rule, for example ``secret.aws.access_key_id``."""

ValueHash = NewType("ValueHash", str)
"""Salted digest of a removed value, used to correlate without retaining."""


class Confidence(float):
    """A detection confidence bounded to [0.0, 1.0].

    A bounded type rather than a bare float because the bound is a domain invariant that
    would otherwise be re-checked, or forgotten, at every call site.
    """

    __slots__ = ()

    def __new__(cls, value: float) -> Confidence:
        if not 0.0 <= value <= 1.0:
            raise ValueError(f"confidence must be within [0.0, 1.0], got {value!r}")
        return super().__new__(cls, value)

    def __repr__(self) -> str:
        return f"Confidence({float(self):.2f})"


class Category(str, Enum):
    """What kind of sensitive thing a rule finds."""

    # Both linters flag the member name, not the value: this is a category label, not a
    # credential. Suppressed on this line rather than disabled repository-wide, so the
    # check keeps working everywhere it matters.
    SECRET = "secret"  # noqa: S105  # nosec B105
    CREDENTIAL = "credential"
    PII = "pii"
    IDENTIFIER = "identifier"
    POLICY = "policy"
    ENGINE = "engine"


class Severity(str, Enum):
    """How bad it is for this value to reach an observability platform."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class Action(str, Enum):
    """What the policy decided to do about a detection."""

    KEEP = "keep"
    """Recognised, deliberately left in place. Emits no finding."""

    MASK = "mask"
    """Replace the detected span with a placeholder naming the rule."""

    PARTIAL = "partial"
    """Keep a bounded prefix, replace the rest."""

    HASH = "hash"
    """Replace with a placeholder carrying a salted digest, so occurrences correlate."""

    DROP = "drop"
    """Replace the whole value, not just the detected span."""


class Handling(str, Enum):
    """What the policy does with a whole attribute before any detection runs."""

    KEEP = "keep"
    SCAN = "scan"
    DROP = "drop"


@dataclass(frozen=True, slots=True)
class DetectionSpan:
    """A half-open ``[start, end)`` region of a string that a detector claims is sensitive."""

    start: int
    end: int
    rule_id: RuleId
    category: Category
    severity: Severity
    confidence: Confidence
    detector: str

    def __post_init__(self) -> None:
        if self.start < 0:
            raise ValueError(f"detection span start must be non-negative, got {self.start}")
        if self.end <= self.start:
            raise ValueError(
                f"detection span end must exceed start, got start={self.start} end={self.end}"
            )

    @property
    def length(self) -> int:
        return self.end - self.start

    def overlaps(self, other: DetectionSpan) -> bool:
        return self.start < other.end and other.start < self.end


@dataclass(frozen=True, slots=True)
class Finding:
    """The auditable record of one redaction.

    Deliberately has no field that could hold the original value. ``value_hash`` is a salted
    digest, which supports correlating the same secret across traces without storing it.
    """

    rule_id: RuleId
    category: Category
    severity: Severity
    confidence: Confidence
    action: Action
    attribute_key: str
    path: str
    detector: str
    value_hash: ValueHash
    policy_version: str

    def to_dict(self) -> dict[str, str | float]:
        """Serialise for an audit sink. Every field is safe to persist and to log."""
        return {
            "rule_id": str(self.rule_id),
            "category": self.category.value,
            "severity": self.severity.value,
            "confidence": round(float(self.confidence), 4),
            "action": self.action.value,
            "attribute_key": self.attribute_key,
            "path": self.path,
            "detector": self.detector,
            "value_hash": str(self.value_hash),
            "policy_version": self.policy_version,
        }


@dataclass(frozen=True, slots=True)
class SanitizedValue:
    """The result of sanitizing one attribute value."""

    value: object
    findings: tuple[Finding, ...]

    @property
    def changed(self) -> bool:
        return bool(self.findings)


@dataclass(frozen=True, slots=True)
class SanitizedAttributes:
    """The result of sanitizing a whole attribute mapping.

    ``dropped_keys`` records attributes the policy removed outright, which callers need in
    order to actually delete them rather than write back a placeholder.
    """

    attributes: dict[str, object]
    dropped_keys: tuple[str, ...]
    findings: tuple[Finding, ...]

    @property
    def changed(self) -> bool:
        return bool(self.findings) or bool(self.dropped_keys)
