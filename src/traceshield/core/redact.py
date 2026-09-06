"""Text surgery: turning a decided action into replacement text.

Placeholders are designed so that sanitizing an already-sanitized value finds nothing new.
The engine discards any detection overlapping a placeholder, which is what makes
``sanitize(sanitize(x)) == sanitize(x)`` hold for every policy (docs/Architecture.md
invariant 4).
"""

from __future__ import annotations

import re
from collections.abc import Iterable, Sequence

from traceshield.core.model import Action, RuleId

PLACEHOLDER_PATTERN = re.compile(r"\[redacted:[a-z0-9_.]+(?::[0-9a-f]{8,32})?\]")
"""Matches any placeholder this module can emit."""


def placeholder(rule_id: RuleId, digest: str | None = None) -> str:
    """Render the replacement marker for a rule.

    The rule identifier is included deliberately: a redacted trace should say what was
    removed, so an engineer reading it knows whether the missing value explains the bug.
    """
    if digest is None:
        return f"[redacted:{rule_id}]"
    return f"[redacted:{rule_id}:{digest}]"


def replacement_for(
    matched: str,
    *,
    action: Action,
    rule_id: RuleId,
    digest: str,
    keep_prefix: int = 0,
) -> str:
    """Return the text that replaces ``matched`` under ``action``."""
    if action is Action.HASH:
        return placeholder(rule_id, digest)
    if action is Action.PARTIAL and keep_prefix > 0:
        return matched[:keep_prefix] + placeholder(rule_id)
    return placeholder(rule_id)


def placeholder_spans(text: str) -> tuple[tuple[int, int], ...]:
    """Locate existing placeholders so detections inside them can be discarded."""
    return tuple((match.start(), match.end()) for match in PLACEHOLDER_PATTERN.finditer(text))


def within_placeholder(start: int, end: int, spans: Iterable[tuple[int, int]]) -> bool:
    """True when ``[start, end)`` intersects an existing placeholder."""
    return any(start < span_end and span_start < end for span_start, span_end in spans)


def apply_replacements(text: str, replacements: Sequence[tuple[int, int, str]]) -> str:
    """Apply non-overlapping ``(start, end, replacement)`` edits.

    Applied right to left so earlier offsets stay valid.
    """
    if not replacements:
        return text
    ordered = sorted(replacements, key=lambda item: item[0], reverse=True)
    result = text
    for start, end, replacement in ordered:
        result = result[:start] + replacement + result[end:]
    return result
