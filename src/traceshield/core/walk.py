"""Bounded, structure-preserving traversal.

Sensitive content in GenAI telemetry sits at the leaves of a nested document that was
serialized into a span attribute (docs/Research.md section 1). Rebuilding that document with
its shape intact, rather than treating the attribute as opaque text, is what keeps a
sanitized trace debuggable.

Every limit here exists because the input is hostile by assumption: model output, tool
results and retrieved documents are all attacker-influenceable (docs/ThreatModel.md T4).
"""

from __future__ import annotations

import json
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass

from traceshield.core.errors import BudgetExceededError

LeafTransform = Callable[[str, str, str], str]
"""``(text, path, key_name) -> replacement text``."""

_JSON_OPENERS = ("{", "[")


@dataclass(slots=True)
class WalkBudget:
    """Mutable traversal accounting. One instance per attribute value."""

    max_depth: int
    max_nodes: int
    nodes_visited: int = 0

    def enter(self, depth: int) -> None:
        if depth > self.max_depth:
            raise BudgetExceededError("max_depth", self.max_depth)
        self.nodes_visited += 1
        if self.nodes_visited > self.max_nodes:
            raise BudgetExceededError("max_nodes", self.max_nodes)


def looks_like_json(text: str) -> bool:
    """Cheap pre-check so the parser is only attempted on plausible input."""
    stripped = text.strip()
    if len(stripped) < 2 or stripped[0] not in _JSON_OPENERS:
        return False
    return (stripped[0] == "{" and stripped[-1] == "}") or (
        stripped[0] == "[" and stripped[-1] == "]"
    )


def parse_json_document(text: str) -> object | None:
    """Parse ``text`` if it is a JSON object or array, otherwise return ``None``.

    Scalars are rejected: a bare JSON string is just text, and round-tripping it through the
    parser would only add quoting noise. Callers screen with :func:`looks_like_json` first so
    the parser is never run on ordinary prose.
    """
    try:
        parsed = json.loads(text)
    except (ValueError, RecursionError):
        return None
    if isinstance(parsed, (dict, list)):
        return parsed
    return None


def serialize_json_document(document: object) -> str:
    """Serialize a transformed document.

    Whitespace from the original is not preserved; structure is. That trade-off is
    deliberate and documented, because reproducing arbitrary formatting would mean writing a
    JSON parser that retains trivia for no observable benefit.
    """
    return json.dumps(document, ensure_ascii=False, separators=(",", ":"))


def transform(
    value: object,
    leaf: LeafTransform,
    *,
    budget: WalkBudget,
    path: str = "",
    key_name: str = "",
    depth: int = 0,
) -> object:
    """Rebuild ``value`` with ``leaf`` applied to every string leaf.

    Object keys, array lengths and node types are preserved exactly. Non-string scalars are
    returned untouched: replacing a number with a placeholder would change the node's type,
    which breaks consumers that validate the payload against its schema. That limitation is
    recorded in the README.
    """
    budget.enter(depth)
    if isinstance(value, str):
        return leaf(value, path, key_name)
    if isinstance(value, Mapping):
        return {
            str(child_key): transform(
                child_value,
                leaf,
                budget=budget,
                path=f"{path}/{child_key}",
                key_name=str(child_key),
                depth=depth + 1,
            )
            for child_key, child_value in value.items()
        }
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        return [
            transform(
                item,
                leaf,
                budget=budget,
                path=f"{path}/{index}",
                # An array element inherits the key that named the array, so a list under
                # "api_keys" is still recognised as sensitive.
                key_name=key_name,
                depth=depth + 1,
            )
            for index, item in enumerate(value)
        ]
    return value
