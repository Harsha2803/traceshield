from __future__ import annotations

import pytest

from traceshield.core.errors import BudgetExceededError
from traceshield.core.walk import (
    WalkBudget,
    looks_like_json,
    parse_json_document,
    serialize_json_document,
    transform,
)


def budget(max_depth: int = 12, max_nodes: int = 5000) -> WalkBudget:
    return WalkBudget(max_depth=max_depth, max_nodes=max_nodes)


def upper(text: str, path: str, key_name: str) -> str:
    del path, key_name
    return text.upper()


class TestJsonDetection:
    @pytest.mark.parametrize("text", ['{"a":1}', "[1,2]", '  {"a": 1}  '])
    def test_recognises_documents(self, text: str) -> None:
        assert looks_like_json(text) is True

    @pytest.mark.parametrize("text", ["", "{", "hello", '"a string"', "{unbalanced", "[1,2"])
    def test_rejects_non_documents(self, text: str) -> None:
        assert looks_like_json(text) is False

    def test_parses_objects_and_arrays(self) -> None:
        assert parse_json_document('{"a":1}') == {"a": 1}
        assert parse_json_document("[1,2]") == [1, 2]

    @pytest.mark.parametrize("text", ["not json", '{"broken": ', '"scalar"', "42", "null"])
    def test_returns_none_for_anything_else(self, text: str) -> None:
        assert parse_json_document(text) is None

    def test_a_nesting_bomb_is_rejected_rather_than_crashing(self) -> None:
        # docs/ThreatModel.md T4: the parser itself is an attack surface. Below the
        # interpreter's recursion limit the document parses and the depth budget catches it
        # instead; above it, the parser raises and this guard turns that into a refusal.
        assert parse_json_document("[" * 50_000 + "]" * 50_000) is None

    def test_round_trip_preserves_structure_not_whitespace(self) -> None:
        document = parse_json_document('{"a": [1, {"b": "c"}]}')
        assert serialize_json_document(document) == '{"a":[1,{"b":"c"}]}'

    def test_serialisation_keeps_non_ascii_readable(self) -> None:
        assert serialize_json_document({"city": "München"}) == '{"city":"München"}'


class TestTransform:
    def test_applies_to_string_leaves_only(self) -> None:
        value = {"text": "abc", "count": 3, "flag": True, "missing": None}
        assert transform(value, upper, budget=budget()) == {
            "text": "ABC",
            "count": 3,
            "flag": True,
            "missing": None,
        }

    def test_preserves_nested_shape(self) -> None:
        value = {"parts": [{"type": "text", "content": "hi"}, {"type": "blob"}]}
        result = transform(value, upper, budget=budget())
        assert result == {"parts": [{"type": "TEXT", "content": "HI"}, {"type": "BLOB"}]}

    def test_passes_the_enclosing_key_to_the_leaf(self) -> None:
        seen: list[tuple[str, str]] = []

        def record(text: str, path: str, key_name: str) -> str:
            seen.append((path, key_name))
            return text

        transform({"outer": {"api_key": "v"}}, record, budget=budget())
        assert seen == [("/outer/api_key", "api_key")]

    def test_array_elements_inherit_the_array_key(self) -> None:
        seen: list[str] = []

        def record(text: str, path: str, key_name: str) -> str:
            del path
            seen.append(key_name)
            return text

        transform({"api_keys": ["a", "b"]}, record, budget=budget())
        assert seen == ["api_keys", "api_keys"]

    def test_non_string_keys_are_stringified(self) -> None:
        assert transform({1: "a"}, upper, budget=budget()) == {"1": "A"}

    def test_depth_budget_is_enforced(self) -> None:
        deep: object = "leaf"
        for _ in range(6):
            deep = {"nested": deep}
        with pytest.raises(BudgetExceededError, match="max_depth"):
            transform(deep, upper, budget=budget(max_depth=3))

    def test_node_budget_is_enforced(self) -> None:
        with pytest.raises(BudgetExceededError, match="max_nodes"):
            transform(["a"] * 50, upper, budget=budget(max_nodes=10))

    def test_budget_error_carries_no_value(self) -> None:
        with pytest.raises(BudgetExceededError) as caught:
            transform({"secret": "s"}, upper, budget=budget(max_depth=0))
        assert "secret" not in str(caught.value)
