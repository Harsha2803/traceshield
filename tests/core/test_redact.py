from __future__ import annotations

import pytest

from traceshield.core.model import Action, RuleId
from traceshield.core.redact import (
    PLACEHOLDER_PATTERN,
    apply_replacements,
    placeholder,
    placeholder_spans,
    replacement_for,
    within_placeholder,
)

RULE = RuleId("secret.aws.access_key_id")


class TestPlaceholder:
    def test_names_the_rule_that_fired(self) -> None:
        assert placeholder(RULE) == "[redacted:secret.aws.access_key_id]"

    def test_carries_a_digest_when_hashing(self) -> None:
        assert placeholder(RULE, "0123456789abcdef").endswith(":0123456789abcdef]")

    @pytest.mark.parametrize("digest", [None, "0123456789abcdef"])
    def test_every_placeholder_is_recognisable(self, digest: str | None) -> None:
        # Idempotence depends on this: a placeholder must be findable on a second pass.
        assert PLACEHOLDER_PATTERN.fullmatch(placeholder(RULE, digest))


class TestReplacement:
    def test_mask_replaces_everything(self) -> None:
        assert replacement_for(
            "secret", action=Action.MASK, rule_id=RULE, digest="d"
        ) == placeholder(RULE)

    def test_hash_includes_the_digest(self) -> None:
        result = replacement_for("secret", action=Action.HASH, rule_id=RULE, digest="abc12345")
        assert result == placeholder(RULE, "abc12345")

    def test_partial_keeps_a_bounded_prefix(self) -> None:
        result = replacement_for(
            "4111111111111111", action=Action.PARTIAL, rule_id=RULE, digest="d", keep_prefix=4
        )
        assert result == "4111" + placeholder(RULE)

    def test_partial_without_keep_prefix_behaves_like_mask(self) -> None:
        result = replacement_for("x", action=Action.PARTIAL, rule_id=RULE, digest="d")
        assert result == placeholder(RULE)


class TestPlaceholderSpans:
    def test_finds_existing_placeholders(self) -> None:
        text = f"before {placeholder(RULE)} after"
        assert placeholder_spans(text) == ((7, 7 + len(placeholder(RULE))),)

    @pytest.mark.parametrize(
        ("start", "end", "expected"),
        [(8, 12, True), (0, 8, True), (0, 5, False), (0, 7, False), (20, 25, False)],
    )
    def test_overlap_check(self, start: int, end: int, expected: bool) -> None:
        assert within_placeholder(start, end, ((7, 20),)) is expected


class TestApplyReplacements:
    def test_no_replacements_returns_the_original(self) -> None:
        assert apply_replacements("unchanged", []) == "unchanged"

    def test_applies_multiple_edits_without_shifting_offsets(self) -> None:
        text = "aaa bbb ccc"
        assert apply_replacements(text, [(0, 3, "X"), (8, 11, "Y")]) == "X bbb Y"

    def test_replacement_length_does_not_corrupt_later_edits(self) -> None:
        text = "aa bb"
        assert apply_replacements(text, [(0, 2, "LONGER"), (3, 5, "Z")]) == "LONGER Z"
