from __future__ import annotations

import pytest

from traceshield import Action, Category, Confidence, DetectionSpan, Finding, Severity
from traceshield.core.model import RuleId, SanitizedAttributes, SanitizedValue, ValueHash


class TestConfidence:
    @pytest.mark.parametrize("value", [0.0, 0.5, 1.0])
    def test_accepts_bounded_values(self, value: float) -> None:
        assert float(Confidence(value)) == value

    @pytest.mark.parametrize("value", [-0.01, 1.01, 2.0, -1.0])
    def test_rejects_out_of_range(self, value: float) -> None:
        with pytest.raises(ValueError, match="within"):
            Confidence(value)

    def test_repr_is_readable(self) -> None:
        assert repr(Confidence(0.5)) == "Confidence(0.50)"


def _span(start: int, end: int) -> DetectionSpan:
    return DetectionSpan(
        start=start,
        end=end,
        rule_id=RuleId("secret.test"),
        category=Category.SECRET,
        severity=Severity.HIGH,
        confidence=Confidence(0.9),
        detector="test",
    )


class TestDetectionSpan:
    def test_rejects_negative_start(self) -> None:
        with pytest.raises(ValueError, match="non-negative"):
            _span(-1, 4)

    @pytest.mark.parametrize(("start", "end"), [(4, 4), (5, 3)])
    def test_rejects_empty_or_inverted(self, start: int, end: int) -> None:
        with pytest.raises(ValueError, match="exceed start"):
            _span(start, end)

    def test_length(self) -> None:
        assert _span(2, 9).length == 7

    @pytest.mark.parametrize(
        ("other", "expected"),
        [((5, 8), True), ((3, 5), True), ((7, 20), True), ((0, 3), False), ((8, 12), False)],
    )
    def test_overlaps(self, other: tuple[int, int], expected: bool) -> None:
        assert _span(3, 8).overlaps(_span(*other)) is expected


class TestFinding:
    def _finding(self) -> Finding:
        return Finding(
            rule_id=RuleId("secret.aws.access_key_id"),
            category=Category.SECRET,
            severity=Severity.CRITICAL,
            confidence=Confidence(0.98),
            action=Action.MASK,
            attribute_key="gen_ai.tool.call.arguments",
            path="/credentials/key",
            detector="pattern",
            value_hash=ValueHash("0123456789abcdef"),
            policy_version="test/1",
        )

    def test_to_dict_is_json_safe(self) -> None:
        payload = self._finding().to_dict()
        assert payload["rule_id"] == "secret.aws.access_key_id"
        assert payload["category"] == "secret"
        assert payload["action"] == "mask"
        assert payload["confidence"] == 0.98
        assert set(payload) == {
            "rule_id",
            "category",
            "severity",
            "confidence",
            "action",
            "attribute_key",
            "path",
            "detector",
            "value_hash",
            "policy_version",
        }

    def test_has_no_field_that_could_hold_a_value(self) -> None:
        # Invariant 3 in docs/Architecture.md, enforced structurally rather than by review.
        assert "value" not in Finding.__slots__


class TestSanitizedResults:
    def test_value_unchanged_without_findings(self) -> None:
        assert SanitizedValue("x", ()).changed is False

    def test_attributes_changed_when_only_dropped(self) -> None:
        result = SanitizedAttributes(attributes={}, dropped_keys=("k",), findings=())
        assert result.changed is True
