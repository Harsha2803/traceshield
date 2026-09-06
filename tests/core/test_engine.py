"""Engine behaviour, including the acceptance criteria in docs/ProductBrief.md section 7."""

from __future__ import annotations

import json
from collections.abc import Iterable

import pytest

from tests import fixtures
from traceshield import (
    Action,
    ActionRule,
    AttributeRule,
    Budgets,
    Confidence,
    DetectionContext,
    DetectionSpan,
    Handling,
    Policy,
    Sanitizer,
    ValueHasher,
)
from traceshield.core.model import Category, RuleId, Severity

CHAT_MESSAGES = [
    {
        "role": "user",
        "parts": [{"type": "text", "content": "rotate the key"}],
    },
    {
        "role": "assistant",
        "parts": [
            {"type": "text", "content": f"using {fixtures.AWS_ACCESS_KEY_ID} now"},
            {
                "type": "tool_call",
                "id": "call_1",
                "name": "rotate",
                "arguments": {"api_key": "opaque-value-abcdef", "region": "eu-west-1"},
            },
        ],
    },
]


def shape(value: object) -> object:
    """Structural skeleton: types, keys and lengths, with leaf content discarded."""
    if isinstance(value, dict):
        return {key: shape(item) for key, item in value.items()}
    if isinstance(value, list):
        return [shape(item) for item in value]
    return type(value).__name__


class TestStructuredRedaction:
    """Acceptance criterion 1 and 3."""

    def test_preserves_message_structure_while_removing_the_secret(
        self, sanitizer: Sanitizer
    ) -> None:
        payload = json.dumps(CHAT_MESSAGES)
        result = sanitizer.sanitize_attribute("gen_ai.input.messages", payload)

        assert isinstance(result.value, str)
        parsed = json.loads(result.value)
        assert shape(parsed) == shape(CHAT_MESSAGES)
        assert [message["role"] for message in parsed] == ["user", "assistant"]
        assert [part["type"] for part in parsed[1]["parts"]] == ["text", "tool_call"]
        assert parsed[1]["parts"][1]["name"] == "rotate"
        assert parsed[1]["parts"][1]["arguments"]["region"] == "eu-west-1"

    def test_the_secret_is_gone_and_the_rule_is_named(self, sanitizer: Sanitizer) -> None:
        result = sanitizer.sanitize_attribute("gen_ai.input.messages", json.dumps(CHAT_MESSAGES))
        assert isinstance(result.value, str)
        assert fixtures.AWS_ACCESS_KEY_ID not in result.value
        assert "[redacted:secret.aws.access_key_id]" in result.value

    def test_the_finding_points_at_the_offending_leaf(self, sanitizer: Sanitizer) -> None:
        result = sanitizer.sanitize_attribute("gen_ai.input.messages", json.dumps(CHAT_MESSAGES))
        finding = next(
            item for item in result.findings if str(item.rule_id) == "secret.aws.access_key_id"
        )
        assert finding.path == "/1/parts/0/content"
        assert finding.attribute_key == "gen_ai.input.messages"
        assert finding.action is Action.MASK

    def test_opaque_tool_argument_is_caught_by_its_key(self, sanitizer: Sanitizer) -> None:
        # The value matches no pattern and carries little entropy. Only the key gives it away.
        result = sanitizer.sanitize_attribute("gen_ai.input.messages", json.dumps(CHAT_MESSAGES))
        assert isinstance(result.value, str)
        assert "opaque-value-abcdef" not in result.value
        assert any(str(f.rule_id) == "secret.generic.sensitive_key" for f in result.findings)

    def test_unparseable_payload_falls_back_to_text_scanning(self, sanitizer: Sanitizer) -> None:
        result = sanitizer.sanitize_attribute(
            "gen_ai.input.messages", f"{{not valid json {fixtures.AWS_ACCESS_KEY_ID}"
        )
        assert isinstance(result.value, str)
        assert fixtures.AWS_ACCESS_KEY_ID not in result.value


class TestAttributeHandling:
    def test_kept_attributes_are_untouched(self, sanitizer: Sanitizer) -> None:
        result = sanitizer.sanitize_attribute("gen_ai.request.model", "claude-opus-5")
        assert result.value == "claude-opus-5"
        assert result.findings == ()

    def test_non_string_scalars_pass_through(self, sanitizer: Sanitizer) -> None:
        for value in (42, 3.5, True, None):
            assert sanitizer.sanitize_attribute("gen_ai.tool.call.result", value).value == value

    def test_sequences_are_scanned_elementwise(self, sanitizer: Sanitizer) -> None:
        result = sanitizer.sanitize_attribute(
            "gen_ai.response.other", ["clean", fixtures.AWS_ACCESS_KEY_ID]
        )
        assert isinstance(result.value, list)
        assert result.value[0] == "clean"
        assert fixtures.AWS_ACCESS_KEY_ID not in str(result.value)

    def test_attribute_key_supplies_the_key_name_signal(self, sanitizer: Sanitizer) -> None:
        result = sanitizer.sanitize_attribute(
            "http.request.header.authorization", "opaque-header-value"
        )
        assert result.value == "[redacted:secret.generic.sensitive_key]"

    def test_dropped_attributes_are_reported_for_deletion(self, hasher: ValueHasher) -> None:
        policy = Policy.build(
            version="test/1",
            attributes=(AttributeRule("gen_ai.input.messages", Handling.DROP),),
            actions=(ActionRule("policy.", Action.DROP, Confidence(0.0)),),
        )
        result = Sanitizer(policy=policy, hasher=hasher).sanitize_attributes(
            {"gen_ai.input.messages": "anything", "gen_ai.request.model": "m"}
        )
        assert result.dropped_keys == ("gen_ai.input.messages",)
        assert "gen_ai.input.messages" not in result.attributes
        assert result.attributes["gen_ai.request.model"] == "m"
        assert result.findings[0].action is Action.DROP


class TestFailClosed:
    """Acceptance criterion 4: the export path survives anything the engine does."""

    class _BrokenDetector:
        @property
        def name(self) -> str:
            return "broken"

        def detect(self, text: str, context: DetectionContext) -> Iterable[DetectionSpan]:
            del text, context
            raise RuntimeError("detector failure with a secret in the message")

    class _LyingDetector:
        @property
        def name(self) -> str:
            return "lying"

        def detect(self, text: str, context: DetectionContext) -> Iterable[DetectionSpan]:
            del context
            return (
                DetectionSpan(
                    start=0,
                    end=len(text) + 100,
                    rule_id=RuleId("secret.test"),
                    category=Category.SECRET,
                    severity=Severity.HIGH,
                    confidence=Confidence(0.9),
                    detector="lying",
                ),
            )

    def test_a_failing_detector_drops_the_value_without_raising(
        self, policy: Policy, hasher: ValueHasher
    ) -> None:
        sanitizer = Sanitizer(policy=policy, hasher=hasher, detectors=[self._BrokenDetector()])
        result = sanitizer.sanitize_attribute("gen_ai.input.messages", "sensitive text")
        assert result.value == "[redacted:engine.detector_error]"
        assert result.findings[0].detector == "broken"
        assert result.findings[0].action is Action.DROP

    def test_a_detector_reporting_an_impossible_span_fails_closed(
        self, policy: Policy, hasher: ValueHasher
    ) -> None:
        sanitizer = Sanitizer(policy=policy, hasher=hasher, detectors=[self._LyingDetector()])
        result = sanitizer.sanitize_attribute("gen_ai.input.messages", "sensitive text")
        assert result.value == "[redacted:engine.detector_error]"

    def test_the_failure_finding_leaks_nothing(self, policy: Policy, hasher: ValueHasher) -> None:
        sanitizer = Sanitizer(policy=policy, hasher=hasher, detectors=[self._BrokenDetector()])
        result = sanitizer.sanitize_attribute("gen_ai.input.messages", fixtures.AWS_ACCESS_KEY_ID)
        assert fixtures.AWS_ACCESS_KEY_ID not in str(result.findings[0].to_dict())

    def test_an_oversized_string_is_dropped_rather_than_scanned(self, hasher: ValueHasher) -> None:
        policy = Policy.build(
            version="test/1",
            attributes=(),
            actions=(ActionRule("policy.", Action.DROP, Confidence(0.0)),),
            budgets=Budgets(max_string_bytes=32),
        )
        result = Sanitizer(policy=policy, hasher=hasher).sanitize_attribute("a.b", "x" * 200)
        assert result.value == "[redacted:policy.budget_exceeded]"
        assert result.findings[0].detector == "max_string_bytes"

    def test_multibyte_strings_are_measured_in_bytes(self, hasher: ValueHasher) -> None:
        policy = Policy.build(
            version="test/1",
            attributes=(),
            actions=(ActionRule("policy.", Action.DROP, Confidence(0.0)),),
            budgets=Budgets(max_string_bytes=20),
        )
        # 12 characters, 36 UTF-8 bytes.
        result = Sanitizer(policy=policy, hasher=hasher).sanitize_attribute("a.b", "日" * 12)
        assert result.value == "[redacted:policy.budget_exceeded]"

    def test_a_deeply_nested_payload_is_dropped(self, hasher: ValueHasher) -> None:
        policy = Policy.build(
            version="test/1",
            attributes=(AttributeRule("a.b", Handling.SCAN, structured=True),),
            actions=(ActionRule("policy.", Action.DROP, Confidence(0.0)),),
            budgets=Budgets(max_depth=3),
        )
        payload: object = "leaf"
        for _ in range(10):
            payload = {"n": payload}
        result = Sanitizer(policy=policy, hasher=hasher).sanitize_attribute(
            "a.b", json.dumps(payload)
        )
        assert result.value == "[redacted:policy.budget_exceeded]"

    def test_a_hostile_repr_cannot_break_hashing(self, sanitizer: Sanitizer) -> None:
        class Hostile:
            def __str__(self) -> str:
                raise RuntimeError("no")

        policy = Policy.build(
            version="test/1",
            attributes=(AttributeRule("a.b", Handling.DROP),),
            actions=(ActionRule("policy.", Action.DROP, Confidence(0.0)),),
        )
        engine = Sanitizer(policy=policy, hasher=ValueHasher.from_secret("x" * 20))
        assert engine.sanitize_attribute("a.b", Hostile()).findings[0].value_hash


class TestFindings:
    """Acceptance criterion 8."""

    def test_no_finding_contains_the_value_it_removed(self, sanitizer: Sanitizer) -> None:
        secrets = [
            fixtures.AWS_ACCESS_KEY_ID,
            fixtures.EMAIL,
            fixtures.PAYMENT_CARD,
            fixtures.JWT,
        ]
        result = sanitizer.sanitize_attribute("gen_ai.tool.call.result", " ".join(secrets))
        rendered = json.dumps([finding.to_dict() for finding in result.findings])
        assert result.findings
        for secret in secrets:
            assert secret not in rendered

    def test_every_finding_records_the_policy_version(self, sanitizer: Sanitizer) -> None:
        result = sanitizer.sanitize_attribute("a.b", fixtures.AWS_ACCESS_KEY_ID)
        assert all(f.policy_version == sanitizer.policy.version for f in result.findings)

    def test_the_same_value_hashes_alike_across_attributes(self, sanitizer: Sanitizer) -> None:
        first = sanitizer.sanitize_attribute("a.b", f"mail {fixtures.EMAIL}")
        second = sanitizer.sanitize_attribute("c.d", f"other {fixtures.EMAIL}")
        assert first.findings[0].value_hash == second.findings[0].value_hash

    def test_email_is_hashed_so_the_same_user_stays_correlatable(
        self, sanitizer: Sanitizer
    ) -> None:
        result = sanitizer.sanitize_attribute("a.b", fixtures.EMAIL)
        assert isinstance(result.value, str)
        assert result.value.startswith("[redacted:pii.email:")
        assert fixtures.EMAIL not in result.value

    def test_findings_are_ordered_by_position(self, sanitizer: Sanitizer) -> None:
        text = f"{fixtures.EMAIL} then {fixtures.AWS_ACCESS_KEY_ID}"
        result = sanitizer.sanitize_attribute("a.b", text)
        assert [str(f.rule_id) for f in result.findings] == [
            "pii.email",
            "secret.aws.access_key_id",
        ]


class TestOverlapResolution:
    def test_higher_confidence_wins(self, sanitizer: Sanitizer) -> None:
        # sk-ant- matches both the Anthropic rule (0.95) and the broader OpenAI one (0.90).
        result = sanitizer.sanitize_attribute("a.b", fixtures.ANTHROPIC_API_KEY)
        assert result.value == "[redacted:secret.anthropic.api_key]"

    def test_a_whole_value_key_match_beats_an_inner_pattern(self, sanitizer: Sanitizer) -> None:
        payload = json.dumps({"password": f"prefix {fixtures.EMAIL} suffix"})
        result = sanitizer.sanitize_attribute("gen_ai.tool.call.arguments", payload)
        assert isinstance(result.value, str)
        assert json.loads(result.value) == {"password": "[redacted:secret.generic.sensitive_key]"}


class TestDeterminism:
    def test_repeated_runs_agree(self, policy: Policy, hasher: ValueHasher) -> None:
        text = f"{fixtures.EMAIL} {fixtures.AWS_ACCESS_KEY_ID} {fixtures.PAYMENT_CARD}"
        first = Sanitizer(policy=policy, hasher=hasher).sanitize_attribute("a.b", text)
        second = Sanitizer(policy=policy, hasher=hasher).sanitize_attribute("a.b", text)
        assert first.value == second.value
        assert [f.to_dict() for f in first.findings] == [f.to_dict() for f in second.findings]


class TestIdempotence:
    """Acceptance criterion 5."""

    @pytest.mark.parametrize(
        "text",
        [
            fixtures.AWS_ACCESS_KEY_ID,
            fixtures.EMAIL,
            fixtures.JWT,
            fixtures.PRIVATE_KEY,
            f"card {fixtures.PAYMENT_CARD} and iban {fixtures.IBAN}",
        ],
    )
    def test_sanitizing_twice_changes_nothing_further(
        self, sanitizer: Sanitizer, text: str
    ) -> None:
        once = sanitizer.sanitize_attribute("a.b", text)
        twice = sanitizer.sanitize_attribute("a.b", once.value)
        assert twice.value == once.value
        assert twice.findings == ()

    def test_structured_payloads_are_idempotent(self, sanitizer: Sanitizer) -> None:
        once = sanitizer.sanitize_attribute("gen_ai.input.messages", json.dumps(CHAT_MESSAGES))
        twice = sanitizer.sanitize_attribute("gen_ai.input.messages", once.value)
        assert twice.value == once.value
        assert twice.findings == ()


class TestRecognisedButKept:
    def test_ip_addresses_survive_because_the_policy_keeps_them(self, sanitizer: Sanitizer) -> None:
        result = sanitizer.sanitize_attribute("gen_ai.tool.call.result", f"host {fixtures.IPV4}")
        assert result.value == f"host {fixtures.IPV4}"
        assert result.findings == ()


class TestDropAction:
    def test_a_policy_can_drop_the_whole_value_on_one_detection(self, hasher: ValueHasher) -> None:
        policy = Policy.build(
            version="test/1",
            attributes=(),
            actions=(ActionRule("secret.", Action.DROP, Confidence(0.6)),),
        )
        result = Sanitizer(policy=policy, hasher=hasher).sanitize_attribute(
            "a.b", f"prefix {fixtures.AWS_ACCESS_KEY_ID} suffix"
        )
        assert result.value == "[redacted:secret.aws.access_key_id]"
        assert result.findings[0].action is Action.DROP


class TestUnexpectedInternalFailure:
    """Invariant 5 for the case nobody planned for: a bug inside TraceShield itself."""

    class _BrokenHasher(ValueHasher):
        def digest(self, value: str) -> str:
            raise RuntimeError("hashing failed")

    def test_an_internal_error_drops_the_value_without_raising(self, policy: Policy) -> None:
        engine = Sanitizer(policy=policy, hasher=self._BrokenHasher(b"x" * 16))
        result = engine.sanitize_attribute("a.b", fixtures.AWS_ACCESS_KEY_ID)
        assert result.value == "[redacted:engine.internal_error]"
        assert fixtures.AWS_ACCESS_KEY_ID not in str(result.value)

    def test_the_finding_admits_the_digest_is_missing_rather_than_faking_one(
        self, policy: Policy
    ) -> None:
        engine = Sanitizer(policy=policy, hasher=self._BrokenHasher(b"x" * 16))
        finding = engine.sanitize_attribute("a.b", fixtures.AWS_ACCESS_KEY_ID).findings[0]
        assert str(finding.rule_id) == "engine.internal_error"
        assert finding.value_hash == "unavailable"
