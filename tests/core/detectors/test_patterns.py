from __future__ import annotations

import pytest

from tests import fixtures
from traceshield import DEFAULT_RULES, DetectionContext, PatternDetector
from traceshield.core.detectors.patterns import rule_for
from traceshield.core.model import RuleId

CONTEXT = DetectionContext(attribute_key="gen_ai.input.messages", path="", key_name="")


def rule_ids(text: str) -> set[str]:
    return {str(span.rule_id) for span in PatternDetector().detect(text, CONTEXT)}


class TestNamedRules:
    @pytest.mark.parametrize(
        ("value", "expected"),
        [
            (fixtures.AWS_ACCESS_KEY_ID, "secret.aws.access_key_id"),
            (fixtures.GITHUB_TOKEN, "secret.github.token"),
            (fixtures.GITHUB_FINE_GRAINED, "secret.github.fine_grained_token"),
            (fixtures.SLACK_TOKEN, "secret.slack.token"),
            (fixtures.GOOGLE_API_KEY, "secret.google.api_key"),
            (fixtures.ANTHROPIC_API_KEY, "secret.anthropic.api_key"),
            (fixtures.OPENAI_API_KEY, "secret.openai.api_key"),
            (fixtures.STRIPE_API_KEY, "secret.stripe.api_key"),
            (fixtures.JWT, "secret.jwt"),
            (fixtures.PRIVATE_KEY, "secret.private_key"),
            (fixtures.EMAIL, "pii.email"),
            (fixtures.PAYMENT_CARD, "pii.payment_card"),
            (fixtures.IBAN, "pii.iban"),
            (fixtures.US_SSN, "pii.us_ssn"),
            (fixtures.AADHAAR, "pii.india_aadhaar"),
            (fixtures.INDIA_PAN, "pii.india_pan"),
            (fixtures.PHONE_E164, "pii.phone_e164"),
            (fixtures.IPV4, "identifier.ipv4"),
        ],
    )
    def test_detects_in_surrounding_text(self, value: str, expected: str) -> None:
        assert expected in rule_ids(f"the value is {value} in a sentence")

    @pytest.mark.parametrize(
        ("text", "rule_id"),
        [
            ("Authorization: Bearer abcdefghijklmnopqrstuvwx", "credential.authorization_header"),
            ("postgres://svc:hunter2@db.internal:5432/app", "credential.url_userinfo"),
        ],
    )
    def test_detects_credentials_in_context(self, text: str, rule_id: str) -> None:
        assert rule_id in rule_ids(text)


class TestChecksumVerification:
    """The point of ADR 0004: shape alone is not a finding."""

    @pytest.mark.parametrize(
        ("value", "rule_id"),
        [
            (fixtures.PAYMENT_CARD_BAD_CHECKSUM, "pii.payment_card"),
            (fixtures.IBAN_BAD_CHECKSUM, "pii.iban"),
            (fixtures.AADHAAR_BAD_CHECKSUM, "pii.india_aadhaar"),
        ],
    )
    def test_rejects_shape_match_with_bad_checksum(self, value: str, rule_id: str) -> None:
        assert rule_id not in rule_ids(f"value {value} here")

    def test_rejects_jwt_shape_without_a_json_header(self) -> None:
        assert "secret.jwt" not in rule_ids("eyJub3RiYXNlNjQh.aaaaaaaa.bbbbbbbb")


class TestNarrowRedaction:
    def test_authorization_rule_covers_only_the_credential(self) -> None:
        text = "Authorization: Bearer abcdefghijklmnopqrstuvwx"
        span = next(
            span
            for span in PatternDetector().detect(text, CONTEXT)
            if str(span.rule_id) == "credential.authorization_header"
        )
        assert text[span.start : span.end] == "abcdefghijklmnopqrstuvwx"

    def test_url_rule_covers_only_the_userinfo(self) -> None:
        text = "postgres://svc:hunter2@db.internal:5432/app"
        span = next(
            span
            for span in PatternDetector().detect(text, CONTEXT)
            if str(span.rule_id) == "credential.url_userinfo"
        )
        assert text[span.start : span.end] == "svc:hunter2"


class TestRulePack:
    def test_rule_ids_are_unique(self) -> None:
        ids = [rule.rule_id for rule in DEFAULT_RULES]
        assert len(set(ids)) == len(ids)

    def test_rule_ids_are_namespaced(self) -> None:
        prefixes = {"secret", "credential", "pii", "identifier"}
        assert all(str(rule.rule_id).split(".")[0] in prefixes for rule in DEFAULT_RULES)

    def test_lookup_by_id(self) -> None:
        assert rule_for(RuleId("secret.aws.access_key_id")) is not None
        assert rule_for(RuleId("nope.not.a.rule")) is None

    def test_clean_text_produces_nothing(self) -> None:
        assert rule_ids("the agent listed three files and returned successfully") == set()


class TestGreedyMatchRefinement:
    """Regression tests for a bug found by test_a_detected_secret_never_survives.

    A greedy quantifier absorbed the digit following a card number, Luhn rejected the
    over-long candidate, and the card was exported intact. Shape matching and verification
    have to agree on the same span, or verification silently becomes a way to miss things.
    """

    def _card_span(self, text: str) -> str:
        span = next(
            span
            for span in PatternDetector().detect(text, CONTEXT)
            if str(span.rule_id) == "pii.payment_card"
        )
        return text[span.start : span.end]

    def test_a_trailing_digit_no_longer_hides_a_card(self) -> None:
        assert self._card_span(f" {fixtures.PAYMENT_CARD} 0") == fixtures.PAYMENT_CARD

    def test_a_leading_digit_no_longer_hides_a_card(self) -> None:
        assert "pii.payment_card" in rule_ids(f"7 {fixtures.PAYMENT_CARD} ")

    def test_grouped_cards_are_matched_exactly(self) -> None:
        assert self._card_span("pay 4111 1111 1111 1111 now") == "4111 1111 1111 1111"
        assert self._card_span("pay 4111-1111-1111-1111 now") == "4111-1111-1111-1111"

    def test_grouped_card_followed_by_a_digit(self) -> None:
        assert self._card_span("card 4111 1111 1111 1111 7 end") == "4111 1111 1111 1111"

    def test_a_long_digit_run_is_not_trimmed_until_luhn_passes(self) -> None:
        """Refinement must not manufacture findings. Luhn accepts about one random input in
        ten, so walking a long digit run would flag ordinary identifiers."""
        assert "pii.payment_card" not in rule_ids("order 1234567890123456789 shipped")

    def test_iban_refines_past_trailing_characters(self) -> None:
        text = f"iban {fixtures.IBAN}XY reference"
        span = next(
            span
            for span in PatternDetector().detect(text, CONTEXT)
            if str(span.rule_id) == "pii.iban"
        )
        assert text[span.start : span.end] == fixtures.IBAN


class TestCustomRules:
    def test_a_rule_whose_group_matches_nothing_produces_no_span(self) -> None:
        """Custom rules may use optional groups; an empty capture is not a finding."""
        import re

        from traceshield.core.detectors.patterns import PatternRule
        from traceshield.core.model import Category, Confidence, Severity

        rule = PatternRule(
            rule_id=RuleId("secret.custom"),
            category=Category.SECRET,
            severity=Severity.LOW,
            confidence=Confidence(0.9),
            pattern=re.compile(r"key(=(\w+))?"),
            group=2,
        )
        assert tuple(PatternDetector([rule]).detect("key", CONTEXT)) == ()
        assert len(tuple(PatternDetector([rule]).detect("key=value", CONTEXT))) == 1
