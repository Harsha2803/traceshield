from __future__ import annotations

import pytest

from traceshield import (
    CONTENT_BEARING_ATTRIBUTES,
    Action,
    ActionRule,
    AttributeRule,
    Budgets,
    Confidence,
    Handling,
    Policy,
    PolicyError,
)
from traceshield.core.model import RuleId
from traceshield.core.policy import STRUCTURED_ATTRIBUTES


class TestDefaultPolicyCoverage:
    def test_every_content_bearing_attribute_is_named_explicitly(self) -> None:
        """Acceptance criterion 2. Relying on the scan-by-default fallback is not coverage:
        an attribute that matters must be visible in the policy an auditor reads."""
        policy = Policy.default()
        for key in CONTENT_BEARING_ATTRIBUTES:
            assert key in policy.exact_attributes, key
            assert policy.exact_attributes[key].handling is Handling.SCAN, key

    def test_schema_backed_attributes_are_parsed_as_documents(self) -> None:
        policy = Policy.default()
        for key in STRUCTURED_ATTRIBUTES:
            assert policy.rule_for_attribute(key).structured is True, key

    def test_unstructured_content_attributes_are_not_parsed(self) -> None:
        assert Policy.default().rule_for_attribute("gen_ai.tool.description").structured is False

    def test_unknown_attributes_are_scanned(self) -> None:
        # Fails closed: a new content field is likelier than a new counter.
        assert Policy.default().rule_for_attribute("some.future.field").handling is Handling.SCAN

    @pytest.mark.parametrize(
        "key", ["gen_ai.usage.input_tokens", "gen_ai.request.model", "gen_ai.tool.name"]
    )
    def test_low_value_attributes_are_kept(self, key: str) -> None:
        assert Policy.default().rule_for_attribute(key).handling is Handling.KEEP


class TestAttributeResolution:
    def test_exact_match_beats_prefix(self) -> None:
        policy = Policy.build(
            version="test/1",
            attributes=(
                AttributeRule("a.", Handling.KEEP),
                AttributeRule("a.b", Handling.SCAN),
            ),
            actions=(),
        )
        assert policy.rule_for_attribute("a.b").handling is Handling.SCAN
        assert policy.rule_for_attribute("a.c").handling is Handling.KEEP

    def test_longest_prefix_wins(self) -> None:
        policy = Policy.build(
            version="test/1",
            attributes=(
                AttributeRule("a.", Handling.KEEP),
                AttributeRule("a.b.", Handling.DROP),
            ),
            actions=(),
        )
        assert policy.rule_for_attribute("a.b.c").handling is Handling.DROP
        assert policy.rule_for_attribute("a.x").handling is Handling.KEEP


class TestActionResolution:
    def _policy(self) -> Policy:
        return Policy.build(
            version="test/1",
            attributes=(),
            actions=(
                ActionRule("secret.", Action.MASK, Confidence(0.6)),
                ActionRule("secret.jwt", Action.HASH, Confidence(0.95)),
            ),
        )

    def test_longest_prefix_wins(self) -> None:
        action, _ = self._policy().action_for(RuleId("secret.jwt"), Confidence(0.99))
        assert action is Action.HASH

    def test_specific_rule_below_threshold_keeps_rather_than_falling_through(self) -> None:
        """Predictability over recall: an operator reading the policy must be able to say
        what it will do without simulating a fall-through chain."""
        action, _ = self._policy().action_for(RuleId("secret.jwt"), Confidence(0.7))
        assert action is Action.KEEP

    def test_unmatched_rule_uses_the_default_action(self) -> None:
        action, _ = self._policy().action_for(RuleId("brand.new.rule"), Confidence(0.5))
        assert action is Action.MASK

    def test_default_policy_keeps_ip_addresses(self) -> None:
        action, _ = Policy.default().action_for(RuleId("identifier.ipv4"), Confidence(0.7))
        assert action is Action.KEEP

    def test_default_policy_hashes_email(self) -> None:
        action, _ = Policy.default().action_for(RuleId("pii.email"), Confidence(0.9))
        assert action is Action.HASH


class TestValidation:
    def test_rejects_empty_version(self) -> None:
        with pytest.raises(PolicyError, match="version"):
            Policy.build(version="", attributes=(), actions=())

    def test_rejects_duplicate_attribute_rule(self) -> None:
        with pytest.raises(PolicyError, match="duplicate attribute rule"):
            Policy.build(
                version="test/1",
                attributes=(AttributeRule("a", Handling.SCAN), AttributeRule("a", Handling.KEEP)),
                actions=(),
            )

    def test_rejects_duplicate_prefix_rule(self) -> None:
        with pytest.raises(PolicyError, match="duplicate attribute prefix"):
            Policy.build(
                version="test/1",
                attributes=(AttributeRule("a.", Handling.SCAN), AttributeRule("a.", Handling.KEEP)),
                actions=(),
            )

    def test_rejects_duplicate_action_rule(self) -> None:
        with pytest.raises(PolicyError, match="duplicate action rule"):
            Policy.build(
                version="test/1",
                attributes=(),
                actions=(
                    ActionRule("secret.", Action.MASK, Confidence(0.6)),
                    ActionRule("secret.", Action.DROP, Confidence(0.6)),
                ),
            )

    def test_rejects_empty_attribute_key(self) -> None:
        with pytest.raises(PolicyError, match="must not be empty"):
            AttributeRule("", Handling.SCAN)

    def test_rejects_structured_attribute_that_is_not_scanned(self) -> None:
        with pytest.raises(PolicyError, match="structured"):
            AttributeRule("a", Handling.KEEP, structured=True)

    def test_rejects_empty_action_prefix(self) -> None:
        with pytest.raises(PolicyError, match="must not be empty"):
            ActionRule("", Action.MASK, Confidence(0.5))

    def test_rejects_negative_keep_prefix(self) -> None:
        with pytest.raises(PolicyError, match="negative keep_prefix"):
            ActionRule("a", Action.PARTIAL, Confidence(0.5), keep_prefix=-1)

    def test_rejects_keep_prefix_without_partial_action(self) -> None:
        with pytest.raises(PolicyError, match="not partial"):
            ActionRule("a", Action.MASK, Confidence(0.5), keep_prefix=4)

    def test_rejects_partial_as_the_default_action(self) -> None:
        with pytest.raises(PolicyError, match="default action"):
            Policy.build(version="test/1", attributes=(), actions=(), default_action=Action.PARTIAL)

    @pytest.mark.parametrize(
        "kwargs", [{"max_depth": 0}, {"max_nodes": 0}, {"max_string_bytes": 0}]
    )
    def test_rejects_non_positive_budgets(self, kwargs: dict[str, int]) -> None:
        with pytest.raises(PolicyError, match="at least 1"):
            Budgets(**kwargs)


class TestPolicyVersion:
    def test_version_names_the_rule_pack(self) -> None:
        from traceshield import RULE_PACK_VERSION

        assert RULE_PACK_VERSION in Policy.default().version
