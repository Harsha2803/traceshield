"""Property tests for the invariants in docs/Architecture.md.

Determinism is what makes these possible; ADR 0004 chose it partly for this reason.
"""

from __future__ import annotations

import json

from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from tests import fixtures
from traceshield import Policy, Sanitizer, ValueHasher

SECRETS = [
    fixtures.AWS_ACCESS_KEY_ID,
    fixtures.GITHUB_TOKEN,
    fixtures.GOOGLE_API_KEY,
    fixtures.STRIPE_API_KEY,
    fixtures.PAYMENT_CARD,
    fixtures.IBAN,
    fixtures.US_SSN,
    fixtures.EMAIL,
]

SANITIZER = Sanitizer(
    policy=Policy.default(),
    hasher=ValueHasher.from_secret("traceshield-property-test-salt"),
)

# Printable text without the bracket characters a placeholder uses, so generated noise can
# never accidentally look like TraceShield output.
noise = st.text(
    alphabet=st.characters(min_codepoint=32, max_codepoint=126, blacklist_characters="[]"),
    max_size=60,
)

json_leaves = st.one_of(noise, st.integers(), st.booleans(), st.none())
json_documents = st.recursive(
    json_leaves,
    lambda children: st.one_of(
        st.lists(children, max_size=4),
        st.dictionaries(st.text(min_size=1, max_size=8), children, max_size=4),
    ),
    max_leaves=12,
)

SETTINGS = settings(max_examples=150, suppress_health_check=[HealthCheck.function_scoped_fixture])


def shape(value: object) -> object:
    if isinstance(value, dict):
        return {key: shape(item) for key, item in value.items()}
    if isinstance(value, list):
        return [shape(item) for item in value]
    return type(value).__name__


@SETTINGS
@given(prefix=noise, secret=st.sampled_from(SECRETS), suffix=noise)
def test_a_detected_secret_never_survives(prefix: str, secret: str, suffix: str) -> None:
    result = SANITIZER.sanitize_attribute("gen_ai.tool.call.result", f"{prefix} {secret} {suffix}")
    assert isinstance(result.value, str)
    assert secret not in result.value


@SETTINGS
@given(prefix=noise, secret=st.sampled_from(SECRETS), suffix=noise)
def test_findings_never_carry_the_secret(prefix: str, secret: str, suffix: str) -> None:
    result = SANITIZER.sanitize_attribute("gen_ai.tool.call.result", f"{prefix} {secret} {suffix}")
    rendered = json.dumps([finding.to_dict() for finding in result.findings])
    assert secret not in rendered


@SETTINGS
@given(text=noise)
def test_sanitization_is_idempotent_for_text(text: str) -> None:
    once = SANITIZER.sanitize_attribute("gen_ai.tool.call.result", text)
    twice = SANITIZER.sanitize_attribute("gen_ai.tool.call.result", once.value)
    assert twice.value == once.value


@SETTINGS
@given(document=json_documents)
def test_structure_is_preserved_for_documents(document: object) -> None:
    payload = json.dumps(document)
    result = SANITIZER.sanitize_attribute("gen_ai.input.messages", payload)
    assert isinstance(result.value, str)
    assert shape(json.loads(result.value)) == shape(document)


@SETTINGS
@given(document=json_documents)
def test_document_sanitization_is_idempotent(document: object) -> None:
    once = SANITIZER.sanitize_attribute("gen_ai.input.messages", json.dumps(document))
    twice = SANITIZER.sanitize_attribute("gen_ai.input.messages", once.value)
    assert twice.value == once.value


@SETTINGS
@given(document=json_documents)
def test_sanitization_never_raises(document: object) -> None:
    # Invariant 5: whatever arrives, the export path keeps working.
    SANITIZER.sanitize_attribute("gen_ai.input.messages", json.dumps(document))
    SANITIZER.sanitize_attributes({"gen_ai.input.messages": document})
