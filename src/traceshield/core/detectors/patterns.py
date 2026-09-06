"""The named rule pack.

Every rule that has a checksum carries its verifier, because a shape match without
verification is how a redaction tool trains its users to ignore it (ADR 0004).

Fixture policy: every test value for these rules is synthetic and, where a checksum applies,
constructed to satisfy it. No real credential and no real person's identifier belongs in
this repository.
"""

from __future__ import annotations

import re
from collections.abc import Callable, Iterable, Sequence
from dataclasses import dataclass, field
from enum import Enum

from traceshield.core.detectors.base import DetectionContext
from traceshield.core.detectors.verifiers import iban_mod97, jwt_header_is_json, luhn, verhoeff
from traceshield.core.model import Category, Confidence, DetectionSpan, RuleId, Severity

RULE_PACK_VERSION = "2026.09.1"
"""Versioned separately from the package. A policy pins behaviour; the pack pins coverage."""


class Refinement(str, Enum):
    """What to do when a match has the right shape but fails its checksum.

    A greedy quantifier can absorb one character too many, which makes a genuine card or
    IBAN fail verification and slip through. Retrying shorter candidates recovers those, but
    it is not free: every retry is another chance for a random digit run to pass by luck.

    So refinement is chosen per rule, against the strength of its checksum. Luhn accepts
    roughly one in ten random inputs, so a payment card only retries at separator
    boundaries, which undoes over-greedy grouping without walking a long digit run. IBAN's
    mod-97 accepts roughly one in ninety-seven, which is strong enough to retry character by
    character.
    """

    NONE = "none"
    SEPARATORS = "separators"
    CHARACTERS = "characters"


@dataclass(frozen=True, slots=True)
class PatternRule:
    """One named detection rule.

    ``group`` exists so a rule can match surrounding context while redacting only the
    sensitive part, which is how basic-auth credentials in a URL are handled without
    destroying the host.
    """

    rule_id: RuleId
    category: Category
    severity: Severity
    confidence: Confidence
    pattern: re.Pattern[str]
    verifier: Callable[[str], bool] | None = field(default=None)
    group: int = 0
    refinement: Refinement = Refinement.NONE


def _rule(
    rule_id: str,
    category: Category,
    severity: Severity,
    confidence: float,
    pattern: str,
    *,
    flags: int = 0,
    verifier: Callable[[str], bool] | None = None,
    group: int = 0,
    refinement: Refinement = Refinement.NONE,
) -> PatternRule:
    return PatternRule(
        rule_id=RuleId(rule_id),
        category=category,
        severity=severity,
        confidence=Confidence(confidence),
        pattern=re.compile(pattern, flags),
        verifier=verifier,
        group=group,
        refinement=refinement,
    )


DEFAULT_RULES: tuple[PatternRule, ...] = (
    # --- Provider credentials. Unambiguous prefixes, so confidence is high without a
    # checksum: nothing else in a trace looks like these.
    _rule(
        "secret.aws.access_key_id",
        Category.SECRET,
        Severity.CRITICAL,
        0.98,
        r"\b(?:AKIA|ASIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ABIA|ACCA)[0-9A-Z]{16}\b",
    ),
    _rule(
        "secret.github.token",
        Category.SECRET,
        Severity.CRITICAL,
        0.95,
        r"\bgh[pousr]_[A-Za-z0-9]{36,251}\b",
    ),
    _rule(
        "secret.github.fine_grained_token",
        Category.SECRET,
        Severity.CRITICAL,
        0.95,
        r"\bgithub_pat_[A-Za-z0-9_]{22,255}\b",
    ),
    _rule(
        "secret.slack.token",
        Category.SECRET,
        Severity.CRITICAL,
        0.95,
        r"\bxox[baprse]-[A-Za-z0-9-]{10,}",
    ),
    _rule(
        "secret.google.api_key",
        Category.SECRET,
        Severity.CRITICAL,
        0.95,
        r"\bAIza[0-9A-Za-z_-]{35}\b",
    ),
    _rule(
        "secret.anthropic.api_key",
        Category.SECRET,
        Severity.CRITICAL,
        0.95,
        r"\bsk-ant-[A-Za-z0-9_-]{24,}",
    ),
    _rule(
        "secret.openai.api_key",
        Category.SECRET,
        Severity.CRITICAL,
        0.9,
        r"\bsk-(?:proj-|svcacct-|admin-)?[A-Za-z0-9_-]{20,}",
    ),
    _rule(
        "secret.stripe.api_key",
        Category.SECRET,
        Severity.CRITICAL,
        0.95,
        r"\b[sr]k_(?:live|test)_[A-Za-z0-9]{16,}\b",
    ),
    # --- Credential material carried in transport metadata that agents copy into arguments.
    _rule(
        "secret.private_key",
        Category.SECRET,
        Severity.CRITICAL,
        0.99,
        r"-----BEGIN (?:[A-Z ]+ )?PRIVATE KEY(?: BLOCK)?-----[\s\S]*?-----END (?:[A-Z ]+ )?PRIVATE KEY(?: BLOCK)?-----",
    ),
    _rule(
        "secret.jwt",
        Category.SECRET,
        Severity.HIGH,
        0.9,
        r"\beyJ[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]{6,}",
        verifier=jwt_header_is_json,
    ),
    _rule(
        "credential.authorization_header",
        Category.CREDENTIAL,
        Severity.HIGH,
        0.9,
        r"\b(?:Bearer|Basic|Token)\s+([A-Za-z0-9._~+/=-]{12,})",
        flags=re.IGNORECASE,
        group=1,
    ),
    _rule(
        # Redacts only the userinfo, so the host and path stay debuggable.
        "credential.url_userinfo",
        Category.CREDENTIAL,
        Severity.HIGH,
        0.95,
        r"[a-zA-Z][a-zA-Z0-9+.-]*://([^\s/:@]+:[^\s/@]+)@",
        group=1,
    ),
    # --- Personal data. Every rule with a checksum verifies it.
    _rule(
        "pii.email",
        Category.PII,
        Severity.MEDIUM,
        0.9,
        r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,}\b",
    ),
    _rule(
        "pii.payment_card",
        Category.PII,
        Severity.CRITICAL,
        0.95,
        r"\b(?:\d{13,19}|\d{4}(?:[ -]\d{4}){2,3}(?:[ -]\d{1,3})?)\b",
        verifier=luhn,
        refinement=Refinement.SEPARATORS,
    ),
    _rule(
        "pii.iban",
        Category.PII,
        Severity.HIGH,
        0.95,
        r"\b[A-Z]{2}\d{2}[A-Z0-9]{11,30}\b",
        verifier=iban_mod97,
        refinement=Refinement.CHARACTERS,
    ),
    _rule(
        "pii.us_ssn",
        Category.PII,
        Severity.CRITICAL,
        0.9,
        r"\b(?!000|666|9\d\d)\d{3}-(?!00)\d{2}-(?!0000)\d{4}\b",
    ),
    _rule(
        "pii.india_aadhaar",
        Category.PII,
        Severity.CRITICAL,
        0.95,
        r"\b[2-9]\d{3}[ -]?\d{4}[ -]?\d{4}\b",
        verifier=verhoeff,
    ),
    _rule(
        "pii.india_pan",
        Category.PII,
        Severity.HIGH,
        0.85,
        r"\b[A-Z]{5}\d{4}[A-Z]\b",
    ),
    _rule(
        "pii.phone_e164",
        Category.PII,
        Severity.MEDIUM,
        0.75,
        r"\+[1-9]\d{7,14}\b",
    ),
    # --- Identifiers that are useful for debugging. Recognised so a policy can choose;
    # the bundled policy keeps them.
    _rule(
        "identifier.ipv4",
        Category.IDENTIFIER,
        Severity.LOW,
        0.7,
        r"\b(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\b",
    ),
)


class PatternDetector:
    """Applies the named rule pack, rejecting matches that fail their checksum."""

    __slots__ = ("_rules",)

    def __init__(self, rules: Sequence[PatternRule] = DEFAULT_RULES) -> None:
        self._rules = tuple(rules)

    @property
    def name(self) -> str:
        return "pattern"

    def detect(self, text: str, context: DetectionContext) -> Iterable[DetectionSpan]:
        del context  # Pattern matching does not depend on where the string came from.
        spans: list[DetectionSpan] = []
        for rule in self._rules:
            for match in rule.pattern.finditer(text):
                if not match.group(rule.group):
                    continue
                verified = _verified_span(text, *match.span(rule.group), rule=rule)
                if verified is None:
                    continue
                start, end = verified
                spans.append(
                    DetectionSpan(
                        start=start,
                        end=end,
                        rule_id=rule.rule_id,
                        category=rule.category,
                        severity=rule.severity,
                        confidence=rule.confidence,
                        detector=self.name,
                    )
                )
        return spans


_SEPARATORS = frozenset(" -")


def _verified_span(text: str, start: int, end: int, *, rule: PatternRule) -> tuple[int, int] | None:
    """Return the span that actually satisfies the rule's checksum, or ``None``."""
    if rule.verifier is None:
        return start, end
    if rule.verifier(text[start:end]):
        return start, end
    for stop in _refinement_stops(text, start, end, rule.refinement):
        if rule.verifier(text[start:stop]):
            return start, stop
    return None


def _refinement_stops(text: str, start: int, end: int, refinement: Refinement) -> Iterable[int]:
    """Candidate shorter end offsets to retry, longest first."""
    if refinement is Refinement.CHARACTERS:
        return range(end - 1, start, -1)
    if refinement is Refinement.SEPARATORS:
        return [index for index in range(end - 1, start, -1) if text[index] in _SEPARATORS]
    return ()


_RULES_BY_ID = {rule.rule_id: rule for rule in DEFAULT_RULES}


def rule_for(rule_id: RuleId) -> PatternRule | None:
    """Look up a pattern rule, for callers that need its category and severity."""
    return _RULES_BY_ID.get(rule_id)
