"""The sanitizer.

One public entry point for the domain. Everything it does is synchronous, deterministic and
free of I/O, because it runs on the OpenTelemetry batch export worker thread (ADR 0003).

The single most important property of this module is that it never raises. It sits inside
somebody else's telemetry pipeline; a redaction library that breaks the pipeline it was
added to protect will simply be removed. Every failure path removes the value it could not
clear and records why.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence

from traceshield.core.detectors.base import DetectionContext, Detector
from traceshield.core.detectors.entropy import EntropyDetector
from traceshield.core.detectors.keyname import KeyNameDetector
from traceshield.core.detectors.patterns import PatternDetector
from traceshield.core.errors import BudgetExceededError
from traceshield.core.hashing import ValueHasher
from traceshield.core.model import (
    Action,
    Category,
    Confidence,
    DetectionSpan,
    Finding,
    Handling,
    RuleId,
    SanitizedAttributes,
    SanitizedValue,
    Severity,
    ValueHash,
)
from traceshield.core.policy import AttributeRule, Policy
from traceshield.core.redact import (
    apply_replacements,
    placeholder,
    placeholder_spans,
    replacement_for,
    within_placeholder,
)
from traceshield.core.walk import (
    WalkBudget,
    looks_like_json,
    parse_json_document,
    serialize_json_document,
    transform,
)

ATTRIBUTE_DROPPED_RULE = RuleId("policy.attribute_dropped")
BUDGET_EXCEEDED_RULE = RuleId("policy.budget_exceeded")
DETECTOR_ERROR_RULE = RuleId("engine.detector_error")
INTERNAL_ERROR_RULE = RuleId("engine.internal_error")

_DIGEST_UNAVAILABLE = "unavailable"
"""Recorded instead of a digest when hashing itself failed.

A fabricated hex string would be indistinguishable from a real digest, which would make the
audit record lie. Saying so plainly is the only honest option."""


class _LeafFailure(Exception):
    """Internal signal that a leaf must be dropped. Never escapes this module."""

    def __init__(self, rule_id: RuleId, detector: str) -> None:
        super().__init__(str(rule_id))
        self.rule_id = rule_id
        self.detector = detector


class Sanitizer:
    """Detects and redacts sensitive values in telemetry attributes.

    Dependencies are constructor-injected so the engine stays deterministic and testable:
    the salt belongs to the composition root, and the detector list is what ADR 0004's
    deferred ML detectors will plug into.
    """

    __slots__ = ("_detectors", "_hasher", "_policy")

    def __init__(
        self,
        *,
        policy: Policy,
        hasher: ValueHasher,
        detectors: Sequence[Detector] | None = None,
    ) -> None:
        self._policy = policy
        self._hasher = hasher
        self._detectors: tuple[Detector, ...] = (
            tuple(detectors)
            if detectors is not None
            else (
                PatternDetector(),
                KeyNameDetector(policy.key_names),
                EntropyDetector(policy.entropy),
            )
        )

    @property
    def policy(self) -> Policy:
        return self._policy

    def sanitize_attributes(self, attributes: Mapping[str, object]) -> SanitizedAttributes:
        """Sanitize a whole attribute mapping.

        Attributes the policy drops are reported in ``dropped_keys`` rather than rewritten,
        so a caller can delete the key instead of exporting a placeholder for it.
        """
        sanitized: dict[str, object] = {}
        dropped: list[str] = []
        findings: list[Finding] = []
        for key, value in attributes.items():
            rule = self._policy.rule_for_attribute(key)
            if rule.handling is Handling.DROP:
                dropped.append(key)
                findings.append(
                    self._finding(
                        rule_id=ATTRIBUTE_DROPPED_RULE,
                        category=Category.POLICY,
                        severity=Severity.MEDIUM,
                        confidence=Confidence(1.0),
                        action=Action.DROP,
                        attribute_key=key,
                        path="",
                        detector="policy",
                        value=value,
                    )
                )
                continue
            result = self.sanitize_attribute(key, value)
            sanitized[key] = result.value
            findings.extend(result.findings)
        return SanitizedAttributes(
            attributes=sanitized,
            dropped_keys=tuple(dropped),
            findings=tuple(findings),
        )

    def sanitize_attribute(self, key: str, value: object) -> SanitizedValue:
        """Sanitize one attribute value.

        Never raises. A budget breach, a failing detector or an unexpected internal error
        all remove the value and record a finding explaining which happened.
        """
        findings: list[Finding] = []
        rule = self._policy.rule_for_attribute(key)
        if rule.handling is Handling.KEEP:
            return SanitizedValue(value, ())
        if rule.handling is Handling.DROP:
            return self._dropped(key, value, ATTRIBUTE_DROPPED_RULE, Category.POLICY, "policy")
        try:
            new_value = self._scan(key, value, rule, findings)
        except BudgetExceededError as exceeded:
            return self._dropped(
                key,
                value,
                BUDGET_EXCEEDED_RULE,
                Category.POLICY,
                detector=exceeded.budget,
            )
        except _LeafFailure as failure:
            return self._dropped(
                key, value, failure.rule_id, Category.ENGINE, detector=failure.detector
            )
        # Deliberately broad: an unexpected bug in this engine must remove the value it
        # could not clear, not propagate into the caller's export path. Invariant 5.
        except Exception:
            return self._dropped(key, value, INTERNAL_ERROR_RULE, Category.ENGINE, "engine")
        return SanitizedValue(new_value, tuple(findings))

    # -- internals ---------------------------------------------------------------------

    def _scan(
        self,
        key: str,
        value: object,
        rule: AttributeRule,
        findings: list[Finding],
    ) -> object:
        budgets = self._policy.budgets
        budget = WalkBudget(max_depth=budgets.max_depth, max_nodes=budgets.max_nodes)

        def leaf(text: str, path: str, key_name: str) -> str:
            return self._sanitize_text(
                text,
                attribute_key=key,
                path=path,
                key_name=key_name,
                findings=findings,
            )

        if isinstance(value, str) and rule.structured and looks_like_json(value):
            document = parse_json_document(value)
            if document is not None:
                return serialize_json_document(transform(document, leaf, budget=budget))
        return transform(value, leaf, budget=budget, key_name=_leaf_key_name(key))

    def _sanitize_text(
        self,
        text: str,
        *,
        attribute_key: str,
        path: str,
        key_name: str,
        findings: list[Finding],
    ) -> str:
        if _exceeds_bytes(text, self._policy.budgets.max_string_bytes):
            raise BudgetExceededError("max_string_bytes", self._policy.budgets.max_string_bytes)

        context = DetectionContext(attribute_key=attribute_key, path=path, key_name=key_name)
        existing = placeholder_spans(text)
        candidates: list[DetectionSpan] = []
        for detector in self._detectors:
            try:
                found = tuple(detector.detect(text, context))
            # A third-party detector is untrusted code on the data path. If it fails we
            # have no evidence the value is safe, so the value goes rather than the check.
            except Exception as error:
                raise _LeafFailure(DETECTOR_ERROR_RULE, detector.name) from error
            for span in found:
                if span.end > len(text):
                    raise _LeafFailure(DETECTOR_ERROR_RULE, detector.name)
                if within_placeholder(span.start, span.end, existing):
                    continue
                candidates.append(span)

        replacements: list[tuple[int, int, str]] = []
        for span in _resolve_overlaps(candidates):
            action, keep_prefix = self._policy.action_for(span.rule_id, span.confidence)
            if action is Action.KEEP:
                continue
            matched = text[span.start : span.end]
            digest = self._hasher.digest(matched)
            findings.append(
                self._finding(
                    rule_id=span.rule_id,
                    category=span.category,
                    severity=span.severity,
                    confidence=span.confidence,
                    action=action,
                    attribute_key=attribute_key,
                    path=path,
                    detector=span.detector,
                    value_hash=ValueHash(digest),
                )
            )
            if action is Action.DROP:
                return placeholder(span.rule_id)
            replacements.append(
                (
                    span.start,
                    span.end,
                    replacement_for(
                        matched,
                        action=action,
                        rule_id=span.rule_id,
                        digest=digest,
                        keep_prefix=keep_prefix,
                    ),
                )
            )
        return apply_replacements(text, replacements)

    def _dropped(
        self,
        key: str,
        value: object,
        rule_id: RuleId,
        category: Category,
        detector: str,
    ) -> SanitizedValue:
        finding = self._finding(
            rule_id=rule_id,
            category=category,
            severity=Severity.MEDIUM if category is Category.POLICY else Severity.HIGH,
            confidence=Confidence(1.0),
            action=Action.DROP,
            attribute_key=key,
            path="",
            detector=detector,
            value=value,
        )
        return SanitizedValue(placeholder(rule_id), (finding,))

    def _finding(
        self,
        *,
        rule_id: RuleId,
        category: Category,
        severity: Severity,
        confidence: Confidence,
        action: Action,
        attribute_key: str,
        path: str,
        detector: str,
        value: object = None,
        value_hash: ValueHash | None = None,
    ) -> Finding:
        digest = value_hash if value_hash is not None else ValueHash(self._digest(value))
        return Finding(
            rule_id=rule_id,
            category=category,
            severity=severity,
            confidence=confidence,
            action=action,
            attribute_key=attribute_key,
            path=path,
            detector=detector,
            value_hash=digest,
            policy_version=self._policy.version,
        )

    def _digest(self, value: object) -> str:
        """Digest a value for a finding, tolerating a hostile value or a broken hasher.

        This runs on the fail-closed path, so it must not depend on the component that may
        have just failed. An earlier version called the hasher here without a guard, which
        meant a failing hasher escaped ``sanitize_attribute`` entirely and broke the caller's
        export. Regression test: TestUnexpectedInternalFailure.
        """
        try:
            rendered = value if isinstance(value, str) else str(value)
            return self._hasher.digest(rendered)
        # Both a hostile __str__ and a broken hasher land here. Neither may stop redaction.
        except Exception:
            return _DIGEST_UNAVAILABLE


def _leaf_key_name(attribute_key: str) -> str:
    """Use the last dotted segment of an attribute key as the key-name signal.

    ``http.request.header.authorization`` should trip the key-name detector on
    ``authorization``, exactly as a JSON field of that name would.
    """
    return attribute_key.rsplit(".", 1)[-1] if attribute_key else ""


def _exceeds_bytes(text: str, limit: int) -> bool:
    """Check the UTF-8 length against a limit, encoding only when it might matter."""
    if len(text) > limit:
        return True
    if len(text) * 4 <= limit:
        return False
    return len(text.encode("utf-8", errors="replace")) > limit


def _resolve_overlaps(spans: Sequence[DetectionSpan]) -> list[DetectionSpan]:
    """Pick a non-overlapping set of detections, then order it positionally.

    Highest confidence wins, then the longest span, then the rule identifier. The last tie
    break exists purely so the result is stable: two detectors agreeing on a region must not
    produce different output between runs.
    """
    ordered = sorted(
        spans,
        key=lambda span: (-float(span.confidence), -span.length, str(span.rule_id), span.start),
    )
    accepted: list[DetectionSpan] = []
    for span in ordered:
        if any(span.overlaps(chosen) for chosen in accepted):
            continue
        accepted.append(span)
    return sorted(accepted, key=lambda span: span.start)
