"""Detectors: the pluggable signals the engine combines."""

from traceshield.core.detectors.base import DetectionContext, Detector
from traceshield.core.detectors.entropy import (
    HIGH_ENTROPY_RULE_ID,
    EntropyDetector,
    EntropySettings,
    shannon_entropy,
)
from traceshield.core.detectors.keyname import (
    SENSITIVE_KEY_RULE_ID,
    KeyNameDetector,
    KeyNameSettings,
)
from traceshield.core.detectors.patterns import (
    DEFAULT_RULES,
    RULE_PACK_VERSION,
    PatternDetector,
    PatternRule,
    rule_for,
)
from traceshield.core.detectors.verifiers import iban_mod97, jwt_header_is_json, luhn, verhoeff

__all__ = [
    "DEFAULT_RULES",
    "HIGH_ENTROPY_RULE_ID",
    "RULE_PACK_VERSION",
    "SENSITIVE_KEY_RULE_ID",
    "DetectionContext",
    "Detector",
    "EntropyDetector",
    "EntropySettings",
    "KeyNameDetector",
    "KeyNameSettings",
    "PatternDetector",
    "PatternRule",
    "iban_mod97",
    "jwt_header_is_json",
    "luhn",
    "rule_for",
    "shannon_entropy",
    "verhoeff",
]
