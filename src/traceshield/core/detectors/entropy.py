"""Shannon entropy scoring for credentials that no named rule covers.

Entropy is the weakest of the four signals in ADR 0004 and the easiest to turn into noise,
so this detector is deliberately narrow. The exclusions matter more than the threshold: a
trace is full of UUIDs, trace identifiers and epoch timestamps, and flagging those would
train users to disable the tool.
"""

from __future__ import annotations

import math
import re
from collections import Counter
from collections.abc import Iterable
from dataclasses import dataclass

from traceshield.core.detectors.base import DetectionContext
from traceshield.core.model import Category, Confidence, DetectionSpan, RuleId, Severity

HIGH_ENTROPY_RULE_ID = RuleId("secret.generic.high_entropy")

_TOKEN_RE = re.compile(r"[A-Za-z0-9+/=_-]{16,}")
_UUID_RE = re.compile(
    r"\A[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\Z"
)
_HEX_RE = re.compile(r"\A[0-9a-fA-F]+\Z")


@dataclass(frozen=True, slots=True)
class EntropySettings:
    """Thresholds for entropy scoring, tunable through the policy.

    Separate thresholds per charset because the maximum achievable entropy differs: a random
    hex string tops out near 4 bits per character while a base64 one reaches nearly 6, so a
    single threshold either misses hex secrets or floods on base64 identifiers.
    """

    min_length: int = 25
    min_hex_length: int = 40
    bits_per_char: float = 4.0
    hex_bits_per_char: float = 3.7
    confidence: float = 0.6

    def __post_init__(self) -> None:
        if self.min_length < 8:
            raise ValueError("entropy min_length must be at least 8")
        if self.bits_per_char <= 0 or self.hex_bits_per_char <= 0:
            raise ValueError("entropy thresholds must be positive")


def shannon_entropy(text: str) -> float:
    """Bits of Shannon entropy per character."""
    if not text:
        return 0.0
    counts = Counter(text)
    length = len(text)
    return -sum((count / length) * math.log2(count / length) for count in counts.values())


class EntropyDetector:
    """Flags long, high-entropy, mixed-charset tokens that look like credential material."""

    __slots__ = ("_settings",)

    def __init__(self, settings: EntropySettings | None = None) -> None:
        self._settings = settings or EntropySettings()

    @property
    def name(self) -> str:
        return "entropy"

    def detect(self, text: str, context: DetectionContext) -> Iterable[DetectionSpan]:
        del context
        settings = self._settings
        spans: list[DetectionSpan] = []
        for match in _TOKEN_RE.finditer(text):
            token = match.group(0)
            if not self._is_candidate(token):
                continue
            is_hex = bool(_HEX_RE.match(token))
            required_length = settings.min_hex_length if is_hex else settings.min_length
            threshold = settings.hex_bits_per_char if is_hex else settings.bits_per_char
            if len(token) < required_length:
                continue
            if shannon_entropy(token) < threshold:
                continue
            spans.append(
                DetectionSpan(
                    start=match.start(),
                    end=match.end(),
                    rule_id=HIGH_ENTROPY_RULE_ID,
                    category=Category.SECRET,
                    severity=Severity.HIGH,
                    confidence=Confidence(settings.confidence),
                    detector=self.name,
                )
            )
        return spans

    @staticmethod
    def _is_candidate(token: str) -> bool:
        if _UUID_RE.match(token):
            return False
        if token.isdigit():
            # Epoch timestamps, counts and ports. Never credential material on their own.
            return False
        has_digit = any(character.isdigit() for character in token)
        has_alpha = any(character.isalpha() for character in token)
        return has_digit and has_alpha
