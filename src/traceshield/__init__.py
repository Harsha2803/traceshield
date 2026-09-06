"""TraceShield: sanitize LLM and agent telemetry before it reaches an observability platform.

Detects and redacts secrets, PII and sensitive tool arguments while preserving trace
structure, and records an auditable decision for every redaction.

    from traceshield import Policy, Sanitizer, ValueHasher

    sanitizer = Sanitizer(
        policy=Policy.default(),
        hasher=ValueHasher.from_secret(os.environ["TRACESHIELD_HASH_SECRET"]),
    )
    result = sanitizer.sanitize_attribute("gen_ai.tool.call.arguments", payload)

The salt is required rather than defaulted: a generated salt would make findings
uncorrelatable between processes, and a hard-coded one would make the digests worthless.
"""

from importlib.metadata import PackageNotFoundError, version

from traceshield.core.detectors import (
    DEFAULT_RULES,
    RULE_PACK_VERSION,
    DetectionContext,
    Detector,
    EntropyDetector,
    EntropySettings,
    KeyNameDetector,
    KeyNameSettings,
    PatternDetector,
    PatternRule,
)
from traceshield.core.engine import Sanitizer
from traceshield.core.errors import BudgetExceededError, PolicyError, TraceShieldError
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
from traceshield.core.policy import (
    CONTENT_BEARING_ATTRIBUTES,
    ActionRule,
    AttributeRule,
    Budgets,
    Policy,
)

try:
    __version__ = version("traceshield")
except PackageNotFoundError:  # pragma: no cover - only hit in an uninstalled source tree
    __version__ = "0.0.0.dev0"

__all__ = [
    "CONTENT_BEARING_ATTRIBUTES",
    "DEFAULT_RULES",
    "RULE_PACK_VERSION",
    "Action",
    "ActionRule",
    "AttributeRule",
    "BudgetExceededError",
    "Budgets",
    "Category",
    "Confidence",
    "DetectionContext",
    "DetectionSpan",
    "Detector",
    "EntropyDetector",
    "EntropySettings",
    "Finding",
    "Handling",
    "KeyNameDetector",
    "KeyNameSettings",
    "PatternDetector",
    "PatternRule",
    "Policy",
    "PolicyError",
    "RuleId",
    "SanitizedAttributes",
    "SanitizedValue",
    "Sanitizer",
    "Severity",
    "TraceShieldError",
    "ValueHash",
    "ValueHasher",
    "__version__",
]
