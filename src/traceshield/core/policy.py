"""Policy: what the engine does, expressed as data rather than control flow.

The rule pack decides what *can* be found; the policy decides what happens when it is. They
are versioned separately because a deployed policy outlives a package upgrade.

The bundled default policy is defined in Python rather than loaded from YAML or TOML. ADR
0001 requires the core to have no runtime dependencies, and the default policy is the part
most worth type-checking and reviewing as code.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from types import MappingProxyType

from traceshield.core.detectors.entropy import EntropySettings
from traceshield.core.detectors.keyname import KeyNameSettings
from traceshield.core.detectors.patterns import RULE_PACK_VERSION
from traceshield.core.errors import PolicyError
from traceshield.core.model import Action, Confidence, Handling, RuleId

POLICY_FORMAT_VERSION = "1"
DEFAULT_POLICY_VERSION = f"traceshield-default/{POLICY_FORMAT_VERSION}.{RULE_PACK_VERSION}"

CONTENT_BEARING_ATTRIBUTES: tuple[str, ...] = (
    # The eleven attributes the upstream GenAI registry annotates as possibly containing
    # sensitive information, plus three that are content-bearing in practice. See
    # docs/Research.md section 1; verified against the registry on 2026-09-06.
    "gen_ai.system_instructions",
    "gen_ai.input.messages",
    "gen_ai.output.messages",
    "gen_ai.tool.call.arguments",
    "gen_ai.tool.call.result",
    "gen_ai.tool.definitions",
    "gen_ai.tool.description",
    "gen_ai.retrieval.query.text",
    "gen_ai.memory.query.text",
    "gen_ai.memory.records",
    "gen_ai.prompt.variable",
    "gen_ai.retrieval.documents",
    "gen_ai.evaluation.explanation",
    "gen_ai.conversation.id",
)

STRUCTURED_ATTRIBUTES: frozenset[str] = frozenset(
    {
        # Attributes with a JSON Schema in the upstream registry, so their values are nested
        # documents rather than flat text.
        "gen_ai.system_instructions",
        "gen_ai.input.messages",
        "gen_ai.output.messages",
        "gen_ai.tool.call.arguments",
        "gen_ai.tool.call.result",
        "gen_ai.tool.definitions",
        "gen_ai.memory.records",
        "gen_ai.retrieval.documents",
    }
)

_KEEP_ATTRIBUTES: tuple[str, ...] = (
    # Enumerations, model names, identifiers and counts. Scanning them wastes time in the
    # export path and risks mangling values a backend groups by.
    "gen_ai.provider.name",
    "gen_ai.operation.name",
    "gen_ai.output.type",
    "gen_ai.token.type",
    "gen_ai.request.model",
    "gen_ai.response.model",
    "gen_ai.response.id",
    "gen_ai.response.status",
    "gen_ai.response.finish_reasons",
    "gen_ai.tool.name",
    "gen_ai.tool.type",
    "gen_ai.tool.call.id",
    "gen_ai.agent.id",
    "gen_ai.agent.name",
    "gen_ai.agent.version",
    "gen_ai.prompt.name",
    "gen_ai.prompt.version",
    "gen_ai.workflow.name",
    "gen_ai.data_source.id",
    "gen_ai.memory.store.id",
    "gen_ai.memory.record.id",
    "gen_ai.evaluation.name",
    "gen_ai.evaluation.score.label",
    "mcp.method.name",
    "mcp.protocol.version",
)

_OTHER_SCAN_ATTRIBUTES: tuple[str, ...] = (
    "gen_ai.agent.description",
    "mcp.resource.uri",
    "url.full",
    "db.query.text",
)


@dataclass(frozen=True, slots=True)
class AttributeRule:
    """How one attribute, or one attribute prefix, is handled before detection runs.

    A key ending in ``.`` is a prefix rule; the longest matching prefix wins.
    """

    key: str
    handling: Handling
    structured: bool = False

    def __post_init__(self) -> None:
        if not self.key:
            raise PolicyError("attribute rule key must not be empty")
        if self.structured and self.handling is not Handling.SCAN:
            raise PolicyError(
                f"attribute rule {self.key!r} marks a structured payload but does not scan it"
            )

    @property
    def is_prefix(self) -> bool:
        return self.key.endswith(".")


@dataclass(frozen=True, slots=True)
class ActionRule:
    """What to do about detections whose rule identifier starts with ``rule_prefix``.

    The longest matching prefix wins, and it wins outright: if its confidence threshold is
    not met the value is kept rather than falling through to a broader rule with a lower
    threshold. Predictability matters more here than recall, because an operator has to be
    able to read a policy and know what it will do.
    """

    rule_prefix: str
    action: Action
    min_confidence: Confidence
    keep_prefix: int = 0

    def __post_init__(self) -> None:
        if not self.rule_prefix:
            raise PolicyError("action rule prefix must not be empty")
        if self.keep_prefix < 0:
            raise PolicyError(f"action rule {self.rule_prefix!r} has a negative keep_prefix")
        if self.keep_prefix and self.action is not Action.PARTIAL:
            raise PolicyError(
                f"action rule {self.rule_prefix!r} sets keep_prefix but its action is not partial"
            )


@dataclass(frozen=True, slots=True)
class Budgets:
    """Hard limits that stop a hostile or pathological payload stalling the exporter.

    A breach is not an error the caller sees; it fails the value closed and records a
    finding. See docs/ThreatModel.md T4.
    """

    max_depth: int = 12
    max_nodes: int = 5_000
    max_string_bytes: int = 262_144

    def __post_init__(self) -> None:
        if self.max_depth < 1 or self.max_nodes < 1 or self.max_string_bytes < 1:
            raise PolicyError("every budget must be at least 1")


@dataclass(frozen=True, slots=True)
class Policy:
    """A complete, validated sanitization policy."""

    version: str
    exact_attributes: Mapping[str, AttributeRule]
    prefix_attributes: tuple[AttributeRule, ...]
    actions: tuple[ActionRule, ...]
    default_handling: Handling = Handling.SCAN
    default_action: Action = Action.MASK
    budgets: Budgets = field(default_factory=Budgets)
    entropy: EntropySettings = field(default_factory=EntropySettings)
    key_names: KeyNameSettings = field(default_factory=KeyNameSettings)

    @classmethod
    def build(
        cls,
        *,
        version: str,
        attributes: tuple[AttributeRule, ...],
        actions: tuple[ActionRule, ...],
        default_handling: Handling = Handling.SCAN,
        default_action: Action = Action.MASK,
        budgets: Budgets | None = None,
        entropy: EntropySettings | None = None,
        key_names: KeyNameSettings | None = None,
    ) -> Policy:
        """Validate and index a policy. The only supported way to construct one."""
        if not version:
            raise PolicyError("policy version must not be empty")
        exact: dict[str, AttributeRule] = {}
        prefixes: list[AttributeRule] = []
        for rule in attributes:
            if rule.is_prefix:
                prefixes.append(rule)
            elif rule.key in exact:
                raise PolicyError(f"duplicate attribute rule for {rule.key!r}")
            else:
                exact[rule.key] = rule
        prefix_keys = [rule.key for rule in prefixes]
        if len(set(prefix_keys)) != len(prefix_keys):
            raise PolicyError("duplicate attribute prefix rule")
        action_keys = [rule.rule_prefix for rule in actions]
        if len(set(action_keys)) != len(action_keys):
            raise PolicyError("duplicate action rule prefix")
        if default_action is Action.PARTIAL:
            raise PolicyError("default action cannot be partial: it has no keep_prefix")
        return cls(
            version=version,
            exact_attributes=MappingProxyType(exact),
            # Longest prefix first, so the first match is the most specific one.
            prefix_attributes=tuple(sorted(prefixes, key=lambda rule: -len(rule.key))),
            actions=tuple(sorted(actions, key=lambda rule: -len(rule.rule_prefix))),
            default_handling=default_handling,
            default_action=default_action,
            budgets=budgets or Budgets(),
            entropy=entropy or EntropySettings(),
            key_names=key_names or KeyNameSettings(),
        )

    def rule_for_attribute(self, key: str) -> AttributeRule:
        """Resolve how an attribute is handled: exact match, then longest prefix, then default."""
        exact = self.exact_attributes.get(key)
        if exact is not None:
            return exact
        for rule in self.prefix_attributes:
            if key.startswith(rule.key):
                return rule
        return AttributeRule(key=key, handling=self.default_handling)

    def action_for(self, rule_id: RuleId, confidence: Confidence) -> tuple[Action, int]:
        """Resolve the action for a detection, returning the action and its keep_prefix."""
        for rule in self.actions:
            if str(rule_id).startswith(rule.rule_prefix):
                if confidence < rule.min_confidence:
                    return Action.KEEP, 0
                return rule.action, rule.keep_prefix
        return self.default_action, 0

    @classmethod
    def default(cls) -> Policy:
        """The bundled policy.

        Fails closed: any attribute not named here is scanned, because an unknown attribute
        in LLM telemetry is more likely to be a new content field than a new counter.
        """
        attributes: list[AttributeRule] = [
            AttributeRule(key=key, handling=Handling.KEEP) for key in _KEEP_ATTRIBUTES
        ]
        attributes.append(AttributeRule(key="gen_ai.usage.", handling=Handling.KEEP))
        attributes.extend(
            AttributeRule(
                key=key,
                handling=Handling.SCAN,
                structured=key in STRUCTURED_ATTRIBUTES,
            )
            for key in CONTENT_BEARING_ATTRIBUTES
        )
        attributes.extend(
            AttributeRule(key=key, handling=Handling.SCAN) for key in _OTHER_SCAN_ATTRIBUTES
        )
        attributes.append(AttributeRule(key="gen_ai.prompt.variable.", handling=Handling.SCAN))
        attributes.append(AttributeRule(key="http.request.header.", handling=Handling.SCAN))

        actions = (
            ActionRule("secret.", Action.MASK, Confidence(0.6)),
            ActionRule("credential.", Action.MASK, Confidence(0.6)),
            # Hashed rather than masked so the same person can be correlated across traces
            # without the address being retained.
            ActionRule("pii.email", Action.HASH, Confidence(0.7)),
            ActionRule("pii.", Action.MASK, Confidence(0.7)),
            # Recognised and deliberately kept: addresses are usually what you are debugging.
            ActionRule("identifier.", Action.KEEP, Confidence(0.0)),
            # Budget breaches and detector failures remove the value they could not clear.
            ActionRule("policy.", Action.DROP, Confidence(0.0)),
            ActionRule("engine.", Action.DROP, Confidence(0.0)),
        )
        return cls.build(
            version=DEFAULT_POLICY_VERSION,
            attributes=tuple(attributes),
            actions=actions,
        )
