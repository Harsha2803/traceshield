"""Salted hashing of removed values.

The salt is supplied by the caller and never generated, defaulted or persisted here. A
digest is a correlation identifier, not a confidentiality guarantee: an attacker holding the
salt can brute-force a low-entropy value offline. That trade-off is stated in
docs/ThreatModel.md T5.
"""

from __future__ import annotations

import hashlib
import hmac

_DIGEST_CHARS = 16
"""Truncation length. 64 bits of digest is ample to correlate occurrences and short enough
to stay readable inside a placeholder."""


class ValueHasher:
    """Produces a stable, salted digest for a removed value.

    Constructor-injected into the engine rather than constructed inside it, because the salt
    is a secret whose lifecycle belongs to the composition root.
    """

    __slots__ = ("_salt",)

    def __init__(self, salt: bytes) -> None:
        if len(salt) < 16:
            raise ValueError("hash salt must be at least 16 bytes")
        self._salt = salt

    @classmethod
    def from_secret(cls, secret: str) -> ValueHasher:
        """Build a hasher from a secret string, for example one read from the environment."""
        encoded = secret.encode("utf-8")
        if len(encoded) < 16:
            raise ValueError("hash secret must be at least 16 bytes when UTF-8 encoded")
        return cls(encoded)

    def digest(self, value: str) -> str:
        """Return a truncated hex digest of ``value``.

        The value is never stored, logged or included in an exception; it exists only for
        the duration of this call.
        """
        mac = hmac.new(self._salt, value.encode("utf-8", errors="replace"), hashlib.sha256)
        return mac.hexdigest()[:_DIGEST_CHARS]

    def __repr__(self) -> str:
        # Never render the salt.
        return "ValueHasher(salt=<redacted>)"
