"""Checksum verifiers.

These are what separate a usable default policy from an alert-fatigue generator: a value
that matches a rule's shape but fails its checksum is not reported. ADR 0004 records why
this matters more than adding further patterns.

Deliberately absent: a GitHub token CRC32 verifier. GitHub documents the scheme as a
base62-encoded CRC32 in the trailing six characters, but not authoritatively enough to
determine which portion of the token it covers, and validating the guess would require a
real token. Shipping a verifier that silently rejects every genuine token would be worse
than shipping none, so GitHub tokens are matched on their unambiguous prefix and charset
instead.
"""

from __future__ import annotations

_VERHOEFF_D = (
    (0, 1, 2, 3, 4, 5, 6, 7, 8, 9),
    (1, 2, 3, 4, 0, 6, 7, 8, 9, 5),
    (2, 3, 4, 0, 1, 7, 8, 9, 5, 6),
    (3, 4, 0, 1, 2, 8, 9, 5, 6, 7),
    (4, 0, 1, 2, 3, 9, 5, 6, 7, 8),
    (5, 9, 8, 7, 6, 0, 4, 3, 2, 1),
    (6, 5, 9, 8, 7, 1, 0, 4, 3, 2),
    (7, 6, 5, 9, 8, 2, 1, 0, 4, 3),
    (8, 7, 6, 5, 9, 3, 2, 1, 0, 4),
    (9, 8, 7, 6, 5, 4, 3, 2, 1, 0),
)
_VERHOEFF_P = (
    (0, 1, 2, 3, 4, 5, 6, 7, 8, 9),
    (1, 5, 7, 6, 2, 8, 3, 0, 9, 4),
    (5, 8, 0, 3, 7, 9, 6, 1, 4, 2),
    (8, 9, 1, 6, 0, 4, 3, 5, 2, 7),
    (9, 4, 5, 3, 1, 2, 6, 8, 7, 0),
    (4, 2, 8, 6, 5, 7, 3, 9, 0, 1),
    (2, 7, 9, 3, 8, 0, 6, 4, 1, 5),
    (7, 0, 4, 6, 9, 1, 3, 2, 5, 8),
)


def _digits(value: str) -> str:
    return "".join(character for character in value if character.isdigit())


def luhn(value: str) -> bool:
    """Verify a payment card number with the Luhn algorithm (ISO/IEC 7812)."""
    digits = _digits(value)
    if not 13 <= len(digits) <= 19:
        return False
    total = 0
    for index, character in enumerate(reversed(digits)):
        digit = ord(character) - 48
        if index % 2 == 1:
            digit *= 2
            if digit > 9:
                digit -= 9
        total += digit
    return total % 10 == 0


def iban_mod97(value: str) -> bool:
    """Verify an IBAN check number with the ISO 13616 mod-97 rule."""
    compact = "".join(value.split()).upper()
    if not 15 <= len(compact) <= 34 or not compact[:2].isalpha() or not compact[2:4].isdigit():
        return False
    if not compact.isalnum():
        return False
    rearranged = compact[4:] + compact[:4]
    numeric = "".join(
        str(ord(character) - 55) if character.isalpha() else character for character in rearranged
    )
    return int(numeric) % 97 == 1


def verhoeff(value: str) -> bool:
    """Verify a number with the Verhoeff checksum, as used by Aadhaar."""
    digits = _digits(value)
    if len(digits) != 12:
        return False
    checksum = 0
    for index, character in enumerate(reversed(digits)):
        checksum = _VERHOEFF_D[checksum][_VERHOEFF_P[index % 8][ord(character) - 48]]
    return checksum == 0


def jwt_header_is_json(value: str) -> bool:
    """Verify that a JWT-shaped string has a header that base64url-decodes to a JSON object
    carrying an ``alg`` claim.

    Three dot-separated base64url segments is a common enough shape that the pattern alone
    produces false positives; decoding the header removes almost all of them.
    """
    import base64
    import json

    header = value.split(".", 1)[0]
    padding = "=" * (-len(header) % 4)
    try:
        decoded = base64.urlsafe_b64decode(header + padding)
        parsed = json.loads(decoded)
    except (ValueError, UnicodeDecodeError):
        return False
    return isinstance(parsed, dict) and "alg" in parsed
