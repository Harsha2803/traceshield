from __future__ import annotations

import pytest

from traceshield import ValueHasher

SALT = "traceshield-test-salt-not-a-secret"


class TestValueHasher:
    def test_is_deterministic_for_the_same_salt(self) -> None:
        assert ValueHasher.from_secret(SALT).digest("v") == ValueHasher.from_secret(SALT).digest(
            "v"
        )

    def test_differs_across_salts(self) -> None:
        other = ValueHasher.from_secret("a-completely-different-salt-value")
        assert ValueHasher.from_secret(SALT).digest("v") != other.digest("v")

    def test_digest_is_short_hex(self) -> None:
        digest = ValueHasher.from_secret(SALT).digest("value")
        assert len(digest) == 16
        assert all(character in "0123456789abcdef" for character in digest)

    @pytest.mark.parametrize("salt", [b"", b"tooshort"])
    def test_rejects_weak_salt(self, salt: bytes) -> None:
        with pytest.raises(ValueError, match="at least 16 bytes"):
            ValueHasher(salt)

    def test_rejects_short_secret(self) -> None:
        with pytest.raises(ValueError, match="at least 16 bytes"):
            ValueHasher.from_secret("short")

    def test_handles_undecodable_input(self) -> None:
        # Surrogates reach the hasher from lossily decoded byte attributes.
        assert ValueHasher.from_secret(SALT).digest("bad \udcff value")

    def test_repr_never_shows_the_salt(self) -> None:
        assert "redacted" in repr(ValueHasher.from_secret(SALT))
        assert SALT not in repr(ValueHasher.from_secret(SALT))
