from __future__ import annotations

import pytest

from traceshield import DetectionContext, KeyNameDetector, KeyNameSettings


def detect(key_name: str, value: str = "opaque-value-1234") -> tuple[object, ...]:
    context = DetectionContext(
        attribute_key="gen_ai.tool.call.arguments", path=f"/{key_name}", key_name=key_name
    )
    return tuple(KeyNameDetector().detect(value, context))


class TestKeyNameDetector:
    @pytest.mark.parametrize(
        "key",
        [
            "api_key",
            "apiKey",
            "api-key",
            "password",
            "passwd",
            "access_token",
            "refresh_token",
            "client_secret",
            "authorization",
            "private_key",
            "session_id",
            "db_credentials",
            "otp",
        ],
    )
    def test_escalates_sensitive_keys(self, key: str) -> None:
        assert len(detect(key)) == 1

    @pytest.mark.parametrize(
        "key",
        [
            # Names about a secret rather than the secret. Redacting these costs
            # debuggability and buys nothing.
            "token_count",
            "auth_type",
            "key_name",
            "password_required",
            "token_expires_at",
            "secret_version",
            "signature_algorithm",
        ],
    )
    def test_ignores_metadata_keys(self, key: str) -> None:
        assert detect(key) == ()

    @pytest.mark.parametrize("key", ["city", "model", "temperature", "user_query", ""])
    def test_ignores_unrelated_keys(self, key: str) -> None:
        assert detect(key) == ()

    def test_ignores_short_values(self) -> None:
        assert detect("api_key", value="none") == ()

    def test_covers_the_whole_value(self) -> None:
        value = "opaque-value-1234"
        span = detect("api_key", value)[0]
        assert (span.start, span.end) == (0, len(value))  # type: ignore[attr-defined]

    def test_min_value_length_is_validated(self) -> None:
        with pytest.raises(ValueError, match="positive"):
            KeyNameSettings(min_value_length=0)
