from __future__ import annotations

import pytest

from tests import fixtures
from traceshield.core.detectors.verifiers import iban_mod97, jwt_header_is_json, luhn, verhoeff


class TestLuhn:
    @pytest.mark.parametrize(
        "value",
        [fixtures.PAYMENT_CARD, "5555555555554444", "4111 1111 1111 1111", "4111-1111-1111-1111"],
    )
    def test_accepts_valid(self, value: str) -> None:
        assert luhn(value) is True

    @pytest.mark.parametrize("value", [fixtures.PAYMENT_CARD_BAD_CHECKSUM, "1234567890123"])
    def test_rejects_bad_checksum(self, value: str) -> None:
        assert luhn(value) is False

    @pytest.mark.parametrize("value", ["", "411111111111", "41111111111111111111"])
    def test_rejects_wrong_length(self, value: str) -> None:
        assert luhn(value) is False


class TestIbanMod97:
    @pytest.mark.parametrize(
        "value", [fixtures.IBAN, "DE89370400440532013000", "GB82 WEST 1234 5698 7654 32"]
    )
    def test_accepts_valid(self, value: str) -> None:
        assert iban_mod97(value) is True

    @pytest.mark.parametrize(
        "value",
        [
            fixtures.IBAN_BAD_CHECKSUM,
            "GBB2WEST12345698765432",
            "GB8XWEST12345698765432",
            "GB82",
            "GB82WEST_2345698765432",
        ],
    )
    def test_rejects_invalid(self, value: str) -> None:
        assert iban_mod97(value) is False


class TestVerhoeff:
    def test_accepts_valid(self) -> None:
        assert verhoeff(fixtures.AADHAAR) is True

    @pytest.mark.parametrize("value", [fixtures.AADHAAR_BAD_CHECKSUM, "234567890125"])
    def test_rejects_bad_checksum(self, value: str) -> None:
        assert verhoeff(value) is False

    @pytest.mark.parametrize("value", ["", "12345678901", "1234567890123"])
    def test_rejects_wrong_length(self, value: str) -> None:
        assert verhoeff(value) is False


class TestJwtHeader:
    def test_accepts_real_header(self) -> None:
        assert jwt_header_is_json(fixtures.JWT) is True

    @pytest.mark.parametrize(
        "value",
        [
            "eyJub3RiYXNlNjQh.abcdefgh.ijklmnop",
            # Valid base64 whose payload is a JSON array, not an object with alg.
            "WyJhIiwiYiJd.abcdefgh.ijklmnop",
            "notevenclose",
        ],
    )
    def test_rejects_non_headers(self, value: str) -> None:
        assert jwt_header_is_json(value) is False
