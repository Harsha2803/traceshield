from __future__ import annotations

import pytest

from traceshield import DetectionContext, EntropyDetector, EntropySettings
from traceshield.core.detectors.entropy import shannon_entropy

CONTEXT = DetectionContext(attribute_key="gen_ai.tool.call.result", path="", key_name="")

HIGH_ENTROPY_TOKEN = "aG9wZWZ1bGx5UmFuZG9tMDkzODQ3NTYyMzQ1Njc4"


def detects(text: str) -> bool:
    return bool(tuple(EntropyDetector().detect(text, CONTEXT)))


class TestShannonEntropy:
    def test_empty_string_is_zero(self) -> None:
        assert shannon_entropy("") == 0.0

    def test_uniform_string_is_zero(self) -> None:
        assert shannon_entropy("aaaaaaaa") == 0.0

    def test_more_variety_scores_higher(self) -> None:
        assert shannon_entropy("abcdefgh") > shannon_entropy("aabbccdd")


class TestEntropyDetector:
    def test_flags_a_long_mixed_token(self) -> None:
        assert detects(f"session token {HIGH_ENTROPY_TOKEN} issued")

    @pytest.mark.parametrize(
        "text",
        [
            # The exclusions matter more than the threshold: traces are full of these.
            "trace 3f2504e0-4f89-11d3-9a0c-0305e82c3301 completed",
            "issued at 17000000000000000000 epoch",
            "a normal English sentence about deploying the service",
            "short0token1",
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa1",
        ],
    )
    def test_does_not_flag_common_trace_content(self, text: str) -> None:
        assert not detects(text)

    def test_short_hex_is_not_flagged_but_long_hex_is(self) -> None:
        assert not detects("digest 0123456789abcdef0123456789abcdef checked")
        assert detects("digest 7f3a9c2e5b8d1046af52c39e7b06d84159e2c3fa checked")


class TestEntropySettings:
    def test_rejects_tiny_min_length(self) -> None:
        with pytest.raises(ValueError, match="min_length"):
            EntropySettings(min_length=4)

    def test_rejects_non_positive_bits_per_char(self) -> None:
        with pytest.raises(ValueError, match="positive"):
            EntropySettings(bits_per_char=0.0)

    def test_rejects_non_positive_hex_threshold(self) -> None:
        with pytest.raises(ValueError, match="positive"):
            EntropySettings(hex_bits_per_char=-1.0)

    def test_thresholds_are_tunable(self) -> None:
        strict = EntropyDetector(EntropySettings(min_length=200))
        assert not tuple(strict.detect(f"token {HIGH_ENTROPY_TOKEN}", CONTEXT))


class TestPathAndUrlExclusion:
    """Regression tests for a false positive found by running the detector over this
    repository's own handoff document: filesystem paths and URLs were reported as
    high-entropy secrets. Tool arguments are full of both."""

    @pytest.mark.parametrize(
        "text",
        [
            "reading /home/shreeharsha/Personal/Projects/Resume_001/traceshield now",
            "cloned from https://github.com/Harsha2803/traceshield.git ok",
            "wrote artifacts/build_2026/output_v3/report_final.json to disk",
            "GET https://api.example.com/v2/accounts/91827364/transactions",
            "module traceshield.core.detectors.entropy loaded",
        ],
    )
    def test_paths_and_urls_are_not_credentials(self, text: str) -> None:
        assert not detects(text)

    def test_a_real_base64_secret_is_still_caught(self) -> None:
        assert detects(f"authorization blob {HIGH_ENTROPY_TOKEN} attached")

    def test_padded_base64_survives_the_path_heuristic(self) -> None:
        # Padding is positive evidence, so slashes do not disqualify it.
        assert detects("blob aG9wZWZ1/Gx5UmFu/G9tMDkzODQ3NTYyMzQ1Njc4== attached")
