"""Shared fixtures.

Every credential-shaped value in this suite is synthetic. Where a rule has a checksum, the
fixture is constructed to satisfy it, so the tests exercise the verifier rather than only
the pattern. No real credential and no real person's identifier belongs in this repository
(AGENTS.md rule 3).
"""

from __future__ import annotations

import pytest

from traceshield import Policy, Sanitizer, ValueHasher

TEST_SALT = "traceshield-test-salt-not-a-secret"


@pytest.fixture
def hasher() -> ValueHasher:
    return ValueHasher.from_secret(TEST_SALT)


@pytest.fixture
def policy() -> Policy:
    return Policy.default()


@pytest.fixture
def sanitizer(policy: Policy, hasher: ValueHasher) -> Sanitizer:
    return Sanitizer(policy=policy, hasher=hasher)
