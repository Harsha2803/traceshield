"""Synthetic sensitive values used across the suite.

AKIAIOSFODNN7EXAMPLE is AWS's own published example key. The rest are invented; the
checksum-bearing ones were constructed to pass their verifier.
"""

from __future__ import annotations

AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"
GITHUB_TOKEN = "ghp_0Sx9synthetic1token2value3for4tests56"
GITHUB_FINE_GRAINED = "github_pat_11ABCDEFG0synthetic1value2for3tests"
SLACK_TOKEN = "xoxb-000000000000-000000000000-syntheticSlackValue"
GOOGLE_API_KEY = "AIzaSy0synthetic1google2api3key4value56"
ANTHROPIC_API_KEY = "sk-ant-api03-synthetic-value-for-tests-only-0123"
OPENAI_API_KEY = "sk-proj-synthetic0value1for2tests3only4"
STRIPE_API_KEY = "sk_live_0synthetic1stripe2key3value"
JWT = (
    "eyJhbGciOiAiSFMyNTYiLCAidHlwIjogIkpXVCJ9"
    ".eyJzdWIiOiAic3ludGhldGljIiwgImlhdCI6IDE3MDAwMDAwMDB9"
    ".c3ludGhldGljLXNpZ25hdHVyZS12YWx1ZQ"
)
PRIVATE_KEY = (
    "-----BEGIN RSA PRIVATE KEY-----\n"
    "c3ludGhldGljLWtleS1tYXRlcmlhbC1ub3QtYS1yZWFsLWtleQ==\n"
    "-----END RSA PRIVATE KEY-----"
)

EMAIL = "casey.synthetic@example.com"
# Luhn-valid test card numbers that no issuer has assigned.
PAYMENT_CARD = "4111111111111111"
PAYMENT_CARD_BAD_CHECKSUM = "4111111111111112"
IBAN = "GB82WEST12345698765432"
IBAN_BAD_CHECKSUM = "GB82WEST12345698765433"
US_SSN = "123-45-6789"
# Verhoeff-valid, constructed for these tests.
AADHAAR = "234567890124"
AADHAAR_BAD_CHECKSUM = "234567890123"
INDIA_PAN = "ABCDE1234F"
PHONE_E164 = "+14155550123"
IPV4 = "192.0.2.44"
