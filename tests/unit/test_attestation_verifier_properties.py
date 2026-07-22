"""Property-based tests for the attestation token verifier module.

**Validates: Requirements 6.1, 6.2, 6.3, 6.4**

Property 6: Attestation Verifier Rejects Invalid Tokens
For any JWT string that is either signed with a different secret, has an expired
exp claim, has iss not equal to "attestation-exchange", or has
device_integrity/app_integrity not equal to "verified", the Attestation_Verifier
SHALL raise an AuthorizationError.
"""

import time

import jwt
import pytest
from hypothesis import given, settings, assume
from hypothesis import strategies as st

from attestation_verifier import AuthorizationError, verify_token


# Strategy for generating non-empty text strings suitable for secrets/identifiers
non_empty_text = st.text(
    alphabet=st.characters(whitelist_categories=("L", "N", "P", "S")),
    min_size=1,
    max_size=64,
)

# Strategy for generating signing secrets
signing_secrets = st.text(
    alphabet=st.characters(whitelist_categories=("L", "N")),
    min_size=8,
    max_size=64,
)


def _mint_valid_claims(
    iss="attestation-exchange",
    device_integrity="verified",
    app_integrity="verified",
    ttl_seconds=600,
    sub="test-user",
):
    """Helper to produce a valid claim set."""
    iat = int(time.time())
    return {
        "iss": iss,
        "sub": sub,
        "iat": iat,
        "exp": iat + ttl_seconds,
        "device_integrity": device_integrity,
        "app_integrity": app_integrity,
        "platform": "android",
    }


class TestProperty6WrongSecret:
    """Requirement 6.1: Verifying with a different secret raises AuthorizationError."""

    @given(
        correct_secret=signing_secrets,
        wrong_secret=signing_secrets,
    )
    @settings(max_examples=50)
    def test_wrong_secret_always_rejected(self, correct_secret, wrong_secret):
        """**Validates: Requirements 6.1**

        For any JWT signed with one secret and verified with a different secret,
        AuthorizationError SHALL be raised.
        """
        assume(correct_secret != wrong_secret)

        claims = _mint_valid_claims()
        token = jwt.encode(claims, correct_secret, algorithm="HS256")

        with pytest.raises(AuthorizationError):
            verify_token(token, wrong_secret)


class TestProperty6WrongIssuer:
    """Requirement 6.2: Tokens with iss != 'attestation-exchange' raise AuthorizationError."""

    @given(
        wrong_iss=st.text(min_size=1, max_size=50).filter(
            lambda x: x != "attestation-exchange"
        ),
        secret=signing_secrets,
    )
    @settings(max_examples=50)
    def test_wrong_issuer_always_rejected(self, wrong_iss, secret):
        """**Validates: Requirements 6.2**

        For any JWT with iss not equal to 'attestation-exchange',
        AuthorizationError SHALL be raised.
        """
        claims = _mint_valid_claims(iss=wrong_iss)
        token = jwt.encode(claims, secret, algorithm="HS256")

        with pytest.raises(AuthorizationError):
            verify_token(token, secret)


class TestProperty6ExpiredToken:
    """Requirement 6.3: Expired tokens raise AuthorizationError."""

    @given(
        seconds_expired=st.integers(min_value=1, max_value=86400),
        secret=signing_secrets,
    )
    @settings(max_examples=50)
    def test_expired_token_always_rejected(self, seconds_expired, secret):
        """**Validates: Requirements 6.3**

        For any JWT whose exp claim is in the past,
        AuthorizationError SHALL be raised.
        """
        claims = _mint_valid_claims(ttl_seconds=-seconds_expired)
        token = jwt.encode(claims, secret, algorithm="HS256")

        with pytest.raises(AuthorizationError):
            verify_token(token, secret)


class TestProperty6InvalidIntegrityClaims:
    """Requirement 6.4: Invalid device_integrity or app_integrity raises AuthorizationError."""

    @given(
        bad_device_integrity=st.text(min_size=0, max_size=30).filter(
            lambda x: x != "verified"
        ),
        secret=signing_secrets,
    )
    @settings(max_examples=50)
    def test_invalid_device_integrity_always_rejected(
        self, bad_device_integrity, secret
    ):
        """**Validates: Requirements 6.4**

        For any JWT with device_integrity not equal to 'verified',
        AuthorizationError SHALL be raised.
        """
        claims = _mint_valid_claims(device_integrity=bad_device_integrity)
        token = jwt.encode(claims, secret, algorithm="HS256")

        with pytest.raises(AuthorizationError):
            verify_token(token, secret)

    @given(
        bad_app_integrity=st.text(min_size=0, max_size=30).filter(
            lambda x: x != "verified"
        ),
        secret=signing_secrets,
    )
    @settings(max_examples=50)
    def test_invalid_app_integrity_always_rejected(self, bad_app_integrity, secret):
        """**Validates: Requirements 6.4**

        For any JWT with app_integrity not equal to 'verified',
        AuthorizationError SHALL be raised.
        """
        claims = _mint_valid_claims(app_integrity=bad_app_integrity)
        token = jwt.encode(claims, secret, algorithm="HS256")

        with pytest.raises(AuthorizationError):
            verify_token(token, secret)
