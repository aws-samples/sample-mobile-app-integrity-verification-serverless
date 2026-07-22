"""Property-based tests for the Token Issuer module using Hypothesis.

These tests validate universal properties of the attestation JWT minting
across randomly generated inputs.
"""

import pytest
import jwt
from hypothesis import given, settings
from hypothesis import strategies as st

from token_issuer import mint_attestation_jwt


# Strategy for generating non-empty user_sub strings
user_sub_strategy = st.text(
    alphabet=st.characters(categories=("L", "N", "P", "S")),
    min_size=1,
    max_size=128,
)

# Strategy for generating non-empty signing secrets
signing_secret_strategy = st.text(
    alphabet=st.characters(categories=("L", "N", "P")),
    min_size=1,
    max_size=256,
)

# Strategy for generating valid ttl_minutes in [5, 15]
ttl_minutes_strategy = st.integers(min_value=5, max_value=15)


class TestAttestationJWTRoundTripConsistency:
    """Property 1: Attestation JWT Round-Trip Consistency.

    For any valid user_sub (non-empty string), signing_secret (non-empty string),
    and ttl_minutes (integer in [5, 15]), minting an attestation JWT and then
    decoding it with the same signing_secret SHALL produce claims where:
    - sub equals user_sub
    - iss equals "attestation-exchange"
    - exp minus iat equals ttl_minutes * 60
    - device_integrity equals "verified"
    - app_integrity equals "verified"
    - platform equals "android"

    **Validates: Requirements 1.1, 1.2, 1.3, 1.5**
    """

    @given(
        user_sub=user_sub_strategy,
        signing_secret=signing_secret_strategy,
        ttl_minutes=ttl_minutes_strategy,
    )
    @settings(max_examples=100)
    def test_sub_claim_equals_user_sub(self, user_sub, signing_secret, ttl_minutes):
        """Decoded JWT sub claim equals original user_sub input."""
        token = mint_attestation_jwt(user_sub, signing_secret, ttl_minutes)
        decoded = jwt.decode(token, signing_secret, algorithms=["HS256"])
        assert decoded["sub"] == user_sub

    @given(
        user_sub=user_sub_strategy,
        signing_secret=signing_secret_strategy,
        ttl_minutes=ttl_minutes_strategy,
    )
    @settings(max_examples=100)
    def test_iss_claim_equals_attestation_exchange(self, user_sub, signing_secret, ttl_minutes):
        """Decoded JWT iss claim equals 'attestation-exchange'."""
        token = mint_attestation_jwt(user_sub, signing_secret, ttl_minutes)
        decoded = jwt.decode(token, signing_secret, algorithms=["HS256"])
        assert decoded["iss"] == "attestation-exchange"

    @given(
        user_sub=user_sub_strategy,
        signing_secret=signing_secret_strategy,
        ttl_minutes=ttl_minutes_strategy,
    )
    @settings(max_examples=100)
    def test_exp_minus_iat_equals_ttl_seconds(self, user_sub, signing_secret, ttl_minutes):
        """Decoded JWT exp - iat equals ttl_minutes * 60."""
        token = mint_attestation_jwt(user_sub, signing_secret, ttl_minutes)
        decoded = jwt.decode(token, signing_secret, algorithms=["HS256"])
        assert decoded["exp"] - decoded["iat"] == ttl_minutes * 60

    @given(
        user_sub=user_sub_strategy,
        signing_secret=signing_secret_strategy,
        ttl_minutes=ttl_minutes_strategy,
    )
    @settings(max_examples=100)
    def test_integrity_claims_are_correct(self, user_sub, signing_secret, ttl_minutes):
        """Decoded JWT has device_integrity='verified', app_integrity='verified', platform='android'."""
        token = mint_attestation_jwt(user_sub, signing_secret, ttl_minutes)
        decoded = jwt.decode(token, signing_secret, algorithms=["HS256"])
        assert decoded["device_integrity"] == "verified"
        assert decoded["app_integrity"] == "verified"
        assert decoded["platform"] == "android"

    @given(
        user_sub=user_sub_strategy,
        signing_secret=signing_secret_strategy,
        ttl_minutes=ttl_minutes_strategy,
    )
    @settings(max_examples=100)
    def test_all_required_claims_present(self, user_sub, signing_secret, ttl_minutes):
        """Decoded JWT contains all required claims: iss, sub, iat, exp, device_integrity, app_integrity, platform."""
        token = mint_attestation_jwt(user_sub, signing_secret, ttl_minutes)
        decoded = jwt.decode(token, signing_secret, algorithms=["HS256"])
        required_claims = {"iss", "sub", "iat", "exp", "device_integrity", "app_integrity", "platform"}
        assert required_claims.issubset(decoded.keys())


class TestTTLBoundsEnforcement:
    """Property 2: TTL Bounds Enforcement.

    For any integer ttl_minutes outside the range [5, 15], the Token_Issuer
    SHALL reject the request. For any integer ttl_minutes within [5, 15],
    the Token_Issuer SHALL successfully produce a JWT.

    **Validates: Requirement 1.4**
    """

    @given(
        ttl_minutes=st.integers().filter(lambda x: x < 5 or x > 15),
    )
    @settings(max_examples=100)
    def test_rejects_ttl_outside_valid_range(self, ttl_minutes):
        """Token_Issuer raises ValueError for any ttl_minutes outside [5, 15]."""
        with pytest.raises(ValueError):
            mint_attestation_jwt("test-user-sub", "test-signing-secret", ttl_minutes)

    @given(
        ttl_minutes=st.integers(min_value=5, max_value=15),
    )
    @settings(max_examples=100)
    def test_accepts_ttl_within_valid_range(self, ttl_minutes):
        """Token_Issuer successfully produces a JWT for any ttl_minutes in [5, 15]."""
        token = mint_attestation_jwt("test-user-sub", "test-signing-secret", ttl_minutes)
        assert isinstance(token, str)
        assert len(token) > 0
        # Verify it's a valid JWT that can be decoded
        decoded = jwt.decode(token, "test-signing-secret", algorithms=["HS256"])
        assert "exp" in decoded
        assert "iat" in decoded
