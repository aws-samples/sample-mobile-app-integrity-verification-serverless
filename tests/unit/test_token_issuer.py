"""Unit tests for the token issuer module.

Validates Requirements 11.1, 11.4 - JWT minting correctness, TTL accuracy,
claim completeness, and signing verification.
"""

import jwt
import pytest

from attestation_exchange.token_issuer import mint_attestation_jwt


SIGNING_SECRET = "test-signing-secret-key-for-unit-tests"
USER_SUB = "a1b2c3d4-e5f6-7890-abcd-ef1234567890"


class TestMintAttestationJWTClaims:
    """Test minting a JWT with known inputs produces a token with all required claims."""

    def test_token_contains_all_required_claims(self):
        token = mint_attestation_jwt(USER_SUB, SIGNING_SECRET, ttl_minutes=10)
        decoded = jwt.decode(token, SIGNING_SECRET, algorithms=["HS256"])

        assert "iss" in decoded
        assert "sub" in decoded
        assert "iat" in decoded
        assert "exp" in decoded
        assert "device_integrity" in decoded
        assert "app_integrity" in decoded
        assert "platform" in decoded

    def test_iss_claim_is_attestation_exchange(self):
        token = mint_attestation_jwt(USER_SUB, SIGNING_SECRET, ttl_minutes=10)
        decoded = jwt.decode(token, SIGNING_SECRET, algorithms=["HS256"])

        assert decoded["iss"] == "attestation-exchange"

    def test_sub_claim_matches_input(self):
        token = mint_attestation_jwt(USER_SUB, SIGNING_SECRET, ttl_minutes=10)
        decoded = jwt.decode(token, SIGNING_SECRET, algorithms=["HS256"])

        assert decoded["sub"] == USER_SUB

    def test_device_integrity_is_verified(self):
        token = mint_attestation_jwt(USER_SUB, SIGNING_SECRET, ttl_minutes=10)
        decoded = jwt.decode(token, SIGNING_SECRET, algorithms=["HS256"])

        assert decoded["device_integrity"] == "verified"

    def test_app_integrity_is_verified(self):
        token = mint_attestation_jwt(USER_SUB, SIGNING_SECRET, ttl_minutes=10)
        decoded = jwt.decode(token, SIGNING_SECRET, algorithms=["HS256"])

        assert decoded["app_integrity"] == "verified"

    def test_platform_is_android(self):
        token = mint_attestation_jwt(USER_SUB, SIGNING_SECRET, ttl_minutes=10)
        decoded = jwt.decode(token, SIGNING_SECRET, algorithms=["HS256"])

        assert decoded["platform"] == "android"


class TestMintAttestationJWTExpiry:
    """Test exp - iat equals ttl_minutes * 60 for various TTL values."""

    @pytest.mark.parametrize("ttl_minutes", [5, 10, 15])
    def test_exp_minus_iat_equals_ttl_seconds(self, ttl_minutes):
        token = mint_attestation_jwt(USER_SUB, SIGNING_SECRET, ttl_minutes=ttl_minutes)
        decoded = jwt.decode(token, SIGNING_SECRET, algorithms=["HS256"])

        expected_ttl_seconds = ttl_minutes * 60
        assert decoded["exp"] - decoded["iat"] == expected_ttl_seconds


class TestMintAttestationJWTVerification:
    """Test token is verifiable with the same signing secret."""

    def test_token_verifiable_with_same_secret(self):
        token = mint_attestation_jwt(USER_SUB, SIGNING_SECRET, ttl_minutes=10)

        # Should not raise
        decoded = jwt.decode(token, SIGNING_SECRET, algorithms=["HS256"])
        assert decoded["sub"] == USER_SUB

    def test_token_not_verifiable_with_different_secret(self):
        token = mint_attestation_jwt(USER_SUB, SIGNING_SECRET, ttl_minutes=10)

        with pytest.raises(jwt.InvalidSignatureError):
            jwt.decode(token, "a-completely-different-secret", algorithms=["HS256"])


class TestMintAttestationJWTTTLValidation:
    """Test TTL values outside [5, 15] raise ValueError."""

    @pytest.mark.parametrize("invalid_ttl", [4, 16, 0, -1, 100])
    def test_invalid_ttl_raises_value_error(self, invalid_ttl):
        with pytest.raises(ValueError):
            mint_attestation_jwt(USER_SUB, SIGNING_SECRET, ttl_minutes=invalid_ttl)

    def test_ttl_boundary_lower_accepted(self):
        # TTL=5 is the lower boundary and should be accepted
        token = mint_attestation_jwt(USER_SUB, SIGNING_SECRET, ttl_minutes=5)
        decoded = jwt.decode(token, SIGNING_SECRET, algorithms=["HS256"])
        assert decoded["exp"] - decoded["iat"] == 300

    def test_ttl_boundary_upper_accepted(self):
        # TTL=15 is the upper boundary and should be accepted
        token = mint_attestation_jwt(USER_SUB, SIGNING_SECRET, ttl_minutes=15)
        decoded = jwt.decode(token, SIGNING_SECRET, algorithms=["HS256"])
        assert decoded["exp"] - decoded["iat"] == 900
