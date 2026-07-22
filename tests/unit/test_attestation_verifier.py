"""Unit tests for the attestation token verifier module."""

import os
import time

import jwt
import pytest

from attestation_verifier import AuthorizationError, verify_token


SIGNING_SECRET = os.environ.get(  # nosec B105 - test-only secret
    "TEST_SIGNING_SECRET", "test-signing-secret-key-for-unit-tests"
)


def _mint_valid_token(
    signing_secret=SIGNING_SECRET,
    iss="attestation-exchange",
    device_integrity="verified",
    app_integrity="verified",
    ttl_seconds=600,
    sub="user-123",
):
    """Helper to mint a token with configurable claims."""
    iat = int(time.time())
    claims = {
        "iss": iss,
        "sub": sub,
        "iat": iat,
        "exp": iat + ttl_seconds,
        "device_integrity": device_integrity,
        "app_integrity": app_integrity,
        "platform": "android",
    }
    return jwt.encode(  # nosemgrep: python.jwt.security.jwt-python-hardcoded-secret
        claims, signing_secret, algorithm="HS256"
    )


class TestVerifyTokenValid:
    """Tests for successful token verification."""

    def test_valid_token_returns_claims(self):
        token = _mint_valid_token()
        claims = verify_token(token, SIGNING_SECRET)

        assert claims["iss"] == "attestation-exchange"
        assert claims["sub"] == "user-123"
        assert claims["device_integrity"] == "verified"
        assert claims["app_integrity"] == "verified"
        assert claims["platform"] == "android"
        assert "exp" in claims
        assert "iat" in claims


class TestVerifyTokenSignature:
    """Tests for signature verification (Requirement 6.1)."""

    def test_wrong_secret_raises_error(self):
        token = _mint_valid_token(signing_secret="correct-secret")  # nosec B105

        with pytest.raises(AuthorizationError, match="invalid signature"):
            verify_token(token, "wrong-secret")

    def test_malformed_token_raises_error(self):
        with pytest.raises(AuthorizationError):
            verify_token("not-a-jwt-token", SIGNING_SECRET)


class TestVerifyTokenIssuer:
    """Tests for issuer claim validation (Requirement 6.2)."""

    def test_wrong_issuer_raises_error(self):
        token = _mint_valid_token(iss="wrong-issuer")

        with pytest.raises(AuthorizationError, match="Invalid issuer"):
            verify_token(token, SIGNING_SECRET)

    def test_missing_issuer_raises_error(self):
        iat = int(time.time())
        claims = {
            "sub": "user-123",
            "iat": iat,
            "exp": iat + 600,
            "device_integrity": "verified",
            "app_integrity": "verified",
        }
        token = jwt.encode(claims, SIGNING_SECRET, algorithm="HS256")

        with pytest.raises(AuthorizationError):
            verify_token(token, SIGNING_SECRET)


class TestVerifyTokenExpiry:
    """Tests for expiry validation (Requirement 6.3)."""

    def test_expired_token_raises_error(self):
        token = _mint_valid_token(ttl_seconds=-60)

        with pytest.raises(AuthorizationError, match="expired"):
            verify_token(token, SIGNING_SECRET)


class TestVerifyTokenIntegrityClaims:
    """Tests for integrity claim validation (Requirement 6.4)."""

    def test_invalid_device_integrity_raises_error(self):
        token = _mint_valid_token(device_integrity="unverified")

        with pytest.raises(AuthorizationError, match="device_integrity"):
            verify_token(token, SIGNING_SECRET)

    def test_invalid_app_integrity_raises_error(self):
        token = _mint_valid_token(app_integrity="unverified")

        with pytest.raises(AuthorizationError, match="app_integrity"):
            verify_token(token, SIGNING_SECRET)

    def test_missing_device_integrity_raises_error(self):
        iat = int(time.time())
        claims = {
            "iss": "attestation-exchange",
            "sub": "user-123",
            "iat": iat,
            "exp": iat + 600,
            "app_integrity": "verified",
        }
        token = jwt.encode(claims, SIGNING_SECRET, algorithm="HS256")

        with pytest.raises(AuthorizationError, match="device_integrity"):
            verify_token(token, SIGNING_SECRET)

    def test_missing_app_integrity_raises_error(self):
        iat = int(time.time())
        claims = {
            "iss": "attestation-exchange",
            "sub": "user-123",
            "iat": iat,
            "exp": iat + 600,
            "device_integrity": "verified",
        }
        token = jwt.encode(claims, SIGNING_SECRET, algorithm="HS256")

        with pytest.raises(AuthorizationError, match="app_integrity"):
            verify_token(token, SIGNING_SECRET)
