"""Unit tests for the Cognito access token verifier module."""

import time
from unittest.mock import patch, MagicMock

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
from jwt.algorithms import RSAAlgorithm

from cognito_verifier import AuthorizationError, verify_token, _jwks_cache


# Generate an RSA key pair for testing
_private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
    backend=default_backend(),
)
_public_key = _private_key.public_key()

# Convert public key to JWK format for the mock JWKS endpoint
_public_jwk = RSAAlgorithm.to_jwk(_public_key, as_dict=True)
_public_jwk["kid"] = "test-kid-001"
_public_jwk["alg"] = "RS256"
_public_jwk["use"] = "sig"

USER_POOL_ID = "us-east-1_TestPool"
APP_CLIENT_ID = "test-app-client-id"
REGION = "us-east-1"
ISSUER_URL = f"https://cognito-idp.{REGION}.amazonaws.com/{USER_POOL_ID}"


def _mint_cognito_token(
    kid="test-kid-001",
    token_use="access",
    client_id=APP_CLIENT_ID,
    iss=ISSUER_URL,
    sub="user-abc-123",
    ttl_seconds=3600,
):
    """Helper to mint a test Cognito-like RS256 JWT."""
    iat = int(time.time())
    claims = {
        "sub": sub,
        "iss": iss,
        "token_use": token_use,
        "client_id": client_id,
        "iat": iat,
        "exp": iat + ttl_seconds,
    }
    headers = {"kid": kid, "alg": "RS256"}
    return jwt.encode(claims, _private_key, algorithm="RS256", headers=headers)


@pytest.fixture(autouse=True)
def clear_jwks_cache():
    """Clear JWKS cache before each test."""
    _jwks_cache.clear()
    yield
    _jwks_cache.clear()


@pytest.fixture
def mock_jwks_response():
    """Mock the JWKS endpoint response."""
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = {"keys": [_public_jwk]}
    mock_response.raise_for_status = MagicMock()
    return mock_response


class TestVerifyTokenValid:
    """Tests for successful token verification (Requirement 5.1)."""

    def test_valid_token_returns_claims(self, mock_jwks_response):
        token = _mint_cognito_token()

        with patch("cognito_verifier.requests.get", return_value=mock_jwks_response):
            claims = verify_token(token, USER_POOL_ID, APP_CLIENT_ID, REGION)

        assert claims["sub"] == "user-abc-123"
        assert claims["token_use"] == "access"
        assert claims["client_id"] == APP_CLIENT_ID
        assert claims["iss"] == ISSUER_URL

    def test_valid_token_has_required_fields(self, mock_jwks_response):
        token = _mint_cognito_token()

        with patch("cognito_verifier.requests.get", return_value=mock_jwks_response):
            claims = verify_token(token, USER_POOL_ID, APP_CLIENT_ID, REGION)

        assert "sub" in claims
        assert "token_use" in claims
        assert "client_id" in claims
        assert "exp" in claims


class TestVerifyTokenSignature:
    """Tests for RS256 signature verification (Requirement 5.1)."""

    def test_invalid_signature_raises_error(self, mock_jwks_response):
        # Create token signed with a different key
        other_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend(),
        )
        iat = int(time.time())
        claims = {
            "sub": "user-abc-123",
            "iss": ISSUER_URL,
            "token_use": "access",
            "client_id": APP_CLIENT_ID,
            "iat": iat,
            "exp": iat + 3600,
        }
        token = jwt.encode(claims, other_key, algorithm="RS256", headers={"kid": "test-kid-001"})

        with patch("cognito_verifier.requests.get", return_value=mock_jwks_response):
            with pytest.raises(AuthorizationError):
                verify_token(token, USER_POOL_ID, APP_CLIENT_ID, REGION)

    def test_malformed_token_raises_error(self):
        with pytest.raises(AuthorizationError):
            verify_token("not-a-jwt", USER_POOL_ID, APP_CLIENT_ID, REGION)


class TestVerifyTokenUse:
    """Tests for token_use claim validation (Requirement 5.2)."""

    def test_wrong_token_use_raises_error(self, mock_jwks_response):
        token = _mint_cognito_token(token_use="id")

        with patch("cognito_verifier.requests.get", return_value=mock_jwks_response):
            with pytest.raises(AuthorizationError, match="token_use"):
                verify_token(token, USER_POOL_ID, APP_CLIENT_ID, REGION)


class TestVerifyClientId:
    """Tests for client_id claim validation (Requirement 5.3)."""

    def test_wrong_client_id_raises_error(self, mock_jwks_response):
        token = _mint_cognito_token(client_id="wrong-client-id")

        with patch("cognito_verifier.requests.get", return_value=mock_jwks_response):
            with pytest.raises(AuthorizationError, match="client_id"):
                verify_token(token, USER_POOL_ID, APP_CLIENT_ID, REGION)


class TestVerifyIssuer:
    """Tests for iss claim validation (Requirement 5.4)."""

    def test_wrong_issuer_raises_error(self, mock_jwks_response):
        token = _mint_cognito_token(iss="https://wrong-issuer.example.com")

        with patch("cognito_verifier.requests.get", return_value=mock_jwks_response):
            with pytest.raises(AuthorizationError, match="[Ii]ssuer"):
                verify_token(token, USER_POOL_ID, APP_CLIENT_ID, REGION)


class TestVerifyExpiry:
    """Tests for token expiry validation (Requirement 5.5)."""

    def test_expired_token_raises_error(self, mock_jwks_response):
        token = _mint_cognito_token(ttl_seconds=-60)

        with patch("cognito_verifier.requests.get", return_value=mock_jwks_response):
            with pytest.raises(AuthorizationError, match="expired"):
                verify_token(token, USER_POOL_ID, APP_CLIENT_ID, REGION)


class TestJWKSCaching:
    """Tests for JWKS caching (Requirement 5.6)."""

    def test_jwks_cached_after_first_call(self, mock_jwks_response):
        token = _mint_cognito_token()

        with patch("cognito_verifier.requests.get", return_value=mock_jwks_response) as mock_get:
            verify_token(token, USER_POOL_ID, APP_CLIENT_ID, REGION)
            verify_token(token, USER_POOL_ID, APP_CLIENT_ID, REGION)

            # JWKS should only be fetched once
            mock_get.assert_called_once()

    def test_no_matching_kid_raises_error(self, mock_jwks_response):
        token = _mint_cognito_token(kid="unknown-kid")

        with patch("cognito_verifier.requests.get", return_value=mock_jwks_response):
            with pytest.raises(AuthorizationError, match="kid"):
                verify_token(token, USER_POOL_ID, APP_CLIENT_ID, REGION)


class TestJWKSFetchFailure:
    """Tests for JWKS endpoint unavailability."""

    def test_jwks_unreachable_raises_error(self):
        import requests as req

        token = _mint_cognito_token()

        mock_response = MagicMock()
        mock_response.raise_for_status.side_effect = req.exceptions.HTTPError("503")

        with patch("cognito_verifier.requests.get", return_value=mock_response):
            with pytest.raises(AuthorizationError, match="Failed to fetch JWKS"):
                verify_token(token, USER_POOL_ID, APP_CLIENT_ID, REGION)

    def test_missing_kid_in_header_raises_error(self):
        """Token header without kid field should raise AuthorizationError."""
        iat = int(time.time())
        claims = {
            "sub": "user-abc-123",
            "iss": ISSUER_URL,
            "token_use": "access",
            "client_id": APP_CLIENT_ID,
            "iat": iat,
            "exp": iat + 3600,
        }
        # Encode without kid in header
        token = jwt.encode(claims, _private_key, algorithm="RS256", headers={"alg": "RS256"})

        with pytest.raises(AuthorizationError, match="kid"):
            verify_token(token, USER_POOL_ID, APP_CLIENT_ID, REGION)
