"""Property-based tests for the Cognito Verifier module using Hypothesis.

These tests validate that the Cognito verifier correctly rejects JWTs with
invalid claims across randomly generated inputs.
"""

import time
from unittest.mock import patch, MagicMock

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
from hypothesis import given, settings, assume
from hypothesis import strategies as st
from jwt.algorithms import RSAAlgorithm

from cognito_verifier import AuthorizationError, verify_token, _jwks_cache


# Generate a fixed RSA key pair for all property tests
_private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
    backend=default_backend(),
)
_public_key = _private_key.public_key()

# Convert public key to JWK format for the mock JWKS endpoint
_public_jwk = RSAAlgorithm.to_jwk(_public_key, as_dict=True)
_public_jwk["kid"] = "prop-test-kid-001"
_public_jwk["alg"] = "RS256"
_public_jwk["use"] = "sig"

# Fixed test configuration
USER_POOL_ID = "us-east-1_PropTestPool"
APP_CLIENT_ID = "prop-test-app-client-id"
REGION = "us-east-1"
ISSUER_URL = f"https://cognito-idp.{REGION}.amazonaws.com/{USER_POOL_ID}"


def _mint_token(
    token_use="access",
    client_id=APP_CLIENT_ID,
    iss=ISSUER_URL,
    ttl_seconds=3600,
    sub="user-prop-test-123",
):
    """Mint an RS256 JWT with configurable claims for property testing."""
    iat = int(time.time())
    claims = {
        "sub": sub,
        "iss": iss,
        "token_use": token_use,
        "client_id": client_id,
        "iat": iat,
        "exp": iat + ttl_seconds,
    }
    headers = {"kid": "prop-test-kid-001", "alg": "RS256"}
    return jwt.encode(claims, _private_key, algorithm="RS256", headers=headers)


def _mock_jwks_response():
    """Create a mock JWKS response returning our test public key."""
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = {"keys": [_public_jwk]}
    mock_response.raise_for_status = MagicMock()
    return mock_response


# Strategies for generating invalid claim values
invalid_token_use_strategy = st.text(
    alphabet=st.characters(categories=("L", "N")),
    min_size=1,
    max_size=50,
).filter(lambda x: x != "access")

invalid_client_id_strategy = st.text(
    alphabet=st.characters(categories=("L", "N", "P")),
    min_size=1,
    max_size=100,
).filter(lambda x: x != APP_CLIENT_ID)

invalid_issuer_strategy = st.text(
    alphabet=st.characters(categories=("L", "N", "P")),
    min_size=1,
    max_size=200,
).filter(lambda x: x != ISSUER_URL)

# Strategy for expired token TTL (negative values produce past expiry)
expired_ttl_strategy = st.integers(min_value=-86400, max_value=-1)


class TestCognitoVerifierRejectsInvalidClaims:
    """Property 8: Cognito Verifier Rejects Invalid Claims.

    For any JWT where token_use is not "access", or client_id does not match
    the configured app client ID, or iss does not match the expected Cognito
    issuer URL, or the token is expired, the Cognito_Verifier SHALL raise
    an AuthorizationError.

    **Validates: Requirements 5.2, 5.3, 5.4, 5.5**
    """

    @given(token_use=invalid_token_use_strategy)
    @settings(max_examples=100)
    def test_rejects_invalid_token_use(self, token_use):
        """Cognito verifier raises AuthorizationError for any token_use != 'access'.

        **Validates: Requirements 5.2**
        """
        _jwks_cache.clear()
        token = _mint_token(token_use=token_use)

        with patch("cognito_verifier.requests.get", return_value=_mock_jwks_response()):
            with pytest.raises(AuthorizationError):
                verify_token(token, USER_POOL_ID, APP_CLIENT_ID, REGION)

    @given(client_id=invalid_client_id_strategy)
    @settings(max_examples=100)
    def test_rejects_invalid_client_id(self, client_id):
        """Cognito verifier raises AuthorizationError for any client_id != configured app client ID.

        **Validates: Requirements 5.3**
        """
        _jwks_cache.clear()
        token = _mint_token(client_id=client_id)

        with patch("cognito_verifier.requests.get", return_value=_mock_jwks_response()):
            with pytest.raises(AuthorizationError):
                verify_token(token, USER_POOL_ID, APP_CLIENT_ID, REGION)

    @given(iss=invalid_issuer_strategy)
    @settings(max_examples=100)
    def test_rejects_invalid_issuer(self, iss):
        """Cognito verifier raises AuthorizationError for any iss != expected Cognito issuer URL.

        **Validates: Requirements 5.4**
        """
        _jwks_cache.clear()
        token = _mint_token(iss=iss)

        with patch("cognito_verifier.requests.get", return_value=_mock_jwks_response()):
            with pytest.raises(AuthorizationError):
                verify_token(token, USER_POOL_ID, APP_CLIENT_ID, REGION)

    @given(ttl_seconds=expired_ttl_strategy)
    @settings(max_examples=100)
    def test_rejects_expired_token(self, ttl_seconds):
        """Cognito verifier raises AuthorizationError for any token with exp in the past.

        **Validates: Requirements 5.5**
        """
        _jwks_cache.clear()
        token = _mint_token(ttl_seconds=ttl_seconds)

        with patch("cognito_verifier.requests.get", return_value=_mock_jwks_response()):
            with pytest.raises(AuthorizationError):
                verify_token(token, USER_POOL_ID, APP_CLIENT_ID, REGION)
