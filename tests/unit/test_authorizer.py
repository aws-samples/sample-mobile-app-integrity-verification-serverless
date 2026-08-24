"""Unit tests for the Lambda Authorizer handler.

**Validates: Requirements 11.2, 11.4**

Tests all authorizer decision paths:
- Both tokens valid → Allow policy
- Missing Authorization → Deny
- Missing X-Attestation-Token → Deny
- Expired Cognito token → Deny
- Expired attestation token → Deny
- Invalid signature on either token → Deny
"""

import importlib.util
import os
import sys
from unittest.mock import patch, MagicMock

import pytest

# Ensure authorizer source is importable for the verifier error classes
_authorizer_src = os.path.join(os.path.dirname(__file__), "..", "..", "src", "authorizer")
sys.path.insert(0, _authorizer_src)

from attestation_verifier import AuthorizationError as AttestAuthError
from cognito_verifier import AuthorizationError as CognitoAuthError


def _load_authorizer_app():
    """Load the authorizer app module explicitly to avoid name collision with sample_api/app.py."""
    module_name = "authorizer_app_unit"
    if module_name in sys.modules:
        return sys.modules[module_name]
    app_path = os.path.join(_authorizer_src, "app.py")
    spec = importlib.util.spec_from_file_location(module_name, app_path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = module
    spec.loader.exec_module(module)
    return module


authorizer_app = _load_authorizer_app()


# --- Helpers ---

METHOD_ARN = "arn:aws:execute-api:us-east-1:123456:api/stage/GET/protected"


def _make_event(auth_header=None, attestation_header=None):
    """Build a REQUEST-type authorizer event with optional headers."""
    headers = {}
    if auth_header is not None:
        headers["Authorization"] = auth_header
    if attestation_header is not None:
        headers["X-Attestation-Token"] = attestation_header
    return {
        "type": "REQUEST",
        "methodArn": METHOD_ARN,
        "headers": headers,
    }


def _is_allow(response):
    """Check if the response is an Allow policy."""
    statement = response["policyDocument"]["Statement"][0]
    return statement["Effect"] == "Allow"


def _is_deny(response):
    """Check if the response is a Deny policy."""
    statement = response["policyDocument"]["Statement"][0]
    return statement["Effect"] == "Deny"


# --- Tests ---


class TestAuthorizerBothTokensValid:
    """Test that valid Cognito and attestation tokens produce an Allow policy."""

    @patch.object(authorizer_app, "_get_signing_secret", return_value="test-secret")
    @patch("cognito_verifier.verify_token")
    @patch("attestation_verifier.verify_token")
    def test_allow_policy_returned(self, mock_attest, mock_cognito, mock_secret):
        """Both tokens valid returns Allow with user sub as principalId."""
        mock_cognito.return_value = {
            "sub": "user-123-abc",
            "token_use": "access",
            "client_id": "test-app-client-id",
        }
        mock_attest.return_value = {
            "iss": "attestation-exchange",
            "device_integrity": "verified",
            "app_integrity": "verified",
        }

        event = _make_event(
            auth_header="Bearer valid-cognito-token",
            attestation_header="valid-attestation-token",
        )
        result = authorizer_app.lambda_handler(event, None)

        assert _is_allow(result)
        assert result["principalId"] == "user-123-abc"
        assert result["context"]["user_sub"] == "user-123-abc"
        assert result["context"]["attestation_verified"] == "true"

    @patch.object(authorizer_app, "_get_signing_secret", return_value="test-secret")
    @patch("cognito_verifier.verify_token")
    @patch("attestation_verifier.verify_token")
    def test_bearer_prefix_stripped(self, mock_attest, mock_cognito, mock_secret):
        """The 'Bearer ' prefix is stripped before passing token to verifier."""
        mock_cognito.return_value = {"sub": "user-456"}
        mock_attest.return_value = {}

        event = _make_event(
            auth_header="Bearer my-token",
            attestation_header="attest-token",
        )
        authorizer_app.lambda_handler(event, None)

        mock_cognito.assert_called_once()
        call_kwargs = mock_cognito.call_args
        assert call_kwargs[1]["token"] == "my-token" or call_kwargs[0][0] == "my-token"


class TestAuthorizerMissingAuthorization:
    """Test that missing Authorization header returns Deny."""

    @patch.object(authorizer_app, "_get_signing_secret", return_value="test-secret")
    def test_missing_authorization_header(self, mock_secret):
        """No Authorization header returns Deny with principalId 'unauthorized'."""
        event = _make_event(attestation_header="some-attest-token")
        result = authorizer_app.lambda_handler(event, None)

        assert _is_deny(result)
        assert result["principalId"] == "unauthorized"

    @patch.object(authorizer_app, "_get_signing_secret", return_value="test-secret")
    def test_empty_headers(self, mock_secret):
        """Empty headers dict returns Deny."""
        event = {
            "type": "REQUEST",
            "methodArn": METHOD_ARN,
            "headers": {},
        }
        result = authorizer_app.lambda_handler(event, None)

        assert _is_deny(result)
        assert result["principalId"] == "unauthorized"


class TestAuthorizerMissingAttestationToken:
    """Test that missing X-Attestation-Token header returns Deny."""

    @patch.object(authorizer_app, "_get_signing_secret", return_value="test-secret")
    def test_missing_attestation_token(self, mock_secret):
        """Authorization present but no X-Attestation-Token returns Deny."""
        event = _make_event(auth_header="Bearer valid-token")
        result = authorizer_app.lambda_handler(event, None)

        assert _is_deny(result)
        assert result["principalId"] == "unauthorized"


class TestAuthorizerExpiredCognitoToken:
    """Test that expired Cognito token returns Deny."""

    @patch.object(authorizer_app, "_get_signing_secret", return_value="test-secret")
    @patch("cognito_verifier.verify_token")
    def test_expired_cognito_token(self, mock_cognito, mock_secret):
        """Expired Cognito token raises AuthorizationError → Deny."""
        mock_cognito.side_effect = CognitoAuthError("Token has expired")

        event = _make_event(
            auth_header="Bearer expired-token",
            attestation_header="valid-attest-token",
        )
        result = authorizer_app.lambda_handler(event, None)

        assert _is_deny(result)
        assert result["principalId"] == "unauthorized"


class TestAuthorizerExpiredAttestationToken:
    """Test that expired attestation token returns Deny."""

    @patch.object(authorizer_app, "_get_signing_secret", return_value="test-secret")
    @patch("cognito_verifier.verify_token")
    @patch("attestation_verifier.verify_token")
    def test_expired_attestation_token(self, mock_attest, mock_cognito, mock_secret):
        """Expired attestation token raises AuthorizationError → Deny."""
        mock_cognito.return_value = {"sub": "user-789"}
        mock_attest.side_effect = AttestAuthError("Attestation token has expired")

        event = _make_event(
            auth_header="Bearer valid-cognito-token",
            attestation_header="expired-attest-token",
        )
        result = authorizer_app.lambda_handler(event, None)

        assert _is_deny(result)
        assert result["principalId"] == "unauthorized"


class TestAuthorizerInvalidSignatureCognito:
    """Test that invalid Cognito token signature returns Deny."""

    @patch.object(authorizer_app, "_get_signing_secret", return_value="test-secret")
    @patch("cognito_verifier.verify_token")
    def test_invalid_cognito_signature(self, mock_cognito, mock_secret):
        """Cognito token with invalid signature raises AuthorizationError → Deny."""
        mock_cognito.side_effect = CognitoAuthError(
            "Token signature verification failed"
        )

        event = _make_event(
            auth_header="Bearer bad-sig-token",
            attestation_header="valid-attest-token",
        )
        result = authorizer_app.lambda_handler(event, None)

        assert _is_deny(result)
        assert result["principalId"] == "unauthorized"


class TestAuthorizerInvalidSignatureAttestation:
    """Test that invalid attestation token signature returns Deny."""

    @patch.object(authorizer_app, "_get_signing_secret", return_value="test-secret")
    @patch("cognito_verifier.verify_token")
    @patch("attestation_verifier.verify_token")
    def test_invalid_attestation_signature(self, mock_attest, mock_cognito, mock_secret):
        """Attestation token with invalid signature raises AuthorizationError → Deny."""
        mock_cognito.return_value = {"sub": "user-abc"}
        mock_attest.side_effect = AttestAuthError(
            "Attestation token has invalid signature"
        )

        event = _make_event(
            auth_header="Bearer valid-cognito-token",
            attestation_header="bad-sig-attest-token",
        )
        result = authorizer_app.lambda_handler(event, None)

        assert _is_deny(result)
        assert result["principalId"] == "unauthorized"


class TestAuthorizerCrossIdentityTokenTransfer:
    """Test that an attestation token bound to one user cannot be used by another.

    Uses the real attestation_verifier (not mocked) to prove the end-to-end
    authorizer decision: a mismatch between the Cognito 'sub' and the
    attestation token 'sub' must result in Deny.
    """

    @patch.object(authorizer_app, "_get_signing_secret", return_value="test-secret")
    @patch("cognito_verifier.verify_token")
    def test_mismatched_attestation_sub_is_denied(self, mock_cognito, mock_secret):
        """USER-B's Cognito token + USER-A's attestation JWT → Deny."""
        import time as _time

        import jwt as _jwt

        # Caller authenticates as USER-B via Cognito.
        mock_cognito.return_value = {"sub": "USER-B-sub"}

        # Attestation JWT was minted for USER-A and is otherwise fully valid.
        iat = int(_time.time())
        attest_claims = {
            "iss": "attestation-exchange",
            "sub": "USER-A-sub",
            "iat": iat,
            "exp": iat + 600,
            "device_integrity": "verified",
            "app_integrity": "verified",
            "platform": "android",
        }
        attest_token = _jwt.encode(attest_claims, "test-secret", algorithm="HS256")

        event = _make_event(
            auth_header="Bearer valid-cognito-token-for-user-b",
            attestation_header=attest_token,
        )
        result = authorizer_app.lambda_handler(event, None)

        assert _is_deny(result)
        assert result["principalId"] == "unauthorized"

    @patch.object(authorizer_app, "_get_signing_secret", return_value="test-secret")
    @patch("cognito_verifier.verify_token")
    def test_matching_attestation_sub_is_allowed(self, mock_cognito, mock_secret):
        """Same 'sub' in both tokens → Allow (guards against over-blocking)."""
        import time as _time

        import jwt as _jwt

        mock_cognito.return_value = {"sub": "USER-A-sub"}

        iat = int(_time.time())
        attest_claims = {
            "iss": "attestation-exchange",
            "sub": "USER-A-sub",
            "iat": iat,
            "exp": iat + 600,
            "device_integrity": "verified",
            "app_integrity": "verified",
            "platform": "android",
        }
        attest_token = _jwt.encode(attest_claims, "test-secret", algorithm="HS256")

        event = _make_event(
            auth_header="Bearer valid-cognito-token-for-user-a",
            attestation_header=attest_token,
        )
        result = authorizer_app.lambda_handler(event, None)

        assert _is_allow(result)
        assert result["principalId"] == "USER-A-sub"
        assert result["context"]["user_sub"] == "USER-A-sub"


class TestAuthorizerSecretsManagerMocked:
    """Test that the signing secret is fetched from Secrets Manager via boto3."""

    @patch("boto3.client")
    @patch("cognito_verifier.verify_token")
    @patch("attestation_verifier.verify_token")
    def test_secrets_manager_called_when_cache_empty(
        self, mock_attest, mock_cognito, mock_boto_client
    ):
        """When cache is empty, _get_signing_secret calls Secrets Manager get_secret_value."""
        # Reset the module-level cache to force a fresh call
        authorizer_app._signing_secret_cache = None

        mock_sm = MagicMock()
        mock_sm.get_secret_value.return_value = {"SecretString": "fetched-secret"}
        mock_boto_client.return_value = mock_sm

        mock_cognito.return_value = {"sub": "user-sm-test"}
        mock_attest.return_value = {}

        event = _make_event(
            auth_header="Bearer token",
            attestation_header="attest-token",
        )
        result = authorizer_app.lambda_handler(event, None)

        assert _is_allow(result)
        mock_boto_client.assert_called_once_with("secretsmanager")
        mock_sm.get_secret_value.assert_called_once()

        # Clean up cache so other tests aren't affected
        authorizer_app._signing_secret_cache = None
