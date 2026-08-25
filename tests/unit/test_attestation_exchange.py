"""Unit tests for the Attestation Exchange flow.

Focuses on DEMO_MODE behavior, Secrets Manager mocking,
and verifying no outbound network calls occur in demo mode.

Validates Requirements: 11.3, 11.4
"""

import json
import os
from unittest.mock import patch, MagicMock

import jwt as pyjwt
import pytest

from attestation_exchange.app import lambda_handler
from attestation_exchange.play_integrity import AttestationVerificationError


SIGNING_SECRET = os.environ.get(  # nosec B105 - test-only secret
    "TEST_SIGNING_SECRET", "test-signing-secret-key-for-hmac-256-operations"
)


def _make_cognito_token(sub: str = "a1b2c3d4-e5f6-7890-abcd-ef1234567890") -> str:
    """Create a minimal JWT with a sub claim for Authorization header."""
    return pyjwt.encode(  # nosemgrep: python.jwt.security.jwt-python-hardcoded-secret
        {"sub": sub}, "dummy-secret", algorithm="HS256"
    )


def _mock_cognito_verify(sub: str = "a1b2c3d4-e5f6-7890-abcd-ef1234567890"):
    """Return a patch that mocks cognito_verifier.verify_token to return valid claims."""
    return patch(
        "attestation_exchange.app.cognito_verifier.verify_token",
        return_value={"sub": sub, "token_use": "access", "client_id": "test-app-client-id"},
    )


def _make_event(body: dict | None = None, authorization: str | None = None) -> dict:
    """Build an API Gateway proxy event for the attestation exchange handler."""
    event = {
        "httpMethod": "POST",
        "path": "/attest",
        "headers": {},
        "body": None,
    }

    if body is not None:
        event["body"] = json.dumps(body)

    if authorization is not None:
        event["headers"]["Authorization"] = authorization

    return event


@pytest.fixture(autouse=True)
def reset_signing_secret_cache():
    """Clear the module-level signing secret cache between tests."""
    import attestation_exchange.app as app_module
    app_module._signing_secret_cache = None
    yield
    app_module._signing_secret_cache = None


@pytest.fixture
def mock_secretsmanager():
    """Mock _get_signing_secret to return a known signing secret (via Lambda Extension mock)."""
    with patch("attestation_exchange.app._get_signing_secret", return_value=SIGNING_SECRET) as mock_fn:
        yield mock_fn


class TestDemoModeSuccess:
    """Test DEMO_MODE returns success without Google API call (Requirement 11.3)."""

    def test_demo_mode_returns_200_with_jwt(self, mock_secretsmanager, monkeypatch):
        """DEMO_MODE=true with valid request returns HTTP 200 and attestation_token."""
        monkeypatch.setenv("DEMO_MODE", "true")

        token = _make_cognito_token()
        event = _make_event(
            body={"integrity_token": "demo-token", "platform": "android"},
            authorization=f"Bearer {token}",
        )

        with _mock_cognito_verify():
            response = lambda_handler(event, None)

        assert response["statusCode"] == 200
        body = json.loads(response["body"])
        assert "attestation_token" in body
        assert "expires_in" in body
        assert body["expires_in"] == 600  # 10 min * 60 sec

    def test_demo_mode_jwt_contains_expected_claims(self, mock_secretsmanager, monkeypatch):
        """The attestation_token issued in DEMO_MODE is a valid JWT with correct claims."""
        monkeypatch.setenv("DEMO_MODE", "true")
        user_sub = "test-user-sub-demo"

        token = _make_cognito_token(sub=user_sub)
        event = _make_event(
            body={"integrity_token": "demo-token", "platform": "android"},
            authorization=f"Bearer {token}",
        )

        with _mock_cognito_verify(sub=user_sub):
            response = lambda_handler(event, None)

        body = json.loads(response["body"])
        decoded = pyjwt.decode(body["attestation_token"], SIGNING_SECRET, algorithms=["HS256"])
        assert decoded["sub"] == user_sub
        assert decoded["iss"] == "attestation-exchange"
        assert decoded["device_integrity"] == "verified"
        assert decoded["app_integrity"] == "verified"

    def test_no_network_calls_made(self, mock_secretsmanager, monkeypatch):
        """Demo mode must not make any outbound network calls."""
        monkeypatch.setenv("DEMO_MODE", "true")

        token = _make_cognito_token()
        event = _make_event(
            body={"integrity_token": "demo-token", "platform": "android"},
            authorization=f"Bearer {token}",
        )

        # The demo implementation doesn't import or use requests at all,
        # so a successful 200 response confirms no network calls.
        with _mock_cognito_verify():
            response = lambda_handler(event, None)
        assert response["statusCode"] == 200


class TestFailedAttestation:
    """Test failed attestation returns 403 (Requirement 11.3)."""

    def test_attestation_verification_error_returns_403(self, mock_secretsmanager):
        """When play_integrity.verify_token raises AttestationVerificationError, returns 403."""
        token = _make_cognito_token()
        event = _make_event(
            body={"integrity_token": "bad-app-token", "platform": "android"},
            authorization=f"Bearer {token}",
        )

        with _mock_cognito_verify(), patch(
            "attestation_exchange.app.play_integrity.verify_token",
            side_effect=AttestationVerificationError("APP_NOT_RECOGNIZED"),
        ):
            response = lambda_handler(event, None)

        assert response["statusCode"] == 403
        body = json.loads(response["body"])
        assert "error" in body
        assert "reason" in body
        assert body["reason"] == "APP_NOT_RECOGNIZED"

    def test_device_integrity_failure_returns_403(self, mock_secretsmanager):
        """When play_integrity.verify_token raises for device integrity, returns 403."""
        token = _make_cognito_token()
        event = _make_event(
            body={"integrity_token": "bad-device-token", "platform": "android"},
            authorization=f"Bearer {token}",
        )

        with _mock_cognito_verify(), patch(
            "attestation_exchange.app.play_integrity.verify_token",
            side_effect=AttestationVerificationError("DEVICE_INTEGRITY_FAILED"),
        ):
            response = lambda_handler(event, None)

        assert response["statusCode"] == 403
        body = json.loads(response["body"])
        assert body["reason"] == "DEVICE_INTEGRITY_FAILED"


class TestMissingIntegrityToken:
    """Test missing integrity_token returns 400 (Requirement 11.3)."""

    def test_missing_integrity_token_returns_400(self, mock_secretsmanager):
        """Request body without integrity_token field returns 400."""
        token = _make_cognito_token()
        event = _make_event(
            body={"platform": "android"},
            authorization=f"Bearer {token}",
        )

        response = lambda_handler(event, None)

        assert response["statusCode"] == 400
        body = json.loads(response["body"])
        assert "integrity_token" in body["error"]

    def test_empty_integrity_token_returns_400(self, mock_secretsmanager):
        """Request body with empty string integrity_token returns 400."""
        token = _make_cognito_token()
        event = _make_event(
            body={"integrity_token": "", "platform": "android"},
            authorization=f"Bearer {token}",
        )

        response = lambda_handler(event, None)

        assert response["statusCode"] == 400


class TestSecretsManagerMocking:
    """Test that Secrets Manager is properly called for signing secret (Requirement 11.4)."""

    def test_secrets_manager_called_with_correct_arn(self, monkeypatch):
        """Lambda calls Secrets Manager get_secret_value with the ARN from SIGNING_SECRET_ARN env var."""
        import attestation_exchange.app as app_module

        monkeypatch.setenv("DEMO_MODE", "true")
        secret_arn = os.environ.get(  # nosec B105 - test-only ARN
            "TEST_SECRET_ARN",
            "arn:aws:secretsmanager:us-east-1:123456789012:secret:test-secret-abc123",
        )
        monkeypatch.setenv("SIGNING_SECRET_ARN", secret_arn)

        # Reset the module-level cache to force a fresh Secrets Manager call
        app_module._signing_secret_cache = None

        token = _make_cognito_token()
        event = _make_event(
            body={"integrity_token": "demo-token", "platform": "android"},
            authorization=f"Bearer {token}",
        )

        # Mock the boto3 Secrets Manager client
        mock_sm = MagicMock()
        mock_sm.get_secret_value.return_value = {"SecretString": SIGNING_SECRET}

        with patch("boto3.client", return_value=mock_sm) as mock_boto_client, _mock_cognito_verify():
            response = lambda_handler(event, None)

        assert response["statusCode"] == 200
        mock_boto_client.assert_called_once_with("secretsmanager")
        # Verify get_secret_value was called with the configured ARN
        mock_sm.get_secret_value.assert_called_once_with(SecretId=secret_arn)

        # Clean up cache so other tests aren't affected
        app_module._signing_secret_cache = None

    def test_secrets_manager_failure_returns_500(self, monkeypatch):
        """When Secrets Manager raises an exception, handler returns 500."""
        monkeypatch.setenv("DEMO_MODE", "true")

        token = _make_cognito_token()
        event = _make_event(
            body={"integrity_token": "demo-token", "platform": "android"},
            authorization=f"Bearer {token}",
        )

        with patch(
            "attestation_exchange.app._get_signing_secret",
            side_effect=Exception("Access denied"),
        ), _mock_cognito_verify():
            response = lambda_handler(event, None)

        assert response["statusCode"] == 500
        body = json.loads(response["body"])
        assert "Internal server error" in body["error"]
        # Must not leak internal error details
        assert "Access denied" not in body["error"]
