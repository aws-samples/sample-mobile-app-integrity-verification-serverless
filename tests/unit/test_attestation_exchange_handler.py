"""Unit tests for the Attestation Exchange Lambda handler.

Validates Requirements: 2.1, 2.2, 2.3, 2.4, 11.3
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
def mock_get_signing_secret():
    """Mock _get_signing_secret to return a known test secret."""
    with patch("attestation_exchange.app._get_signing_secret", return_value=SIGNING_SECRET) as m:
        yield m


@pytest.fixture
def mock_play_integrity_pass():
    """Mock play_integrity.verify_token to pass verification."""
    with patch("attestation_exchange.app.play_integrity.verify_token") as m:
        m.return_value = {
            "appIntegrity": {"appRecognitionVerdict": "PLAY_RECOGNIZED"},
            "deviceIntegrity": {"deviceRecognitionVerdict": ["MEETS_DEVICE_INTEGRITY"]},
        }
        yield m


@pytest.fixture
def mock_cognito_verify_default():
    """Mock cognito_verifier.verify_token to return valid claims for default sub."""
    with patch(
        "attestation_exchange.app.cognito_verifier.verify_token",
        return_value={"sub": "a1b2c3d4-e5f6-7890-abcd-ef1234567890", "token_use": "access", "client_id": "test-app-client-id"},
    ) as m:
        yield m


class TestValidRequest:
    """Test valid request returns 200 with attestation_token (Requirement 2.1)."""

    def test_valid_request_returns_200(self, mock_get_signing_secret, mock_play_integrity_pass, mock_cognito_verify_default):
        """A valid body and Authorization returns 200 with attestation_token and expires_in."""
        token = _make_cognito_token()
        event = _make_event(
            body={"integrity_token": "valid-token", "platform": "android"},
            authorization=f"Bearer {token}",
        )

        response = lambda_handler(event, None)

        assert response["statusCode"] == 200
        body = json.loads(response["body"])
        assert "attestation_token" in body
        assert "expires_in" in body
        assert body["expires_in"] == 600  # 10 minutes * 60 seconds

    def test_valid_request_attestation_token_is_decodable(self, mock_get_signing_secret, mock_play_integrity_pass):
        """The returned attestation_token is a valid JWT with expected claims."""
        token = _make_cognito_token(sub="user-sub-123")
        event = _make_event(
            body={"integrity_token": "valid-token", "platform": "android"},
            authorization=f"Bearer {token}",
        )

        with _mock_cognito_verify(sub="user-sub-123"):
            response = lambda_handler(event, None)

        body = json.loads(response["body"])
        decoded = pyjwt.decode(body["attestation_token"], SIGNING_SECRET, algorithms=["HS256"])
        assert decoded["sub"] == "user-sub-123"
        assert decoded["iss"] == "attestation-exchange"
        assert decoded["device_integrity"] == "verified"
        assert decoded["app_integrity"] == "verified"


class TestMissingBody:
    """Test missing or invalid body returns 400 (Requirement 2.2)."""

    def test_missing_body_returns_400(self, mock_get_signing_secret):
        """No request body returns 400."""
        event = _make_event(body=None, authorization=f"Bearer {_make_cognito_token()}")
        # body is None by default in _make_event when body=None
        event["body"] = None

        response = lambda_handler(event, None)

        assert response["statusCode"] == 400
        body = json.loads(response["body"])
        assert "error" in body

    def test_empty_body_returns_400(self, mock_get_signing_secret):
        """Empty string body returns 400."""
        event = _make_event(authorization=f"Bearer {_make_cognito_token()}")
        event["body"] = ""

        response = lambda_handler(event, None)

        assert response["statusCode"] == 400

    def test_missing_integrity_token_returns_400(self, mock_get_signing_secret):
        """Body without integrity_token field returns 400."""
        event = _make_event(
            body={"platform": "android"},
            authorization=f"Bearer {_make_cognito_token()}",
        )

        response = lambda_handler(event, None)

        assert response["statusCode"] == 400
        body = json.loads(response["body"])
        assert "integrity_token" in body["error"]

    def test_invalid_json_body_returns_400(self, mock_get_signing_secret):
        """Malformed JSON body returns 400."""
        event = _make_event(authorization=f"Bearer {_make_cognito_token()}")
        event["body"] = "not-valid-json{{"

        response = lambda_handler(event, None)

        assert response["statusCode"] == 400


class TestMissingAuthorization:
    """Test missing or invalid Authorization returns 401 (Requirement 2.3)."""

    def test_missing_authorization_header_returns_401(self, mock_get_signing_secret):
        """No Authorization header returns 401."""
        event = _make_event(
            body={"integrity_token": "some-token", "platform": "android"},
        )

        response = lambda_handler(event, None)

        assert response["statusCode"] == 401
        body = json.loads(response["body"])
        assert "error" in body

    def test_empty_authorization_header_returns_401(self, mock_get_signing_secret):
        """Empty Authorization header returns 401."""
        event = _make_event(
            body={"integrity_token": "some-token", "platform": "android"},
            authorization="",
        )

        response = lambda_handler(event, None)

        assert response["statusCode"] == 401

    def test_invalid_bearer_token_returns_401(self, mock_get_signing_secret):
        """Authorization with non-JWT Bearer token returns 401."""
        event = _make_event(
            body={"integrity_token": "some-token", "platform": "android"},
            authorization="Bearer not-a-valid-jwt",
        )

        response = lambda_handler(event, None)

        assert response["statusCode"] == 401

    def test_missing_sub_in_token_returns_401(self, mock_get_signing_secret):
        """JWT without a sub claim returns 401."""
        # Create a token with no sub claim
        token_no_sub = pyjwt.encode(  # nosemgrep: python.jwt.security.jwt-python-hardcoded-secret
            {"aud": "test"}, "secret", algorithm="HS256"
        )
        event = _make_event(
            body={"integrity_token": "some-token", "platform": "android"},
            authorization=f"Bearer {token_no_sub}",
        )

        response = lambda_handler(event, None)

        assert response["statusCode"] == 401


class TestPlayIntegrityFailure:
    """Test Play Integrity failure returns 403 (Requirement 2.4)."""

    def test_attestation_verification_error_returns_403(self, mock_get_signing_secret, mock_cognito_verify_default):
        """When Play Integrity raises AttestationVerificationError, returns 403 with reason."""
        token = _make_cognito_token()
        event = _make_event(
            body={"integrity_token": "tampered-token", "platform": "android"},
            authorization=f"Bearer {token}",
        )

        with patch(
            "attestation_exchange.app.play_integrity.verify_token",
            side_effect=AttestationVerificationError("DEVICE_INTEGRITY_FAILED"),
        ):
            response = lambda_handler(event, None)

        assert response["statusCode"] == 403
        body = json.loads(response["body"])
        assert body["reason"] == "DEVICE_INTEGRITY_FAILED"
        assert "error" in body

    def test_app_not_recognized_returns_403(self, mock_get_signing_secret, mock_cognito_verify_default):
        """App recognition failure returns 403 with reason."""
        token = _make_cognito_token()
        event = _make_event(
            body={"integrity_token": "bad-app-token", "platform": "android"},
            authorization=f"Bearer {token}",
        )

        with patch(
            "attestation_exchange.app.play_integrity.verify_token",
            side_effect=AttestationVerificationError("APP_NOT_RECOGNIZED"),
        ):
            response = lambda_handler(event, None)

        assert response["statusCode"] == 403
        body = json.loads(response["body"])
        assert body["reason"] == "APP_NOT_RECOGNIZED"


class TestSecretsManagerFailure:
    """Test Secrets Manager failure returns 500 (Requirement 2.5)."""

    def test_secrets_manager_error_returns_500(self):
        """When _get_signing_secret raises, returns 500 without internal details."""
        token = _make_cognito_token()
        event = _make_event(
            body={"integrity_token": "valid-token", "platform": "android"},
            authorization=f"Bearer {token}",
        )

        with _mock_cognito_verify(), patch(
            "attestation_exchange.app.play_integrity.verify_token",
            return_value={"appIntegrity": {}, "deviceIntegrity": {}},
        ), patch(
            "attestation_exchange.app._get_signing_secret",
            side_effect=Exception("Connection refused"),
        ):
            response = lambda_handler(event, None)

        assert response["statusCode"] == 500
        body = json.loads(response["body"])
        assert "Internal server error" in body["error"]
        # Must not leak internal details
        assert "Connection refused" not in body["error"]
