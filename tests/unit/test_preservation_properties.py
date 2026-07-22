"""Property-based tests for Preservation of Valid Flow and Deny Behavior.

**Validates: Requirements 3.1, 3.2, 3.3, 3.4, 3.5, 3.6, 3.7, 3.8, 3.9, 3.10**

Property 2: Preservation - Valid Flow and Deny Behavior Unchanged

These tests capture the BASELINE behavior of the UNFIXED code for non-buggy inputs.
They must ALL PASS on the current (unfixed) code to confirm the behaviors that must
be preserved after fixes are applied.

Preservation properties verified:
- Valid request body with integrity_token and Authorization → attestation JWT returned
- Missing request body → 400 with "Request body is required"
- Invalid JSON body → 400 with "Invalid JSON in request body"
- Missing integrity_token field → 400 with "integrity_token is required"
- Missing Authorization header → 401 with "Unauthorized"
- Authorizer with missing Authorization → Deny policy
- Authorizer with missing X-Attestation-Token → Deny policy
- Deny policy uses "unauthorized" as principalId with specific resource
- DEMO_MODE returns hardcoded passing verdict without real API calls
"""

import importlib.util
import json
import os
import sys
from unittest.mock import patch

import jwt as pyjwt
import pytest
from hypothesis import given, settings, assume, HealthCheck
from hypothesis import strategies as st

# Ensure source directories are on path
_src_root = os.path.join(os.path.dirname(__file__), "..", "..", "src")
_attestation_src = os.path.join(_src_root, "attestation_exchange")
_authorizer_src = os.path.join(_src_root, "authorizer")
sys.path.insert(0, _src_root)
sys.path.insert(0, _attestation_src)
sys.path.insert(0, _authorizer_src)

from attestation_exchange.app import lambda_handler as attest_handler
from attestation_exchange.play_integrity import verify_token as play_verify_token
from authorizer.policy_builder import build_policy

# After the fix, cognito_verifier.verify_token() is used instead of _extract_cognito_sub().
# Tests that need a valid Cognito token must mock cognito_verifier.verify_token to return claims.


def _load_authorizer_app():
    """Load the authorizer app module explicitly to avoid name collision."""
    module_name = "authorizer_app_preservation"
    if module_name in sys.modules:
        return sys.modules[module_name]
    app_path = os.path.join(_authorizer_src, "app.py")
    spec = importlib.util.spec_from_file_location(module_name, app_path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = module
    spec.loader.exec_module(module)
    return module


authorizer_app = _load_authorizer_app()


# --- Strategies ---

# Non-empty strings suitable for token content
token_text = st.text(
    alphabet=st.characters(whitelist_categories=("L", "N")),
    min_size=1,
    max_size=80,
)

# Strategy for generating non-empty integrity tokens (at least 16 chars for nonce extraction)
integrity_token_strategy = st.text(
    alphabet=st.characters(whitelist_categories=("L", "N")),
    min_size=16,
    max_size=100,
)

# Strategy for user sub values (UUID-like)
user_sub_strategy = st.from_regex(
    r"[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}",
    fullmatch=True,
)

# Strategy for method ARN strings
method_arn_strategy = st.builds(
    lambda acct, api, stage, method, path: (
        f"arn:aws:execute-api:us-east-1:{acct}:{api}/{stage}/{method}/{path}"
    ),
    acct=st.text(alphabet="0123456789", min_size=12, max_size=12),
    api=st.text(alphabet="abcdefghijklmnopqrstuvwxyz0123456789", min_size=4, max_size=10),
    stage=st.sampled_from(["dev", "staging", "prod", "test"]),
    method=st.sampled_from(["GET", "POST", "PUT", "DELETE"]),
    path=st.text(alphabet="abcdefghijklmnopqrstuvwxyz/", min_size=1, max_size=20),
)

# Strategy for generating invalid JSON strings (that won't parse as JSON)
invalid_json_strategy = st.text(min_size=1, max_size=100).filter(
    lambda s: _is_invalid_json(s)
)


def _is_invalid_json(s: str) -> bool:
    """Return True if the string is NOT valid JSON."""
    try:
        json.loads(s)
        return False
    except (json.JSONDecodeError, ValueError):
        return True


def _make_cognito_token(sub: str = "a1b2c3d4-e5f6-7890-abcd-ef1234567890") -> str:
    """Create a minimal JWT with a sub claim (unfixed code decodes without verification)."""
    return pyjwt.encode({"sub": sub}, "dummy-secret", algorithm="HS256")


def _make_attest_event(body=None, body_str=None, authorization=None):
    """Build an API Gateway proxy event for the attestation exchange handler."""
    event = {
        "httpMethod": "POST",
        "path": "/attest",
        "headers": {},
        "body": None,
    }
    if body is not None:
        event["body"] = json.dumps(body)
    elif body_str is not None:
        event["body"] = body_str
    if authorization is not None:
        event["headers"]["Authorization"] = authorization
    return event


# =============================================================================
# PRESERVATION PROPERTY TESTS - Attestation Exchange Handler
# =============================================================================


class TestPreservationValidAttestationFlow:
    """Property 2a: Valid attestation request returns JWT with expected structure.

    **Validates: Requirements 3.1, 3.10**

    For any valid request with integrity_token, valid Authorization header,
    the handler returns 200 with attestation_token and expires_in fields.
    In DEMO_MODE the play integrity verification always passes.
    """

    @given(
        user_sub=user_sub_strategy,
        integrity_token=integrity_token_strategy,
    )
    @settings(max_examples=50, deadline=None, suppress_health_check=[HealthCheck.too_slow])
    def test_valid_request_returns_attestation_jwt(self, user_sub, integrity_token):
        """**Validates: Requirements 3.1, 3.10**

        For all valid attestation requests in demo mode, the handler returns 200
        with attestation_token (decodable JWT with sub, exp, iat, attestation claims)
        and expires_in field.
        """
        import attestation_exchange.app as app_module
        app_module._signing_secret_cache = None

        token = _make_cognito_token(sub=user_sub)
        event = _make_attest_event(
            body={"integrity_token": integrity_token, "platform": "android"},
            authorization=f"Bearer {token}",
        )

        signing_secret = "test-preservation-secret-for-hmac"

        with patch(
            "attestation_exchange.app._get_signing_secret",
            return_value=signing_secret,
        ), patch(
            "attestation_exchange.app.cognito_verifier.verify_token",
            return_value={"sub": user_sub, "token_use": "access", "client_id": "test"},
        ):
            response = attest_handler(event, None)

        assert response["statusCode"] == 200
        body = json.loads(response["body"])
        assert "attestation_token" in body
        assert "expires_in" in body
        assert body["expires_in"] == 600  # 10 min * 60 sec

        # Decode the attestation JWT and verify claims
        decoded = pyjwt.decode(
            body["attestation_token"], signing_secret, algorithms=["HS256"]
        )
        assert decoded["sub"] == user_sub
        assert "exp" in decoded
        assert "iat" in decoded
        assert decoded["device_integrity"] == "verified"
        assert decoded["app_integrity"] == "verified"
        assert decoded["iss"] == "attestation-exchange"


class TestPreservationMissingBody:
    """Property 2b: Missing request body returns 400.

    **Validates: Requirements 3.6**
    """

    @given(authorization=token_text)
    @settings(max_examples=30, deadline=None)
    def test_missing_body_returns_400(self, authorization):
        """**Validates: Requirements 3.6**

        For any request with missing body, returns 400 with "Request body is required".
        """
        token = _make_cognito_token()
        event = _make_attest_event(
            body=None,
            authorization=f"Bearer {token}",
        )
        # Ensure body is truly None/empty
        event["body"] = None

        response = attest_handler(event, None)

        assert response["statusCode"] == 400
        body = json.loads(response["body"])
        assert body["error"] == "Request body is required"

    @given(authorization=token_text)
    @settings(max_examples=30, deadline=None)
    def test_empty_body_returns_400(self, authorization):
        """**Validates: Requirements 3.6**

        For any request with empty string body, returns 400 with "Request body is required".
        """
        token = _make_cognito_token()
        event = _make_attest_event(authorization=f"Bearer {token}")
        event["body"] = ""

        response = attest_handler(event, None)

        assert response["statusCode"] == 400
        body = json.loads(response["body"])
        assert body["error"] == "Request body is required"


class TestPreservationInvalidJSON:
    """Property 2c: Invalid JSON body returns 400.

    **Validates: Requirements 3.6**
    """

    @given(invalid_json=invalid_json_strategy)
    @settings(max_examples=50, deadline=None, suppress_health_check=[HealthCheck.too_slow])
    def test_invalid_json_returns_400(self, invalid_json):
        """**Validates: Requirements 3.6**

        For all invalid JSON strings as request body, returns 400 with
        "Invalid JSON in request body".
        """
        token = _make_cognito_token()
        event = _make_attest_event(authorization=f"Bearer {token}")
        event["body"] = invalid_json

        response = attest_handler(event, None)

        assert response["statusCode"] == 400
        body = json.loads(response["body"])
        assert body["error"] == "Invalid JSON in request body"


class TestPreservationMissingIntegrityToken:
    """Property 2d: Missing integrity_token field returns 400.

    **Validates: Requirements 3.7**
    """

    @given(
        platform=st.sampled_from(["android", "ios"]),
        extra_field=st.text(min_size=0, max_size=20),
    )
    @settings(max_examples=30, deadline=None)
    def test_missing_integrity_token_returns_400(self, platform, extra_field):
        """**Validates: Requirements 3.7**

        For any request body missing the integrity_token field, returns 400 with
        "integrity_token is required".
        """
        token = _make_cognito_token()
        body = {"platform": platform}
        if extra_field:
            body["extra"] = extra_field
        event = _make_attest_event(
            body=body,
            authorization=f"Bearer {token}",
        )

        response = attest_handler(event, None)

        assert response["statusCode"] == 400
        resp_body = json.loads(response["body"])
        assert resp_body["error"] == "integrity_token is required"


class TestPreservationMissingAuthorization:
    """Property 2e: Missing Authorization header returns 401.

    **Validates: Requirements 3.8**
    """

    @given(integrity_token=integrity_token_strategy)
    @settings(max_examples=30, deadline=None)
    def test_missing_authorization_returns_401(self, integrity_token):
        """**Validates: Requirements 3.8**

        For any request with missing Authorization header, returns 401 with
        "Unauthorized".
        """
        event = _make_attest_event(
            body={"integrity_token": integrity_token, "platform": "android"},
            authorization=None,
        )
        # Remove Authorization header entirely
        event["headers"] = {}

        response = attest_handler(event, None)

        assert response["statusCode"] == 401
        body = json.loads(response["body"])
        assert body["error"] == "Unauthorized"


# =============================================================================
# PRESERVATION PROPERTY TESTS - Authorizer Deny Behavior
# =============================================================================


class TestPreservationAuthorizerDenyMissingAuth:
    """Property 2f: Authorizer with missing Authorization header → Deny policy.

    **Validates: Requirements 3.3**
    """

    @given(
        method_arn=method_arn_strategy,
        attestation_token=token_text,
    )
    @settings(max_examples=50, deadline=None)
    def test_missing_auth_header_deny(self, method_arn, attestation_token):
        """**Validates: Requirements 3.3**

        For any method ARN and any attestation token, when Authorization header
        is missing, the authorizer returns a Deny policy with principalId "unauthorized".
        """
        authorizer_app._signing_secret_cache = None

        event = {
            "type": "REQUEST",
            "methodArn": method_arn,
            "headers": {"X-Attestation-Token": attestation_token},
        }

        result = authorizer_app.lambda_handler(event, None)

        assert result["principalId"] == "unauthorized"
        stmt = result["policyDocument"]["Statement"][0]
        assert stmt["Effect"] == "Deny"
        assert stmt["Resource"] == method_arn


class TestPreservationAuthorizerDenyMissingAttestation:
    """Property 2g: Authorizer with missing X-Attestation-Token header → Deny policy.

    **Validates: Requirements 3.3**
    """

    @given(
        method_arn=method_arn_strategy,
        cognito_token=token_text,
    )
    @settings(max_examples=50, deadline=None)
    def test_missing_attestation_header_deny(self, method_arn, cognito_token):
        """**Validates: Requirements 3.3**

        For any method ARN and any cognito token, when X-Attestation-Token header
        is missing, the authorizer returns a Deny policy with principalId "unauthorized".
        """
        authorizer_app._signing_secret_cache = None

        event = {
            "type": "REQUEST",
            "methodArn": method_arn,
            "headers": {"Authorization": f"Bearer {cognito_token}"},
        }

        result = authorizer_app.lambda_handler(event, None)

        assert result["principalId"] == "unauthorized"
        stmt = result["policyDocument"]["Statement"][0]
        assert stmt["Effect"] == "Deny"
        assert stmt["Resource"] == method_arn


class TestPreservationDenyPolicyStructure:
    """Property 2h: Deny policy always uses "unauthorized" principalId and specific resource.

    **Validates: Requirements 3.3, 3.4, 3.5**
    """

    @given(method_arn=method_arn_strategy)
    @settings(max_examples=100, deadline=None)
    def test_deny_policy_structure_preserved(self, method_arn):
        """**Validates: Requirements 3.3, 3.4, 3.5**

        For all random strings as methodArn, Deny policy preserves specific resource
        and uses "unauthorized" principalId.
        """
        result = build_policy("unauthorized", "Deny", method_arn)

        assert result["principalId"] == "unauthorized"
        assert result["policyDocument"]["Version"] == "2012-10-17"
        stmt = result["policyDocument"]["Statement"][0]
        assert stmt["Action"] == "execute-api:Invoke"
        assert stmt["Effect"] == "Deny"
        assert stmt["Resource"] == method_arn
        # Deny should NOT include context
        assert "context" not in result

    @given(
        principal_id=st.text(min_size=1, max_size=50),
        method_arn=method_arn_strategy,
    )
    @settings(max_examples=100, deadline=None)
    def test_deny_overrides_principal_to_unauthorized(self, principal_id, method_arn):
        """**Validates: Requirements 3.3**

        For any principal_id input with Deny effect, the policy builder always
        overrides principalId to "unauthorized".
        """
        result = build_policy(principal_id, "Deny", method_arn)

        assert result["principalId"] == "unauthorized"
        stmt = result["policyDocument"]["Statement"][0]
        assert stmt["Effect"] == "Deny"
        assert stmt["Resource"] == method_arn


# =============================================================================
# PRESERVATION PROPERTY TESTS - Demo Mode
# =============================================================================


class TestPreservationDemoMode:
    """Property 2i: DEMO_MODE returns hardcoded passing verdict without real API calls.

    **Validates: Requirements 3.10**
    """

    @given(integrity_token=integrity_token_strategy)
    @settings(max_examples=50, deadline=None)
    def test_demo_mode_returns_passing_verdict(self, integrity_token):
        """**Validates: Requirements 3.10**

        For all valid attestation requests in demo mode, verify_token returns a
        verdict with passing app and device integrity without making real API calls.
        """
        verdict = play_verify_token(integrity_token)

        # Verify the verdict has the expected hardcoded passing values
        assert verdict["appIntegrity"]["appRecognitionVerdict"] == "PLAY_RECOGNIZED"
        assert "MEETS_DEVICE_INTEGRITY" in verdict["deviceIntegrity"]["deviceRecognitionVerdict"]
        # Verify requestDetails are present
        assert "requestDetails" in verdict
        assert verdict["requestDetails"]["requestPackageName"] == "com.example.app"
        # Nonce is derived from the token prefix
        assert verdict["requestDetails"]["nonce"] == integrity_token[:16]

    @given(
        user_sub=user_sub_strategy,
        integrity_token=integrity_token_strategy,
    )
    @settings(max_examples=30, deadline=None, suppress_health_check=[HealthCheck.too_slow])
    def test_demo_mode_full_flow_returns_jwt(self, user_sub, integrity_token):
        """**Validates: Requirements 3.1, 3.10**

        For all valid attestation requests in demo mode, the full handler returns
        a valid attestation JWT with expected claims (sub, exp, iat, attestation_verified fields).
        """
        import attestation_exchange.app as app_module
        app_module._signing_secret_cache = None

        signing_secret = "test-demo-mode-secret"
        token = _make_cognito_token(sub=user_sub)
        event = _make_attest_event(
            body={"integrity_token": integrity_token, "platform": "android"},
            authorization=f"Bearer {token}",
        )

        with patch(
            "attestation_exchange.app._get_signing_secret",
            return_value=signing_secret,
        ), patch(
            "attestation_exchange.app.cognito_verifier.verify_token",
            return_value={"sub": user_sub, "token_use": "access", "client_id": "test"},
        ):
            response = attest_handler(event, None)

        assert response["statusCode"] == 200
        body = json.loads(response["body"])
        decoded = pyjwt.decode(
            body["attestation_token"], signing_secret, algorithms=["HS256"]
        )
        assert decoded["sub"] == user_sub
        assert decoded["iss"] == "attestation-exchange"
        assert decoded["device_integrity"] == "verified"
        assert decoded["app_integrity"] == "verified"
        assert "exp" in decoded
        assert "iat" in decoded
        # Verify expiry is in the future relative to iat
        assert decoded["exp"] > decoded["iat"]
