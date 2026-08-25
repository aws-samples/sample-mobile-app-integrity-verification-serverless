"""Bug Condition Exploration Property Tests.

These tests exercise the UNFIXED code to confirm bugs exist.
They encode the EXPECTED (correct) behavior — meaning they WILL FAIL
on the current unfixed code, thereby proving the bugs are real.

**Validates: Requirements 1.2, 1.3, 1.4, 1.8, 1.11**

DO NOT fix these tests or the code when they fail.
Failure = bug confirmed = success for exploration.
"""

import json
import os
import sys
from unittest.mock import patch, MagicMock

import pytest
from hypothesis import given, settings, assume, HealthCheck
from hypothesis import strategies as st

# Ensure source paths are available
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "src"))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "src", "attestation_exchange"))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "src", "authorizer"))

import jwt as pyjwt

from attestation_exchange.play_integrity import evaluate_verdict, AttestationVerificationError
from authorizer.policy_builder import build_policy


# ---------------------------------------------------------------------------
# Strategies
# ---------------------------------------------------------------------------

# Strategy for arbitrary user sub claims (simulating token forgery)
arbitrary_sub = st.text(
    alphabet=st.characters(whitelist_categories=("L", "N", "P")),
    min_size=1,
    max_size=64,
)

# Strategy for platform strings that are NOT android or ios
invalid_platforms = st.text(min_size=1, max_size=30).filter(
    lambda p: p.lower() not in ("android", "ios")
)

# Strategy for nonces that definitely differ from each other
nonce_strategy = st.text(
    alphabet=st.characters(whitelist_categories=("L", "N")),
    min_size=4,
    max_size=32,
)

# Strategy for package names that differ from expected
wrong_package_strategy = st.text(
    alphabet=st.characters(whitelist_categories=("L", "N", "P")),
    min_size=1,
    max_size=50,
).filter(lambda p: p != "com.example.app")

# Strategy for API Gateway methodArn-like strings
method_arn_strategy = st.from_regex(
    r"arn:aws:execute-api:us-east-1:[0-9]{12}:[a-z0-9]+/(dev|prod|stage)/(GET|POST|PUT|DELETE)/[a-z]+",
    fullmatch=True,
)


# ---------------------------------------------------------------------------
# Test 1a: Forged Cognito JWT accepted at /attest
# ---------------------------------------------------------------------------


class TestForgedCognitoJWT:
    """Test 1a: Forged JWT with arbitrary sub should be rejected (401).

    On unfixed code, _extract_cognito_sub() uses verify_signature=False,
    so ANY JWT (even unsigned/forged) will be accepted. The test asserts
    that forged JWTs should produce a 401 — this will FAIL on unfixed code.
    """

    @given(sub_claim=arbitrary_sub)
    @settings(max_examples=50, deadline=None, suppress_health_check=[HealthCheck.function_scoped_fixture])
    def test_forged_jwt_returns_401(self, sub_claim, monkeypatch):
        """**Validates: Requirements 1.2**

        A JWT crafted with an arbitrary sub claim and no valid signature
        SHOULD be rejected with 401 at the /attest endpoint.
        """
        # Set required env vars
        monkeypatch.setenv("SIGNING_SECRET_ARN", "arn:aws:secretsmanager:us-east-1:123456789012:secret:test")
        monkeypatch.setenv("TOKEN_TTL_MINUTES", "10")
        monkeypatch.setenv("DEMO_MODE", "true")

        # Craft a forged JWT — signed with an arbitrary secret (not the real one)
        forged_token = pyjwt.encode(  # nosemgrep: python.jwt.security.jwt-python-hardcoded-secret
            {"sub": sub_claim, "token_use": "access", "iss": "https://fake.issuer"},
            "attacker-secret-key",
            algorithm="HS256",
        )

        event = {
            "body": json.dumps({
                "integrity_token": "valid-token-placeholder",
                "platform": "android",
            }),
            "headers": {
                "Authorization": f"Bearer {forged_token}",
            },
        }

        # Import fresh to avoid caching issues
        from attestation_exchange import app as attest_app

        # Mock secrets manager to avoid real AWS calls
        with patch.object(attest_app, "_get_signing_secret", return_value="test-secret"):
            result = attest_app.lambda_handler(event, None)

        # Expected: 401 because the JWT signature is not verified against Cognito JWKS
        # WILL FAIL on unfixed code because _extract_cognito_sub uses verify_signature=False
        assert result["statusCode"] == 401, (
            f"Forged JWT with sub='{sub_claim}' was ACCEPTED (status {result['statusCode']}). "
            f"Expected 401 rejection. Bug confirmed: signature not verified."
        )


# ---------------------------------------------------------------------------
# Test 1b: Play Integrity replay — mismatched nonce
# ---------------------------------------------------------------------------


class TestPlayIntegrityReplay:
    """Test 1b: Verdict with mismatched nonce should raise AttestationVerificationError.

    On unfixed code, evaluate_verdict() does NOT check requestDetails.nonce,
    so replayed tokens with wrong nonces pass validation.
    """

    @given(
        verdict_nonce=nonce_strategy,
        expected_nonce=nonce_strategy,
    )
    @settings(max_examples=50, deadline=None)
    def test_mismatched_nonce_raises_error(self, verdict_nonce, expected_nonce):
        """**Validates: Requirements 1.3**

        A Play Integrity verdict whose nonce does NOT match the expected
        nonce SHOULD raise AttestationVerificationError.
        """
        # Ensure nonces are actually different
        assume(verdict_nonce != expected_nonce)

        verdict = {
            "appIntegrity": {
                "appRecognitionVerdict": "PLAY_RECOGNIZED",
            },
            "deviceIntegrity": {
                "deviceRecognitionVerdict": ["MEETS_DEVICE_INTEGRITY"],
            },
            "requestDetails": {
                "requestPackageName": "com.example.app",
                "nonce": verdict_nonce,
                "timestampMillis": "1234567890",
            },
        }

        # Expected: should raise because nonce doesn't match
        # WILL FAIL on unfixed code because nonce is not checked
        with pytest.raises(AttestationVerificationError):
            evaluate_verdict(verdict, expected_nonce, "com.example.app")


# ---------------------------------------------------------------------------
# Test 1c: Package name spoofing
# ---------------------------------------------------------------------------


class TestPackageNameSpoofing:
    """Test 1c: Verdict with wrong package name should raise AttestationVerificationError.

    On unfixed code, evaluate_verdict() does NOT check requestDetails.requestPackageName,
    so verdicts from spoofed/modified apps pass validation.
    """

    @given(wrong_package=wrong_package_strategy)
    @settings(max_examples=50, deadline=None)
    def test_wrong_package_name_raises_error(self, wrong_package):
        """**Validates: Requirements 1.4**

        A Play Integrity verdict whose requestPackageName does NOT match
        the expected package SHOULD raise AttestationVerificationError.
        """
        verdict = {
            "appIntegrity": {
                "appRecognitionVerdict": "PLAY_RECOGNIZED",
            },
            "deviceIntegrity": {
                "deviceRecognitionVerdict": ["MEETS_DEVICE_INTEGRITY"],
            },
            "requestDetails": {
                "requestPackageName": wrong_package,
                "nonce": "valid-nonce",
                "timestampMillis": "1234567890",
            },
        }

        # Expected: should raise because package name doesn't match expected
        # WILL FAIL on unfixed code because package name is not checked
        with pytest.raises(AttestationVerificationError):
            evaluate_verdict(verdict, "valid-nonce", "com.example.app")


# ---------------------------------------------------------------------------
# Test 1d: Invalid platform accepted
# ---------------------------------------------------------------------------


class TestInvalidPlatformAccepted:
    """Test 1d: Invalid platform values should return 400.

    On unfixed code, the platform field is not validated — any value
    (including 'windows', random strings) is accepted without error.
    """

    @given(invalid_platform=invalid_platforms)
    @settings(max_examples=50, deadline=None, suppress_health_check=[HealthCheck.function_scoped_fixture])
    def test_invalid_platform_returns_400(self, invalid_platform, monkeypatch):
        """**Validates: Requirements 1.11**

        A request with an unsupported platform value SHOULD return 400.
        """
        monkeypatch.setenv("SIGNING_SECRET_ARN", "arn:aws:secretsmanager:us-east-1:123456789012:secret:test")
        monkeypatch.setenv("TOKEN_TTL_MINUTES", "10")
        monkeypatch.setenv("DEMO_MODE", "true")

        # Use a valid-looking token (doesn't matter since platform should be validated first)
        token = pyjwt.encode(  # nosemgrep: python.jwt.security.jwt-python-hardcoded-secret
            {"sub": "user-123", "token_use": "access"},
            "some-key",
            algorithm="HS256",
        )

        event = {
            "body": json.dumps({
                "integrity_token": "valid-token",
                "platform": invalid_platform,
            }),
            "headers": {
                "Authorization": f"Bearer {token}",
            },
        }

        from attestation_exchange import app as attest_app

        with patch.object(attest_app, "_get_signing_secret", return_value="test-secret"):
            result = attest_app.lambda_handler(event, None)

        # Expected: 400 because platform is not in {"android", "ios"}
        # WILL FAIL on unfixed code because platform is not validated
        assert result["statusCode"] == 400, (
            f"Invalid platform '{invalid_platform}' was ACCEPTED (status {result['statusCode']}). "
            f"Expected 400 rejection. Bug confirmed: platform not validated."
        )


# ---------------------------------------------------------------------------
# Test 1e: Policy builder uses specific resource for Allow
# ---------------------------------------------------------------------------


class TestPolicyBuilderWildcard:
    """Test 1e: Allow policy should use wildcard resource for caching.

    On unfixed code, build_policy() uses the exact methodArn as the resource
    for Allow policies, preventing authorizer cache reuse across methods.
    """

    @given(method_arn=method_arn_strategy)
    @settings(max_examples=50, deadline=None)
    def test_allow_policy_uses_wildcard_resource(self, method_arn):
        """**Validates: Requirements 1.8**

        When building an Allow policy, the resource SHOULD use a wildcard
        (stage/*) instead of the specific methodArn to enable authorizer caching.
        """
        result = build_policy(
            principal_id="user-123",
            effect="Allow",
            resource=method_arn,
            context={"user_sub": "user-123"},
        )

        actual_resource = result["policyDocument"]["Statement"][0]["Resource"]

        # Extract base ARN up to stage and expect wildcard
        # e.g., "arn:aws:execute-api:us-east-1:123:api/dev/GET/resource"
        # should become "arn:aws:execute-api:us-east-1:123:api/dev/*"
        parts = method_arn.split("/")
        # ARN format: arn:aws:execute-api:region:account:api-id/stage/method/resource
        expected_wildcard = parts[0] + "/" + parts[1] + "/*"

        assert actual_resource == expected_wildcard, (
            f"Allow policy uses specific resource '{actual_resource}' instead of "
            f"wildcard '{expected_wildcard}'. Bug confirmed: wildcard not applied."
        )
