"""Property-based tests for the Lambda Authorizer handler.

**Validates: Requirements 4.2, 4.3, 4.4, 4.5, 4.6, 4.7**

Property 3: Authorizer Deny on Invalid or Missing Tokens
For any API Gateway REQUEST event where either the Authorization header is missing,
the X-Attestation-Token header is missing, the Cognito token has an invalid signature,
the Cognito token is expired, the attestation JWT has an invalid signature, or the
attestation JWT is expired, the Lambda_Authorizer SHALL return a Deny policy with
principalId "unauthorized".
"""

import importlib
import importlib.util
import os
import sys
from unittest.mock import patch, MagicMock

import pytest
from hypothesis import given, settings, assume, HealthCheck
from hypothesis import strategies as st

# Ensure authorizer source is importable
_authorizer_src = os.path.join(os.path.dirname(__file__), "..", "..", "src", "authorizer")
sys.path.insert(0, _authorizer_src)

from attestation_verifier import AuthorizationError as AttestAuthError
from cognito_verifier import AuthorizationError as CognitoAuthError


def _get_authorizer_app():
    """Load the authorizer app module explicitly to avoid name collision with sample_api/app.py.

    Python's module cache (sys.modules) may already have 'app' pointing to sample_api/app.py
    if other tests ran first. We use importlib to load the specific file we need.
    """
    module_name = "authorizer_app_module"
    if module_name in sys.modules:
        return sys.modules[module_name]
    app_path = os.path.join(_authorizer_src, "app.py")
    spec = importlib.util.spec_from_file_location(module_name, app_path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = module
    spec.loader.exec_module(module)
    return module


# Load at module level so it's available to all tests
authorizer_app = _get_authorizer_app()


# --- Strategies ---

# Strategy for generating non-empty token-like strings
token_text = st.text(
    alphabet=st.characters(whitelist_categories=("L", "N")),
    min_size=1,
    max_size=100,
)

# Strategy for generating method ARNs using builds for efficiency
_account_ids = st.text(alphabet="0123456789", min_size=12, max_size=12)
_api_ids = st.text(alphabet="abcdefghijklmnopqrstuvwxyz0123456789", min_size=4, max_size=10)
_stage_names = st.sampled_from(["dev", "staging", "prod", "test"])
_resource_paths = st.text(alphabet="abcdefghijklmnopqrstuvwxyz", min_size=1, max_size=20)

method_arns = st.builds(
    lambda acct, api, stage, path: f"arn:aws:execute-api:us-east-1:{acct}:{api}/{stage}/GET/{path}",
    acct=_account_ids,
    api=_api_ids,
    stage=_stage_names,
    path=_resource_paths,
)

# Failure reason messages
failure_reasons = st.sampled_from([
    "Token has expired",
    "Token signature verification failed",
    "Invalid token header",
    "Token header missing 'kid' field",
    "Invalid token_use claim",
    "Invalid client_id claim",
    "Attestation token has expired",
    "Attestation token has invalid signature",
    "Invalid issuer",
    "Invalid device_integrity",
    "Invalid app_integrity",
])


def _build_event(method_arn, auth_header=None, attestation_header=None):
    """Build a REQUEST authorizer event with the given headers."""
    headers = {}
    if auth_header is not None:
        headers["Authorization"] = auth_header
    if attestation_header is not None:
        headers["X-Attestation-Token"] = attestation_header
    return {
        "type": "REQUEST",
        "methodArn": method_arn,
        "headers": headers,
    }


def _assert_deny_policy(result, method_arn):
    """Assert the result is a valid Deny policy with principalId 'unauthorized'."""
    assert result["principalId"] == "unauthorized"
    assert result["policyDocument"]["Version"] == "2012-10-17"
    stmt = result["policyDocument"]["Statement"][0]
    assert stmt["Action"] == "execute-api:Invoke"
    assert stmt["Effect"] == "Deny"
    assert stmt["Resource"] == method_arn


class TestProperty3MissingAuthorizationHeader:
    """Requirement 4.2: Missing Authorization header returns Deny."""

    @given(
        method_arn=method_arns,
        attestation_token=token_text,
    )
    @settings(max_examples=50, deadline=None)
    def test_missing_authorization_always_deny(self, method_arn, attestation_token):
        """**Validates: Requirements 4.2**

        For any REQUEST event where Authorization header is missing,
        the Lambda_Authorizer SHALL return a Deny policy with principalId 'unauthorized'.
        """
        # Clear the signing secret cache to avoid cross-test state
        authorizer_app._signing_secret_cache = None

        event = _build_event(
            method_arn=method_arn,
            auth_header=None,
            attestation_header=attestation_token,
        )

        result = authorizer_app.lambda_handler(event, None)
        _assert_deny_policy(result, method_arn)


class TestProperty3MissingAttestationHeader:
    """Requirement 4.3: Missing X-Attestation-Token header returns Deny."""

    @given(
        method_arn=method_arns,
        cognito_token=token_text,
    )
    @settings(max_examples=50, deadline=None)
    def test_missing_attestation_always_deny(self, method_arn, cognito_token):
        """**Validates: Requirements 4.3**

        For any REQUEST event where X-Attestation-Token header is missing,
        the Lambda_Authorizer SHALL return a Deny policy with principalId 'unauthorized'.
        """
        authorizer_app._signing_secret_cache = None

        event = _build_event(
            method_arn=method_arn,
            auth_header=f"Bearer {cognito_token}",
            attestation_header=None,
        )

        result = authorizer_app.lambda_handler(event, None)
        _assert_deny_policy(result, method_arn)


class TestProperty3InvalidCognitoSignature:
    """Requirement 4.4: Invalid Cognito token signature returns Deny."""

    @given(
        method_arn=method_arns,
        cognito_token=token_text,
        attestation_token=token_text,
    )
    @settings(max_examples=50, deadline=None)
    def test_invalid_cognito_signature_always_deny(
        self, method_arn, cognito_token, attestation_token
    ):
        """**Validates: Requirements 4.4**

        For any REQUEST event where the Cognito token has an invalid signature,
        the Lambda_Authorizer SHALL return a Deny policy with principalId 'unauthorized'.
        """
        authorizer_app._signing_secret_cache = "test-secret"  # nosec B105 - test fixture

        event = _build_event(
            method_arn=method_arn,
            auth_header=f"Bearer {cognito_token}",
            attestation_header=attestation_token,
        )

        with patch.object(
            authorizer_app, "_get_signing_secret", return_value="test-secret"  # nosec B105
        ), patch(
            "cognito_verifier.verify_token",
            side_effect=CognitoAuthError("Token signature verification failed"),
        ):
            result = authorizer_app.lambda_handler(event, None)

        _assert_deny_policy(result, method_arn)


class TestProperty3ExpiredCognitoToken:
    """Requirement 4.5: Expired Cognito token returns Deny."""

    @given(
        method_arn=method_arns,
        cognito_token=token_text,
        attestation_token=token_text,
    )
    @settings(max_examples=50, deadline=None)
    def test_expired_cognito_token_always_deny(
        self, method_arn, cognito_token, attestation_token
    ):
        """**Validates: Requirements 4.5**

        For any REQUEST event where the Cognito token is expired,
        the Lambda_Authorizer SHALL return a Deny policy with principalId 'unauthorized'.
        """
        authorizer_app._signing_secret_cache = "test-secret"  # nosec B105 - test fixture

        event = _build_event(
            method_arn=method_arn,
            auth_header=f"Bearer {cognito_token}",
            attestation_header=attestation_token,
        )

        with patch.object(
            authorizer_app, "_get_signing_secret", return_value="test-secret"  # nosec B105
        ), patch(
            "cognito_verifier.verify_token",
            side_effect=CognitoAuthError("Token has expired"),
        ):
            result = authorizer_app.lambda_handler(event, None)

        _assert_deny_policy(result, method_arn)


class TestProperty3InvalidAttestationSignature:
    """Requirement 4.6: Invalid attestation JWT signature returns Deny."""

    @given(
        method_arn=method_arns,
        cognito_token=token_text,
        attestation_token=token_text,
        user_sub=token_text,
    )
    @settings(max_examples=50, deadline=None)
    def test_invalid_attestation_signature_always_deny(
        self, method_arn, cognito_token, attestation_token, user_sub
    ):
        """**Validates: Requirements 4.6**

        For any REQUEST event where the attestation JWT has an invalid signature,
        the Lambda_Authorizer SHALL return a Deny policy with principalId 'unauthorized'.
        """
        authorizer_app._signing_secret_cache = "test-secret"  # nosec B105 - test fixture

        event = _build_event(
            method_arn=method_arn,
            auth_header=f"Bearer {cognito_token}",
            attestation_header=attestation_token,
        )

        with patch.object(
            authorizer_app, "_get_signing_secret", return_value="test-secret"  # nosec B105
        ), patch(
            "cognito_verifier.verify_token",
            return_value={"sub": user_sub, "token_use": "access"},
        ), patch(
            "attestation_verifier.verify_token",
            side_effect=AttestAuthError("Attestation token has invalid signature"),
        ):
            result = authorizer_app.lambda_handler(event, None)

        _assert_deny_policy(result, method_arn)


class TestProperty3ExpiredAttestationToken:
    """Requirement 4.7: Expired attestation JWT returns Deny."""

    @given(
        method_arn=method_arns,
        cognito_token=token_text,
        attestation_token=token_text,
        user_sub=token_text,
    )
    @settings(max_examples=50, deadline=None)
    def test_expired_attestation_token_always_deny(
        self, method_arn, cognito_token, attestation_token, user_sub
    ):
        """**Validates: Requirements 4.7**

        For any REQUEST event where the attestation JWT is expired,
        the Lambda_Authorizer SHALL return a Deny policy with principalId 'unauthorized'.
        """
        authorizer_app._signing_secret_cache = "test-secret"  # nosec B105 - test fixture

        event = _build_event(
            method_arn=method_arn,
            auth_header=f"Bearer {cognito_token}",
            attestation_header=attestation_token,
        )

        with patch.object(
            authorizer_app, "_get_signing_secret", return_value="test-secret"  # nosec B105
        ), patch(
            "cognito_verifier.verify_token",
            return_value={"sub": user_sub, "token_use": "access"},
        ), patch(
            "attestation_verifier.verify_token",
            side_effect=AttestAuthError("Attestation token has expired"),
        ):
            result = authorizer_app.lambda_handler(event, None)

        _assert_deny_policy(result, method_arn)


class TestProperty3CombinedInvalidScenarios:
    """Combined: Any failure scenario always produces Deny."""

    @given(
        method_arn=method_arns,
        cognito_token=token_text,
        attestation_token=token_text,
        failure_reason=failure_reasons,
        fails_on=st.sampled_from(["cognito", "attestation"]),
    )
    @settings(max_examples=100, deadline=None)
    def test_any_token_failure_always_deny(
        self, method_arn, cognito_token, attestation_token, failure_reason, fails_on
    ):
        """**Validates: Requirements 4.2, 4.3, 4.4, 4.5, 4.6, 4.7**

        For any REQUEST event where either token verification raises an error,
        the Lambda_Authorizer SHALL return a Deny policy with principalId 'unauthorized'.
        """
        authorizer_app._signing_secret_cache = "test-secret"  # nosec B105 - test fixture

        event = _build_event(
            method_arn=method_arn,
            auth_header=f"Bearer {cognito_token}",
            attestation_header=attestation_token,
        )

        if fails_on == "cognito":
            cognito_side_effect = CognitoAuthError(failure_reason)
            attestation_side_effect = None
        else:
            cognito_side_effect = None
            attestation_side_effect = AttestAuthError(failure_reason)

        cognito_return = {"sub": "test-user", "token_use": "access"}

        with patch.object(
            authorizer_app, "_get_signing_secret", return_value="test-secret"  # nosec B105
        ), patch(
            "cognito_verifier.verify_token",
            side_effect=cognito_side_effect if cognito_side_effect else None,
            return_value=cognito_return if not cognito_side_effect else None,
        ), patch(
            "attestation_verifier.verify_token",
            side_effect=attestation_side_effect if attestation_side_effect else None,
            return_value={"iss": "attestation-exchange"} if not attestation_side_effect else None,
        ):
            result = authorizer_app.lambda_handler(event, None)

        _assert_deny_policy(result, method_arn)


class TestProperty3BothHeadersMissing:
    """Both headers missing still returns Deny."""

    @given(method_arn=method_arns)
    @settings(max_examples=30, deadline=None)
    def test_both_headers_missing_always_deny(self, method_arn):
        """**Validates: Requirements 4.2, 4.3**

        For any REQUEST event where both Authorization and X-Attestation-Token
        headers are missing, the Lambda_Authorizer SHALL return a Deny policy.
        """
        authorizer_app._signing_secret_cache = None

        event = _build_event(
            method_arn=method_arn,
            auth_header=None,
            attestation_header=None,
        )

        result = authorizer_app.lambda_handler(event, None)
        _assert_deny_policy(result, method_arn)


# --- Property 4: Authorizer Allow with Context on Valid Tokens ---


# Strategy for generating Cognito sub values (UUID-like strings)
_sub_chars = "abcdef0123456789"
cognito_subs = st.text(alphabet=_sub_chars, min_size=8, max_size=36)


def _assert_allow_policy(result, method_arn, expected_sub):
    """Assert the result is a valid Allow policy with correct principalId and context.
    
    Note: After fix for requirement 2.8, Allow policies use wildcard resource (stage/*)
    for authorizer cache reuse across methods, rather than the specific methodArn.
    """
    assert result["principalId"] == expected_sub
    assert result["policyDocument"]["Version"] == "2012-10-17"
    stmt = result["policyDocument"]["Statement"][0]
    assert stmt["Action"] == "execute-api:Invoke"
    assert stmt["Effect"] == "Allow"
    # After fix 2.8: Allow policies use wildcard resource for cache reuse
    # Extract base ARN up to stage and verify wildcard is applied
    parts = method_arn.split("/")
    expected_wildcard = parts[0] + "/" + parts[1] + "/*"
    assert stmt["Resource"] == expected_wildcard
    # Verify context fields
    assert "context" in result
    assert result["context"]["user_sub"] == expected_sub
    assert result["context"]["attestation_verified"] == "true"


class TestProperty4AllowWithValidTokens:
    """Property 4: Authorizer Allow with Context on Valid Tokens.

    **Validates: Requirements 4.1, 4.8**

    For any API Gateway REQUEST event where both the Cognito access token and
    attestation JWT are valid, the Lambda_Authorizer SHALL return an Allow policy
    with principalId matching the Cognito sub, and context containing user_sub
    and attestation_verified fields.
    """

    @given(
        method_arn=method_arns,
        cognito_token=token_text,
        attestation_token=token_text,
        user_sub=cognito_subs,
    )
    @settings(max_examples=100, deadline=None, suppress_health_check=[HealthCheck.too_slow])
    def test_valid_tokens_always_allow_with_context(
        self, method_arn, cognito_token, attestation_token, user_sub
    ):
        """**Validates: Requirements 4.1, 4.8**

        For any REQUEST event where both the Cognito access token and attestation
        JWT are valid, the Lambda_Authorizer SHALL return an Allow policy with
        principalId matching the Cognito sub, and context containing user_sub and
        attestation_verified="true".
        """
        authorizer_app._signing_secret_cache = "test-secret"  # nosec B105 - test fixture

        event = _build_event(
            method_arn=method_arn,
            auth_header=f"Bearer {cognito_token}",
            attestation_header=attestation_token,
        )

        cognito_claims = {"sub": user_sub, "token_use": "access"}
        attestation_claims = {"iss": "attestation-exchange", "exp": 9999999999}

        with patch.object(
            authorizer_app, "_get_signing_secret", return_value="test-secret"  # nosec B105
        ), patch(
            "cognito_verifier.verify_token",
            return_value=cognito_claims,
        ), patch(
            "attestation_verifier.verify_token",
            return_value=attestation_claims,
        ):
            result = authorizer_app.lambda_handler(event, None)

        _assert_allow_policy(result, method_arn, user_sub)
