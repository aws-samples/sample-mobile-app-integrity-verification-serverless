"""Unit tests for the Policy Builder module."""

import sys
import os

# Add src to path for imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "src"))

from authorizer.policy_builder import build_policy


class TestBuildPolicyAllow:
    """Tests for Allow policy generation."""

    def test_allow_policy_structure(self):
        """Allow policy has correct principalId, policyDocument, and wildcard resource."""
        context = {"user_sub": "abc-123", "attestation_verified": "true"}
        result = build_policy("abc-123", "Allow", "arn:aws:execute-api:us-east-1:123:api/stage/GET/protected", context)

        assert result["principalId"] == "abc-123"
        assert result["policyDocument"]["Version"] == "2012-10-17"
        stmt = result["policyDocument"]["Statement"][0]
        assert stmt["Action"] == "execute-api:Invoke"
        assert stmt["Effect"] == "Allow"
        # Allow policy uses wildcard resource for caching across all methods/paths
        assert stmt["Resource"] == "arn:aws:execute-api:us-east-1:123:api/stage/*"
        assert result["context"] == context

    def test_allow_without_context(self):
        """Allow policy without context does not include context key."""
        result = build_policy("abc-123", "Allow", "arn:aws:execute-api:us-east-1:123:api/stage/GET/protected")

        assert result["principalId"] == "abc-123"
        assert "context" not in result

    def test_allow_with_none_context(self):
        """Allow policy with explicit None context does not include context key."""
        result = build_policy("abc-123", "Allow", "arn:aws:execute-api:us-east-1:123:api/stage/GET/protected", None)

        assert "context" not in result

    def test_allow_transforms_resource_to_wildcard(self):
        """Allow policy transforms resource ARN to wildcard stage/* format."""
        resource = "arn:aws:execute-api:us-east-1:123456789012:abc123/dev/GET/protected"
        result = build_policy("user-sub", "Allow", resource)

        stmt = result["policyDocument"]["Statement"][0]
        assert stmt["Resource"] == "arn:aws:execute-api:us-east-1:123456789012:abc123/dev/*"

    def test_allow_transforms_nested_resource_path(self):
        """Allow policy correctly wildcards deeply nested resource paths."""
        resource = "arn:aws:execute-api:us-east-1:123:api/prod/POST/api/v1/users"
        result = build_policy("user-sub", "Allow", resource)

        stmt = result["policyDocument"]["Statement"][0]
        assert stmt["Resource"] == "arn:aws:execute-api:us-east-1:123:api/prod/*"


class TestBuildPolicyDeny:
    """Tests for Deny policy generation."""

    def test_deny_policy_sets_unauthorized_principal(self):
        """Deny policy overrides principalId to 'unauthorized'."""
        result = build_policy("some-user-sub", "Deny", "arn:aws:execute-api:us-east-1:123:api/stage/GET/protected")

        assert result["principalId"] == "unauthorized"

    def test_deny_policy_preserves_specific_resource(self):
        """Deny policy preserves specific resource ARN (no wildcard transformation)."""
        result = build_policy("ignored", "Deny", "arn:aws:execute-api:us-east-1:123:api/stage/GET/protected")

        assert result["policyDocument"]["Version"] == "2012-10-17"
        stmt = result["policyDocument"]["Statement"][0]
        assert stmt["Action"] == "execute-api:Invoke"
        assert stmt["Effect"] == "Deny"
        assert stmt["Resource"] == "arn:aws:execute-api:us-east-1:123:api/stage/GET/protected"

    def test_deny_policy_ignores_context(self):
        """Deny policy does not include context even if provided."""
        context = {"user_sub": "abc-123", "attestation_verified": "true"}
        result = build_policy("user", "Deny", "arn:aws:execute-api:us-east-1:123:api/stage/GET/protected", context)

        assert result["principalId"] == "unauthorized"
        assert "context" not in result
