"""Shared pytest fixtures for serverless-mobile-api-attestation tests."""

import os
import sys
from unittest.mock import patch

import pytest

# Add src directories to path so Lambda modules can be imported directly
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src", "attestation_exchange"))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src", "authorizer"))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src", "sample_api"))


class FakeLambdaContext:
    """Minimal mock Lambda context for testing with Powertools Logger decorator."""

    function_name = "test-function"
    memory_limit_in_mb = 256
    invoked_function_arn = "arn:aws:lambda:us-east-1:123456789012:function:test-function"
    aws_request_id = "test-request-id-00000000"


def _build_lambda_context_model_safe(context):
    """Tolerant version of build_lambda_context_model that handles None context."""
    if context is None:
        context = FakeLambdaContext()
    from aws_lambda_powertools.logging.lambda_context import build_lambda_context_model as _original
    return _original(context)


@pytest.fixture(autouse=True)
def set_environment_variables(monkeypatch):
    """Set common environment variables used across Lambda functions."""
    monkeypatch.setenv("SIGNING_SECRET_ARN", "arn:aws:secretsmanager:us-east-1:123456789012:secret:test-secret-abc123")
    monkeypatch.setenv("TOKEN_TTL_MINUTES", "10")
    monkeypatch.setenv("DEMO_MODE", "true")
    monkeypatch.setenv("COGNITO_USER_POOL_ID", "us-east-1_TestPool")
    monkeypatch.setenv("COGNITO_APP_CLIENT_ID", "test-app-client-id")
    monkeypatch.setenv("COGNITO_REGION", "us-east-1")
    monkeypatch.setenv("AWS_DEFAULT_REGION", "us-east-1")


@pytest.fixture(autouse=True)
def patch_lambda_context_model():
    """Patch Powertools build_lambda_context_model to handle None context in tests."""
    with patch(
        "aws_lambda_powertools.logging.logger.build_lambda_context_model",
        side_effect=_build_lambda_context_model_safe,
    ):
        yield


@pytest.fixture
def signing_secret():
    """Provide a test signing secret for HS256 JWT operations."""
    return "test-signing-secret-key-for-hmac-256-operations"


@pytest.fixture
def sample_user_sub():
    """Provide a sample Cognito user sub for testing."""
    return "a1b2c3d4-e5f6-7890-abcd-ef1234567890"
