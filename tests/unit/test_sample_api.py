"""Unit tests for Sample API Lambda handler."""

import json
import datetime
from unittest.mock import patch

import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "src", "sample_api"))

from app import lambda_handler


class TestSampleApiHandler:
    """Tests for the Sample API Lambda handler."""

    def _make_event(self, user_sub="test-user-123", attestation_verified="true"):
        """Create a mock API Gateway proxy event with authorizer context."""
        return {
            "requestContext": {
                "authorizer": {
                    "user_sub": user_sub,
                    "attestation_verified": attestation_verified,
                }
            }
        }

    def test_returns_200_with_valid_authorizer_context(self):
        """WHEN invoked with valid authorizer context, returns HTTP 200."""
        event = self._make_event()
        result = lambda_handler(event, None)

        assert result["statusCode"] == 200

    def test_response_contains_success_message(self):
        """Response message confirms both identity and integrity verification."""
        event = self._make_event()
        result = lambda_handler(event, None)
        body = json.loads(result["body"])

        assert body["message"] == "Identity and integrity verified successfully"

    def test_response_includes_user_sub(self):
        """Response includes user_sub from authorizer context."""
        event = self._make_event(user_sub="abc-def-456")
        result = lambda_handler(event, None)
        body = json.loads(result["body"])

        assert body["user_sub"] == "abc-def-456"

    def test_response_includes_attestation_verified_true(self):
        """Response includes attestation_verified as boolean true."""
        event = self._make_event(attestation_verified="true")
        result = lambda_handler(event, None)
        body = json.loads(result["body"])

        assert body["attestation_verified"] is True

    def test_response_includes_iso8601_timestamp(self):
        """Response includes an ISO 8601 timestamp ending with Z."""
        event = self._make_event()
        result = lambda_handler(event, None)
        body = json.loads(result["body"])

        assert "timestamp" in body
        assert body["timestamp"].endswith("Z")
        # Verify it's a valid ISO 8601 timestamp
        ts = body["timestamp"].rstrip("Z")
        datetime.datetime.fromisoformat(ts)

    def test_response_content_type_is_json(self):
        """Response has Content-Type application/json header."""
        event = self._make_event()
        result = lambda_handler(event, None)

        assert result["headers"]["Content-Type"] == "application/json"

    def test_attestation_verified_false_when_not_verified(self):
        """attestation_verified is False when authorizer context says false."""
        event = self._make_event(attestation_verified="false")
        result = lambda_handler(event, None)
        body = json.loads(result["body"])

        assert body["attestation_verified"] is False
