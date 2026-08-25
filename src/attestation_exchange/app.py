"""Attestation Exchange Lambda handler.

POST /attest endpoint that receives a Google Play Integrity token,
verifies it, and returns a short-lived attestation JWT.
"""

import json
import os

import boto3
from aws_lambda_powertools import Logger

try:
    # Lambda runtime (flat deployment package)
    import play_integrity
    import token_issuer
    import cognito_verifier
except ImportError:
    # Local/test imports (package structure)
    from attestation_exchange import play_integrity, token_issuer, cognito_verifier

logger = Logger()

# Supported platforms for attestation requests
SUPPORTED_PLATFORMS = {"android", "ios"}

# Module-level cache for the signing secret
_signing_secret_cache: str | None = None


def _get_signing_secret() -> str:
    """Retrieve the signing secret from Secrets Manager, using module-level cache."""
    global _signing_secret_cache
    if _signing_secret_cache is not None:
        return _signing_secret_cache

    secret_arn = os.environ["SIGNING_SECRET_ARN"]
    client = boto3.client("secretsmanager")
    response = client.get_secret_value(SecretId=secret_arn)
    _signing_secret_cache = response["SecretString"]
    return _signing_secret_cache


@logger.inject_lambda_context
def lambda_handler(event: dict, context) -> dict:
    """POST /attest endpoint handler.

    Receives a Play Integrity token and Cognito access token,
    verifies integrity, and returns a short-lived attestation JWT.

    Args:
        event: API Gateway proxy event with body containing
               integrity_token and platform fields.
        context: Lambda context (unused).

    Returns:
        API Gateway proxy response dict with statusCode and body.
    """
    # Step 1: Parse request body
    body_str = event.get("body")
    if not body_str:
        return {
            "statusCode": 400,
            "body": json.dumps({"error": "Request body is required"}),
        }

    try:
        body = json.loads(body_str)
    except (json.JSONDecodeError, TypeError):
        return {
            "statusCode": 400,
            "body": json.dumps({"error": "Invalid JSON in request body"}),
        }

    # Step 2: Validate required fields
    integrity_token = body.get("integrity_token")
    if not integrity_token:
        return {
            "statusCode": 400,
            "body": json.dumps({"error": "integrity_token is required"}),
        }

    platform = body.get("platform", "android")

    # Validate platform value
    if platform not in SUPPORTED_PLATFORMS:
        return {
            "statusCode": 400,
            "body": json.dumps({"error": f"Unsupported platform: {platform}. Must be one of: android, ios"}),
        }

    # Step 3: Extract and validate Cognito token from Authorization header
    headers = event.get("headers") or {}
    authorization = headers.get("Authorization") or headers.get("authorization") or ""

    if not authorization:
        return {
            "statusCode": 401,
            "body": json.dumps({"error": "Unauthorized"}),
        }

    # Extract Bearer token
    if not authorization.startswith("Bearer "):
        return {
            "statusCode": 401,
            "body": json.dumps({"error": "Unauthorized"}),
        }
    token = authorization[len("Bearer "):]

    # Verify Cognito token using JWKS
    try:
        user_pool_id = os.environ.get("COGNITO_USER_POOL_ID", "")
        app_client_id = os.environ.get("COGNITO_APP_CLIENT_ID", "")
        cognito_region = os.environ.get("COGNITO_REGION", "us-east-1")

        claims = cognito_verifier.verify_token(
            token=token,
            user_pool_id=user_pool_id,
            app_client_id=app_client_id,
            region=cognito_region,
        )
        user_sub = claims["sub"]
    except Exception:
        return {
            "statusCode": 401,
            "body": json.dumps({"error": "Unauthorized"}),
        }

    # Step 4: Verify Play Integrity token (demo - always passes)
    nonce = body.get("nonce", "")
    expected_package_name = os.environ.get("EXPECTED_PACKAGE_NAME", "com.example.app")

    try:
        play_integrity.verify_token(
            integrity_token,
            expected_nonce=nonce,
            expected_package_name=expected_package_name,
        )
    except Exception as e:
        if hasattr(e, 'reason'):
            # AttestationVerificationError from play_integrity module
            return {
                "statusCode": 403,
                "body": json.dumps({"error": "Attestation verification failed", "reason": e.reason}),
            }
        logger.exception("Unexpected error during Play Integrity verification")
        return {
            "statusCode": 500,
            "body": json.dumps({"error": "Internal server error"}),
        }

    # Step 5: Retrieve signing secret from Secrets Manager
    try:
        signing_secret = _get_signing_secret()
    except Exception:
        logger.exception("Failed to retrieve signing secret")
        return {
            "statusCode": 500,
            "body": json.dumps({"error": "Internal server error"}),
        }

    # Step 6: Mint attestation JWT
    ttl_minutes = int(os.environ.get("TOKEN_TTL_MINUTES", "10"))

    try:
        attestation_token = token_issuer.mint_attestation_jwt(
            user_sub=user_sub,
            signing_secret=signing_secret,
            ttl_minutes=ttl_minutes,
        )
    except ValueError as e:
        logger.error("Token minting configuration error: %s", str(e))
        return {
            "statusCode": 500,
            "body": json.dumps({"error": "Internal server error"}),
        }

    # Step 7: Return success response
    expires_in = ttl_minutes * 60

    return {
        "statusCode": 200,
        "body": json.dumps({
            "attestation_token": attestation_token,
            "expires_in": expires_in,
        }),
    }
