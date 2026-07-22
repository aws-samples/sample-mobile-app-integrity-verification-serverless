"""Lambda Authorizer handler for dual-token validation.

REQUEST-type Lambda authorizer that validates both a Cognito access token
(Authorization header) and an attestation JWT (X-Attestation-Token header)
before granting API access.
"""

import os

import boto3
from aws_lambda_powertools import Logger

import attestation_verifier
import cognito_verifier
from policy_builder import build_policy

logger = Logger()

# Module-level cache for the signing secret (persists across warm invocations)
_signing_secret_cache: str = None


def _get_signing_secret() -> str:
    """Retrieve the HMAC signing secret from Secrets Manager, with caching."""
    global _signing_secret_cache
    if _signing_secret_cache is not None:
        return _signing_secret_cache

    secret_arn = os.environ["SIGNING_SECRET_ARN"]
    client = boto3.client("secretsmanager")
    response = client.get_secret_value(SecretId=secret_arn)
    _signing_secret_cache = response["SecretString"]
    return _signing_secret_cache


def _get_header(headers: dict, header_name: str) -> str:
    """Case-insensitive header lookup.

    Args:
        headers: The headers dict from the authorizer event.
        header_name: The header name to look up (case-insensitive).

    Returns:
        The header value, or None if not found.
    """
    if not headers:
        return None
    for key, value in headers.items():
        if key.lower() == header_name.lower():
            return value
    return None


@logger.inject_lambda_context
def lambda_handler(event: dict, context) -> dict:
    """REQUEST-type Lambda authorizer. Validates both Cognito and attestation tokens.

    Args:
        event: API Gateway REQUEST authorizer event containing headers and methodArn.
        context: Lambda context object (unused).

    Returns:
        IAM policy document (Allow or Deny).
    """
    method_arn = event.get("methodArn", "")
    logger.info("Authorizer invoked", extra={"event_keys": list(event.keys())})
    logger.info("Headers present", extra={"header_keys": list((event.get('headers') or {}).keys())})

    try:
        headers = event.get("headers", {})

        # Extract Authorization header and strip "Bearer " prefix
        auth_header = _get_header(headers, "Authorization")
        if not auth_header:
            logger.warning("DENY: No Authorization header found")
            return build_policy("unauthorized", "Deny", method_arn)

        cognito_token = auth_header
        if cognito_token.startswith("Bearer "):
            cognito_token = cognito_token[7:]
        elif cognito_token.startswith("bearer "):
            cognito_token = cognito_token[7:]

        # Extract X-Attestation-Token header
        attestation_token = _get_header(headers, "X-Attestation-Token")
        if not attestation_token:
            logger.warning("DENY: No X-Attestation-Token header found")
            return build_policy("unauthorized", "Deny", method_arn)

        logger.info("Both headers present, verifying tokens")

        # Retrieve signing secret from Secrets Manager (cached)
        signing_secret = _get_signing_secret()
        logger.info("Retrieved signing secret from Secrets Manager")

        # Get Cognito configuration from environment variables
        user_pool_id = os.environ["COGNITO_USER_POOL_ID"]
        app_client_id = os.environ["COGNITO_APP_CLIENT_ID"]
        region = os.environ["COGNITO_REGION"]

        # Verify Cognito access token
        logger.info("Verifying Cognito token")
        cognito_claims = cognito_verifier.verify_token(
            token=cognito_token,
            user_pool_id=user_pool_id,
            app_client_id=app_client_id,
            region=region,
        )
        logger.info("Cognito token valid")

        # Verify attestation JWT
        logger.info("Verifying attestation token")
        attestation_verifier.verify_token(
            token=attestation_token,
            signing_secret=signing_secret,
        )
        logger.info("Attestation token valid")

        # Both tokens valid - return Allow policy with context
        user_sub = cognito_claims["sub"]
        policy_context = {
            "user_sub": user_sub,
            "attestation_verified": "true",
        }

        logger.info("ALLOW: Authorization successful")
        return build_policy(user_sub, "Allow", method_arn, context=policy_context)

    except Exception as e:
        # Any unexpected error results in Deny
        logger.exception("DENY: Exception during authorization")
        return build_policy("unauthorized", "Deny", method_arn)
