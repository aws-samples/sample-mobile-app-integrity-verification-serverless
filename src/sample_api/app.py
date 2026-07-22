"""Sample API Lambda - Protected endpoint demonstrating the attestation pattern."""

import json
import datetime


def lambda_handler(event: dict, context) -> dict:
    """GET /protected endpoint handler.

    Returns a success response confirming both identity and integrity
    verification, including user information from the authorizer context.
    """
    authorizer_context = event.get("requestContext", {}).get("authorizer", {})
    user_sub = authorizer_context.get("user_sub", "unknown")
    attestation_verified = authorizer_context.get("attestation_verified", "false")

    return {
        "statusCode": 200,
        "headers": {
            "Content-Type": "application/json",
        },
        "body": json.dumps({
            "message": "Identity and integrity verified successfully",
            "user_sub": user_sub,
            "attestation_verified": attestation_verified == "true" or attestation_verified is True,
            "timestamp": datetime.datetime.now(datetime.UTC).isoformat().replace("+00:00", "Z"),
        }),
    }
