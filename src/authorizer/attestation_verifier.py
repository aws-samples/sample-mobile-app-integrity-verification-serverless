"""Attestation Token Verifier module.

This module verifies attestation JWTs minted by the Attestation Exchange Lambda
using the shared HMAC signing secret from Secrets Manager.
"""

import jwt


class AuthorizationError(Exception):
    """Raised when token verification or claim validation fails."""

    pass


def verify_token(token: str, signing_secret: str) -> dict:
    """Verify an attestation JWT minted by the Attestation Exchange Lambda.

    Decodes and verifies the HS256 signature using the shared signing secret,
    then validates that all required claims are present and correct.

    Steps:
        1. Decode and verify using HS256 with the shared signing secret
        2. Validate claims:
           - 'exp' has not passed
           - 'iss' == "attestation-exchange"
           - 'device_integrity' == "verified"
           - 'app_integrity' == "verified"

    Args:
        token: The attestation JWT string to verify.
        signing_secret: The HMAC secret used to verify the signature.

    Returns:
        Decoded token claims as a dictionary.

    Raises:
        AuthorizationError: If signature verification or claim validation fails.
    """
    try:
        decoded = jwt.decode(
            token,
            signing_secret,
            algorithms=["HS256"],
            options={"require": ["exp", "iss", "iat"]},
        )
    except jwt.ExpiredSignatureError:
        raise AuthorizationError("Attestation token has expired")
    except jwt.InvalidSignatureError:
        raise AuthorizationError("Attestation token has invalid signature")
    except jwt.DecodeError:
        raise AuthorizationError("Attestation token is malformed")
    except jwt.InvalidTokenError as e:
        raise AuthorizationError(f"Attestation token is invalid: {e}")

    # Validate issuer claim
    if decoded.get("iss") != "attestation-exchange":
        raise AuthorizationError(
            f"Invalid issuer: expected 'attestation-exchange', "
            f"got '{decoded.get('iss')}'"
        )

    # Validate device integrity claim
    if decoded.get("device_integrity") != "verified":
        raise AuthorizationError(
            f"Invalid device_integrity: expected 'verified', "
            f"got '{decoded.get('device_integrity')}'"
        )

    # Validate app integrity claim
    if decoded.get("app_integrity") != "verified":
        raise AuthorizationError(
            f"Invalid app_integrity: expected 'verified', "
            f"got '{decoded.get('app_integrity')}'"
        )

    return decoded
