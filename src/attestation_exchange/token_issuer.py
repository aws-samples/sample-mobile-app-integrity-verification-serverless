"""Token Issuer module for minting attestation JWTs.

This module provides functionality to create short-lived HS256-signed JWTs
that attest to device and app integrity verification.
"""

import time

import jwt


def mint_attestation_jwt(user_sub: str, signing_secret: str, ttl_minutes: int) -> str:
    """Create a signed attestation JWT with HS256.

    Mints a short-lived JWT containing claims that attest the caller's device
    and application integrity have been verified via Play Integrity.

    Args:
        user_sub: The Cognito user identifier (sub claim).
        signing_secret: The HMAC secret used to sign the JWT.
        ttl_minutes: Token time-to-live in minutes. Must be in range [5, 15].

    Returns:
        A signed JWT string that can be verified with the same signing_secret.

    Raises:
        ValueError: If ttl_minutes is not in the range [5, 15].
    """
    if not isinstance(ttl_minutes, int) or ttl_minutes < 5 or ttl_minutes > 15:
        raise ValueError(
            f"ttl_minutes must be an integer in the range [5, 15], got {ttl_minutes}"
        )

    iat = int(time.time())
    exp = iat + (ttl_minutes * 60)

    claims = {
        "iss": "attestation-exchange",
        "sub": user_sub,
        "iat": iat,
        "exp": exp,
        "device_integrity": "verified",
        "app_integrity": "verified",
        "platform": "android",
    }

    token = jwt.encode(claims, signing_secret, algorithm="HS256")
    return token
