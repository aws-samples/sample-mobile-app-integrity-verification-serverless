"""Cognito access token verification using JWKS.

Verifies RS256-signed Cognito access tokens by fetching and caching
the JSON Web Key Set (JWKS) from the Cognito well-known endpoint.
"""

import jwt
import requests
from jwt.algorithms import RSAAlgorithm


class AuthorizationError(Exception):
    """Raised when token verification or claim validation fails."""

    pass


# Module-level JWKS cache keyed by issuer URL.
# Persists across warm Lambda invocations to avoid repeated network calls.
_jwks_cache: dict = {}


def _get_jwks(issuer_url: str) -> list:
    """Fetch JWKS keys from the Cognito well-known endpoint, with caching.

    Args:
        issuer_url: The Cognito issuer URL (e.g. https://cognito-idp.us-east-1.amazonaws.com/us-east-1_abc123)

    Returns:
        List of JWK key dicts from the JWKS endpoint.

    Raises:
        AuthorizationError: If the JWKS endpoint cannot be reached or returns invalid data.
    """
    if issuer_url in _jwks_cache:
        return _jwks_cache[issuer_url]

    jwks_url = f"{issuer_url}/.well-known/jwks.json"
    try:
        response = requests.get(jwks_url, timeout=5)
        response.raise_for_status()
        jwks_data = response.json()
    except (requests.RequestException, ValueError) as e:
        raise AuthorizationError(f"Failed to fetch JWKS from {jwks_url}: {e}")

    keys = jwks_data.get("keys", [])
    if not keys:
        raise AuthorizationError("JWKS endpoint returned no keys")

    _jwks_cache[issuer_url] = keys
    return keys


def _find_key_by_kid(keys: list, kid: str) -> dict:
    """Find a JWK matching the given key ID.

    Args:
        keys: List of JWK key dicts.
        kid: The key ID to match.

    Returns:
        The matching JWK dict.

    Raises:
        AuthorizationError: If no key matches the kid.
    """
    for key in keys:
        if key.get("kid") == kid:
            return key
    raise AuthorizationError(f"No matching key found for kid: {kid}")


def verify_token(token: str, user_pool_id: str, app_client_id: str, region: str) -> dict:
    """Verify a Cognito access token using JWKS.

    Steps:
        1. Decode header to get 'kid' (key ID)
        2. Fetch JWKS from Cognito well-known endpoint (cached at module level)
        3. Find matching key by 'kid'
        4. Verify RS256 signature
        5. Validate claims: exp, iss, token_use, client_id

    Args:
        token: The JWT access token string.
        user_pool_id: The Cognito User Pool ID.
        app_client_id: The Cognito App Client ID.
        region: The AWS region (e.g. "us-east-1").

    Returns:
        Decoded token claims dict (sub, token_use, client_id, exp, etc.)

    Raises:
        AuthorizationError: If any validation step fails.
    """
    issuer_url = f"https://cognito-idp.{region}.amazonaws.com/{user_pool_id}"

    # Step 1: Decode JWT header to extract kid
    try:
        unverified_header = jwt.get_unverified_header(token)
    except jwt.exceptions.DecodeError as e:
        raise AuthorizationError(f"Invalid token header: {e}")

    kid = unverified_header.get("kid")
    if not kid:
        raise AuthorizationError("Token header missing 'kid' field")

    # Step 2: Fetch JWKS (cached)
    keys = _get_jwks(issuer_url)

    # Step 3: Find matching key by kid
    matching_key = _find_key_by_kid(keys, kid)

    # Step 4: Construct RSA public key from JWK
    try:
        public_key = RSAAlgorithm.from_jwk(matching_key)
    except Exception as e:
        raise AuthorizationError(f"Failed to construct public key from JWK: {e}")

    # Step 5: Verify signature and decode claims
    try:
        decoded = jwt.decode(
            token,
            public_key,
            algorithms=["RS256"],
            issuer=issuer_url,
            options={
                "verify_exp": True,
                "verify_iss": True,
                "require": ["exp", "iss", "token_use", "client_id", "sub"],
            },
        )
    except jwt.ExpiredSignatureError:
        raise AuthorizationError("Token has expired")
    except jwt.InvalidIssuerError:
        raise AuthorizationError(
            f"Invalid token issuer. Expected: {issuer_url}"
        )
    except jwt.exceptions.DecodeError as e:
        raise AuthorizationError(f"Token signature verification failed: {e}")
    except jwt.exceptions.InvalidTokenError as e:
        raise AuthorizationError(f"Token validation failed: {e}")

    # Step 6: Validate token_use claim
    if decoded.get("token_use") != "access":
        raise AuthorizationError(
            f"Invalid token_use claim. Expected 'access', got '{decoded.get('token_use')}'"
        )

    # Step 7: Validate client_id claim
    if decoded.get("client_id") != app_client_id:
        raise AuthorizationError(
            f"Invalid client_id claim. Expected '{app_client_id}', got '{decoded.get('client_id')}'"
        )

    return decoded
