"""Play Integrity Verifier module (Demo Implementation).

This module simulates the verification of Google Play Integrity tokens.
In this demo implementation, it always returns a passing verdict without
making network calls to the Google Play Integrity API.

In a production implementation, this module would call the Google Play
Integrity API's decodeIntegrityToken endpoint to verify the token and
evaluate the verdict against required integrity thresholds.
"""

from aws_lambda_powertools import Logger

logger = Logger()


class AttestationVerificationError(Exception):
    """Raised when Play Integrity verification fails.

    Attributes:
        reason: A descriptive reason for the failure.
    """

    def __init__(self, reason: str) -> None:
        self.reason = reason
        super().__init__(reason)


def evaluate_verdict(verdict: dict, expected_nonce: str, expected_package_name: str) -> None:
    """Evaluate a Play Integrity verdict against required thresholds.

    Checks that the verdict meets minimum integrity requirements:
    - requestDetails.nonce must match expected_nonce
    - requestDetails.requestPackageName must match expected_package_name
    - appRecognitionVerdict must be "PLAY_RECOGNIZED"
    - deviceRecognitionVerdict must contain "MEETS_DEVICE_INTEGRITY"

    Args:
        verdict: The decoded Play Integrity verdict dictionary containing
            requestDetails, appIntegrity and deviceIntegrity fields.
        expected_nonce: The nonce value expected in the verdict's
            requestDetails to prevent replay attacks.
        expected_package_name: The expected Android package name to validate
            against the verdict's requestDetails.requestPackageName.

    Raises:
        AttestationVerificationError: If the verdict does not meet
            the required integrity thresholds, nonce does not match,
            or package name does not match.
    """
    # Validate nonce BEFORE app/device integrity checks
    request_details = verdict.get("requestDetails", {})
    verdict_nonce = request_details.get("nonce", "")

    if verdict_nonce != expected_nonce:
        raise AttestationVerificationError(
            "Nonce mismatch: verdict nonce does not match expected nonce"
        )

    # Validate package name BEFORE app/device integrity checks
    verdict_package_name = request_details.get("requestPackageName", "")

    if verdict_package_name != expected_package_name:
        raise AttestationVerificationError(
            f"Package name mismatch: expected '{expected_package_name}', "
            f"got '{verdict_package_name}'"
        )

    app_integrity = verdict.get("appIntegrity", {})
    app_recognition = app_integrity.get("appRecognitionVerdict", "")

    if app_recognition != "PLAY_RECOGNIZED":
        raise AttestationVerificationError(
            f"App integrity check failed: appRecognitionVerdict is "
            f"'{app_recognition}', expected 'PLAY_RECOGNIZED'"
        )

    device_integrity = verdict.get("deviceIntegrity", {})
    device_recognition = device_integrity.get("deviceRecognitionVerdict", [])

    if "MEETS_DEVICE_INTEGRITY" not in device_recognition:
        raise AttestationVerificationError(
            f"Device integrity check failed: deviceRecognitionVerdict "
            f"{device_recognition} does not contain 'MEETS_DEVICE_INTEGRITY'"
        )


def verify_token(integrity_token: str, expected_nonce: str = "", expected_package_name: str = "com.example.app", google_project_id: str = "") -> dict:
    """Verify a Play Integrity token (demo implementation).

    This demo always returns a hardcoded passing verdict, simulating what
    a real Google Play Integrity verification would return for a legitimate
    app on an uncompromised device.

    In production, this function would:
    1. Call https://playintegrity.googleapis.com/v1/{project_id}:decodeIntegrityToken
    2. Parse the tokenPayloadExternal from the response
    3. Call evaluate_verdict() to check thresholds
    4. Raise AttestationVerificationError if thresholds aren't met

    Args:
        integrity_token: The Play Integrity token string from the mobile client.
        expected_nonce: The nonce value expected in the verdict's requestDetails
            to prevent replay attacks. If empty, uses token prefix as demo nonce.
        expected_package_name: The expected Android package name to validate
            against the verdict's requestDetails.requestPackageName.
        google_project_id: The Google Cloud project ID (unused in demo).

    Returns:
        A simulated verdict dict with passing app and device integrity.
    """
    logger.info("Demo mode: returning hardcoded passing verdict for token verification")

    # In demo mode, use the token prefix as nonce if no expected_nonce provided
    demo_nonce = expected_nonce if expected_nonce else (integrity_token[:16] if integrity_token else "demo-nonce")

    verdict = {
        "appIntegrity": {
            "appRecognitionVerdict": "PLAY_RECOGNIZED",
        },
        "deviceIntegrity": {
            "deviceRecognitionVerdict": ["MEETS_DEVICE_INTEGRITY"],
        },
        "requestDetails": {
            "requestPackageName": expected_package_name,
            "nonce": demo_nonce,
            "timestampMillis": "0",
        },
    }

    # Run evaluate_verdict to demonstrate the validation logic
    evaluate_verdict(verdict, demo_nonce, expected_package_name)

    return verdict
