"""Property-based tests for the Play Integrity Verifier module using Hypothesis.

These tests validate that evaluate_verdict correctly rejects any verdict
with insufficient app or device integrity.
"""

import pytest
from hypothesis import given, settings, assume
from hypothesis import strategies as st

from play_integrity import evaluate_verdict, AttestationVerificationError


# The only valid passing value for app recognition
VALID_APP_RECOGNITION = "PLAY_RECOGNIZED"

# The required device integrity label
REQUIRED_DEVICE_INTEGRITY = "MEETS_DEVICE_INTEGRITY"

# Strategy for generating app recognition values that are NOT "PLAY_RECOGNIZED"
invalid_app_recognition_strategy = st.text(min_size=0, max_size=50).filter(
    lambda x: x != VALID_APP_RECOGNITION
)

# Strategy for generating device recognition verdict lists that do NOT contain "MEETS_DEVICE_INTEGRITY"
invalid_device_recognition_strategy = st.lists(
    st.text(min_size=0, max_size=50).filter(lambda x: x != REQUIRED_DEVICE_INTEGRITY),
    min_size=0,
    max_size=5,
)

# Strategy for generating device recognition verdict lists that DO contain "MEETS_DEVICE_INTEGRITY"
valid_device_recognition_strategy = st.lists(
    st.text(min_size=0, max_size=50).filter(lambda x: x != REQUIRED_DEVICE_INTEGRITY),
    min_size=0,
    max_size=4,
).map(lambda lst: lst + [REQUIRED_DEVICE_INTEGRITY])


class TestPlayIntegrityVerdictRejection:
    """Property 5: Play Integrity Verdict Rejection on Insufficient Integrity.

    For any Play Integrity verdict where appRecognitionVerdict is not
    "PLAY_RECOGNIZED" or deviceRecognitionVerdict does not contain
    "MEETS_DEVICE_INTEGRITY", the Play_Integrity_Verifier SHALL raise
    an AttestationVerificationError.

    **Validates: Requirements 3.2, 3.3**
    """

    @given(
        app_recognition=invalid_app_recognition_strategy,
        device_recognition=st.lists(st.text(min_size=0, max_size=50), min_size=0, max_size=5),
    )
    @settings(max_examples=100)
    def test_rejects_invalid_app_recognition(self, app_recognition, device_recognition):
        """evaluate_verdict raises AttestationVerificationError when
        appRecognitionVerdict is not 'PLAY_RECOGNIZED', regardless of device verdict.

        **Validates: Requirements 3.2**
        """
        nonce = "test-nonce"
        package_name = "com.example.app"
        verdict = {
            "appIntegrity": {"appRecognitionVerdict": app_recognition},
            "deviceIntegrity": {"deviceRecognitionVerdict": device_recognition},
            "requestDetails": {"nonce": nonce, "requestPackageName": package_name},
        }
        with pytest.raises(AttestationVerificationError):
            evaluate_verdict(verdict, nonce, package_name)

    @given(
        device_recognition=invalid_device_recognition_strategy,
    )
    @settings(max_examples=100)
    def test_rejects_missing_device_integrity(self, device_recognition):
        """evaluate_verdict raises AttestationVerificationError when
        deviceRecognitionVerdict does not contain 'MEETS_DEVICE_INTEGRITY',
        even when appRecognitionVerdict is valid.

        **Validates: Requirements 3.3**
        """
        nonce = "test-nonce"
        package_name = "com.example.app"
        verdict = {
            "appIntegrity": {"appRecognitionVerdict": VALID_APP_RECOGNITION},
            "deviceIntegrity": {"deviceRecognitionVerdict": device_recognition},
            "requestDetails": {"nonce": nonce, "requestPackageName": package_name},
        }
        with pytest.raises(AttestationVerificationError):
            evaluate_verdict(verdict, nonce, package_name)

    @given(
        app_recognition=invalid_app_recognition_strategy,
        device_recognition=invalid_device_recognition_strategy,
    )
    @settings(max_examples=100)
    def test_rejects_both_invalid(self, app_recognition, device_recognition):
        """evaluate_verdict raises AttestationVerificationError when both
        appRecognitionVerdict and deviceRecognitionVerdict are invalid.

        **Validates: Requirements 3.2, 3.3**
        """
        nonce = "test-nonce"
        package_name = "com.example.app"
        verdict = {
            "appIntegrity": {"appRecognitionVerdict": app_recognition},
            "deviceIntegrity": {"deviceRecognitionVerdict": device_recognition},
            "requestDetails": {"nonce": nonce, "requestPackageName": package_name},
        }
        with pytest.raises(AttestationVerificationError):
            evaluate_verdict(verdict, nonce, package_name)
