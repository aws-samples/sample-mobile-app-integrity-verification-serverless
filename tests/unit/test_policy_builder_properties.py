"""Property-based tests for the Policy Builder module.

**Validates: Requirements 7.1, 7.2, 7.3**

Property 7: Policy Builder Structural Correctness
For any valid principal_id, effect ("Allow" or "Deny"), and method ARN, the Policy_Builder
SHALL return a response where policyDocument contains Version "2012-10-17", Statement with
Action "execute-api:Invoke", the provided effect, and the provided Resource. When effect is
"Deny", principalId SHALL be "unauthorized".
"""

import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "src"))

from hypothesis import given, assume, settings
from hypothesis import strategies as st

from authorizer.policy_builder import build_policy


# --- Strategies ---

# Generate non-empty principal IDs (alphanumeric, UUID-like patterns)
principal_id_strategy = st.text(
    alphabet=st.characters(whitelist_categories=("L", "N", "Pd")),
    min_size=1,
    max_size=128,
)

# Effect is always either "Allow" or "Deny"
effect_strategy = st.sampled_from(["Allow", "Deny"])

# Generate realistic method ARN patterns
method_arn_strategy = st.from_regex(
    r"arn:aws:execute-api:[a-z]{2}-[a-z]+-[0-9]:[0-9]{12}:[a-z0-9]+/[a-z]+/(GET|POST|PUT|DELETE|PATCH)/[a-z/]+",
    fullmatch=True,
)


# --- Property Tests ---


class TestPolicyBuilderStructuralCorrectness:
    """Property 7: Policy Builder Structural Correctness."""

    @given(
        principal_id=principal_id_strategy,
        effect=effect_strategy,
        resource=method_arn_strategy,
    )
    @settings(max_examples=200)
    def test_output_always_conforms_to_iam_policy_schema(self, principal_id, effect, resource):
        """Output structure always conforms to IAM policy schema.

        **Validates: Requirements 7.1, 7.2, 7.3**
        """
        result = build_policy(principal_id, effect, resource)

        # Top-level keys must exist
        assert "principalId" in result
        assert "policyDocument" in result

        # policyDocument must have correct Version
        policy_doc = result["policyDocument"]
        assert policy_doc["Version"] == "2012-10-17"

        # Statement must be a list with at least one statement
        assert "Statement" in policy_doc
        assert isinstance(policy_doc["Statement"], list)
        assert len(policy_doc["Statement"]) >= 1

        # Each statement must have Action, Effect, and Resource
        statement = policy_doc["Statement"][0]
        assert statement["Action"] == "execute-api:Invoke"
        assert statement["Effect"] == effect

        # Allow policies use wildcard resource; Deny policies preserve specific resource
        if effect == "Allow":
            arn_parts = resource.split("/")
            expected_resource = "/".join(arn_parts[:2]) + "/*"
            assert statement["Resource"] == expected_resource
        else:
            assert statement["Resource"] == resource

    @given(
        principal_id=principal_id_strategy,
        resource=method_arn_strategy,
    )
    @settings(max_examples=200)
    def test_deny_always_has_unauthorized_principal(self, principal_id, resource):
        """When effect is 'Deny', principalId SHALL be 'unauthorized'.

        **Validates: Requirements 7.2**
        """
        result = build_policy(principal_id, "Deny", resource)

        assert result["principalId"] == "unauthorized"

    @given(
        principal_id=principal_id_strategy,
        resource=method_arn_strategy,
    )
    @settings(max_examples=200)
    def test_allow_preserves_provided_principal_id(self, principal_id, resource):
        """When effect is 'Allow', principalId SHALL be the provided principal_id.

        **Validates: Requirements 7.1**
        """
        result = build_policy(principal_id, "Allow", resource)

        assert result["principalId"] == principal_id
