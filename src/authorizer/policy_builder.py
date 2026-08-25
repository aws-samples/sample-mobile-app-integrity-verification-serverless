"""Policy Builder module for Lambda Authorizer responses.

Constructs IAM policy documents for API Gateway REQUEST-type authorizer responses.
"""


def build_policy(principal_id: str, effect: str, resource: str, context: dict = None) -> dict:
    """
    Builds an IAM policy document for the API Gateway authorizer response.

    Args:
        principal_id: User identifier (Cognito sub or "unauthorized").
        effect: "Allow" or "Deny".
        resource: The methodArn from the authorizer event.
        context: Optional context dict to pass to downstream Lambda.

    Returns:
        dict: Complete authorizer response with policyDocument.
    """
    # For Deny responses, override principalId to "unauthorized"
    if effect == "Deny":
        principal_id = "unauthorized"

    # For Allow responses, transform resource ARN to wildcard so cached policy
    # applies across all methods/paths within the same API stage.
    # ARN format: arn:aws:execute-api:region:account:api-id/stage/METHOD/resource
    # Wildcard:   arn:aws:execute-api:region:account:api-id/stage/*
    if effect == "Allow":
        arn_parts = resource.split("/")
        resource = "/".join(arn_parts[:2]) + "/*"

    response = {
        "principalId": principal_id,
        "policyDocument": {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Action": "execute-api:Invoke",
                    "Effect": effect,
                    "Resource": resource,
                }
            ],
        },
    }

    # Include context only for Allow responses when context is provided
    if context and effect == "Allow":
        response["context"] = context

    return response
