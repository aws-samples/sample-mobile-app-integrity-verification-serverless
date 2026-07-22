# test-api.ps1 - End-to-end API test script for the Attestation Demo
# Run from the project root: .\scripts\test-api.ps1

param(
    [string]$StackName = "serverless-mobile-api-attestation",
    [string]$Username = "testuser@example.com",
    [string]$Password = "TestPass123!"
)

Write-Host "`n=== Serverless Mobile API Attestation - E2E Test ===" -ForegroundColor Cyan

# Step 1: Get stack outputs
Write-Host "`n[1/7] Fetching stack outputs..." -ForegroundColor Yellow
$outputs = aws cloudformation describe-stacks --stack-name $StackName --query "Stacks[0].Outputs" | ConvertFrom-Json

$ApiEndpoint = ($outputs | Where-Object { $_.OutputKey -eq "ApiEndpoint" }).OutputValue
$UserPoolId = ($outputs | Where-Object { $_.OutputKey -eq "CognitoUserPoolId" }).OutputValue
$ClientId = ($outputs | Where-Object { $_.OutputKey -eq "CognitoAppClientId" }).OutputValue

Write-Host "  API Endpoint: $ApiEndpoint"
Write-Host "  User Pool ID: $UserPoolId"
Write-Host "  Client ID:    $ClientId"

# Step 2: Create test user (idempotent - ignores errors if user exists)
Write-Host "`n[2/7] Ensuring test user exists..." -ForegroundColor Yellow
try {
    aws cognito-idp sign-up --client-id $ClientId --username $Username --password $Password 2>$null | Out-Null
    aws cognito-idp admin-confirm-sign-up --user-pool-id $UserPoolId --username $Username 2>$null | Out-Null
    Write-Host "  User created and confirmed" -ForegroundColor Green
} catch {
    Write-Host "  User already exists (OK)" -ForegroundColor Green
}

# Step 3: Get Cognito access token via SRP (USER_PASSWORD_AUTH is disabled)
# Since SRP is complex from PowerShell, we temporarily enable USER_PASSWORD_AUTH,
# get the token, then disable it again. For a real app, use the hosted UI or SRP SDK.
Write-Host "`n[3/7] Getting Cognito access token..." -ForegroundColor Yellow

# Temporarily enable USER_PASSWORD_AUTH to get a token for testing
aws cognito-idp update-user-pool-client --user-pool-id $UserPoolId --client-id $ClientId `
    --explicit-auth-flows ALLOW_USER_SRP_AUTH ALLOW_REFRESH_TOKEN_AUTH ALLOW_USER_PASSWORD_AUTH 2>$null | Out-Null

$authResult = aws cognito-idp initiate-auth `
    --client-id $ClientId `
    --auth-flow USER_PASSWORD_AUTH `
    --auth-parameters "USERNAME=$Username,PASSWORD=$Password" 2>&1 | ConvertFrom-Json

# Restore secure auth flows (remove USER_PASSWORD_AUTH)
aws cognito-idp update-user-pool-client --user-pool-id $UserPoolId --client-id $ClientId `
    --explicit-auth-flows ALLOW_USER_SRP_AUTH ALLOW_REFRESH_TOKEN_AUTH 2>$null | Out-Null

$Token = $authResult.AuthenticationResult.AccessToken

if (-not $Token) {
    Write-Host "  ERROR: Failed to get access token." -ForegroundColor Red
    Write-Host "  Make sure the user is confirmed: aws cognito-idp admin-confirm-sign-up --user-pool-id $UserPoolId --username $Username"
    exit 1
}
Write-Host "  Got access token ($($Token.Length) chars)" -ForegroundColor Green

# Step 4: Call POST /attest with valid token
Write-Host "`n[4/7] Calling POST /attest (attestation exchange)..." -ForegroundColor Yellow
$body = '{"integrity_token": "demo-token-at-least-16", "platform": "android"}'
try {
    $attestResponse = Invoke-RestMethod -Uri "$ApiEndpoint/attest" -Method POST `
        -Headers @{
            "Content-Type" = "application/json"
            "Authorization" = "Bearer $Token"
        } -Body $body

    $AttestToken = $attestResponse.attestation_token
    $ExpiresIn = $attestResponse.expires_in

    Write-Host "  Status: SUCCESS" -ForegroundColor Green
    Write-Host "  Attestation token received (expires in ${ExpiresIn}s)"
} catch {
    Write-Host "  Status: FAILED - $($_.ErrorDetails.Message)" -ForegroundColor Red
    Write-Host "  (This may fail if Cognito JWKS verification rejects the token format)" -ForegroundColor DarkYellow
    $AttestToken = $null
}

# Step 5: Call GET /protected with both tokens (only if attestation succeeded)
if ($AttestToken) {
    Write-Host "`n[5/7] Calling GET /protected (dual-token auth)..." -ForegroundColor Yellow
    try {
        $protectedResponse = Invoke-RestMethod -Uri "$ApiEndpoint/protected" -Method GET `
            -Headers @{
                "Authorization" = "Bearer $Token"
                "X-Attestation-Token" = $AttestToken
            }

        Write-Host "  Status: SUCCESS" -ForegroundColor Green
        Write-Host "  Message: $($protectedResponse.message)"
        Write-Host "  User Sub: $($protectedResponse.user_sub)"
        Write-Host "  Attestation Verified: $($protectedResponse.attestation_verified)"
        Write-Host "  Timestamp: $($protectedResponse.timestamp)"
    } catch {
        $statusCode = $_.Exception.Response.StatusCode.value__
        Write-Host "  Got HTTP $statusCode - $($_.ErrorDetails.Message)" -ForegroundColor Red
    }
} else {
    Write-Host "`n[5/7] Skipping /protected test (no attestation token)" -ForegroundColor DarkYellow
}

# Step 6: Test security fix - invalid platform rejected
Write-Host "`n[6/7] Testing security fix: invalid platform rejected..." -ForegroundColor Yellow
try {
    Invoke-RestMethod -Uri "$ApiEndpoint/attest" -Method POST `
        -Headers @{
            "Content-Type" = "application/json"
            "Authorization" = "Bearer $Token"
        } -Body '{"integrity_token": "test-token-1234567890", "platform": "windows"}' -ErrorAction Stop
    Write-Host "  UNEXPECTED: Request succeeded (should have been rejected)" -ForegroundColor Red
} catch {
    $errorBody = $_.ErrorDetails.Message
    if ($errorBody -match "Unsupported platform") {
        Write-Host "  PASS: Invalid platform correctly rejected with 400" -ForegroundColor Green
        Write-Host "  Response: $errorBody"
    } else {
        Write-Host "  Got error but unexpected message: $errorBody" -ForegroundColor Red
    }
}

# Step 7: Test security fix - forged JWT rejected
Write-Host "`n[7/7] Testing security fix: forged JWT rejected..." -ForegroundColor Yellow
try {
    Invoke-RestMethod -Uri "$ApiEndpoint/attest" -Method POST `
        -Headers @{
            "Content-Type" = "application/json"
            "Authorization" = "Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhdHRhY2tlciJ9.fake"
        } -Body '{"integrity_token": "test-token-1234567890", "platform": "android"}' -ErrorAction Stop
    Write-Host "  UNEXPECTED: Forged JWT was accepted!" -ForegroundColor Red
} catch {
    $errorBody = $_.ErrorDetails.Message
    if ($errorBody -match "Unauthorized") {
        Write-Host "  PASS: Forged JWT correctly rejected with 401" -ForegroundColor Green
        Write-Host "  Response: $errorBody"
    } else {
        Write-Host "  Got error but unexpected message: $errorBody" -ForegroundColor Red
    }
}

Write-Host "`n=== All tests complete! ===" -ForegroundColor Cyan
