@echo off
REM test-api.bat - End-to-end API test for the Attestation Demo
REM Run from the project root: scripts\test-api.bat

set STACK_NAME=serverless-mobile-api-attestation
set USERNAME=testuser@example.com
set PASSWORD=TestPass123!

echo.
echo === Serverless Mobile API Attestation - E2E Test ===
echo.

REM Step 1: Get stack outputs
echo [1/6] Fetching stack outputs...
for /f "tokens=*" %%a in ('aws cloudformation describe-stacks --stack-name %STACK_NAME% --query "Stacks[0].Outputs[?OutputKey==''ApiEndpoint''].OutputValue" --output text') do set API_ENDPOINT=%%a
for /f "tokens=*" %%a in ('aws cloudformation describe-stacks --stack-name %STACK_NAME% --query "Stacks[0].Outputs[?OutputKey==''CognitoUserPoolId''].OutputValue" --output text') do set POOL_ID=%%a
for /f "tokens=*" %%a in ('aws cloudformation describe-stacks --stack-name %STACK_NAME% --query "Stacks[0].Outputs[?OutputKey==''CognitoAppClientId''].OutputValue" --output text') do set CLIENT_ID=%%a

echo   API: %API_ENDPOINT%
echo   Pool: %POOL_ID%
echo   Client: %CLIENT_ID%
echo.

REM Step 2: Get Cognito token
echo [2/6] Getting Cognito access token...
for /f "tokens=*" %%a in ('aws cognito-idp initiate-auth --client-id %CLIENT_ID% --auth-flow USER_PASSWORD_AUTH --auth-parameters USERNAME=%USERNAME%,PASSWORD="%PASSWORD%" --query "AuthenticationResult.AccessToken" --output text') do set TOKEN=%%a

if "%TOKEN%"=="" (
    echo   ERROR: Failed to get token. Create user first.
    exit /b 1
)
echo   Got token successfully.
echo.

REM Step 3: POST /attest
echo [3/6] Calling POST /attest...
curl -s -X POST %API_ENDPOINT%/attest -H "Content-Type: application/json" -H "Authorization: Bearer %TOKEN%" -d "{\"integrity_token\": \"demo-token\", \"platform\": \"android\"}" -o attest_response.json
type attest_response.json
echo.
echo.

REM Extract attestation token (requires jq or manual copy)
for /f "tokens=*" %%a in ('type attest_response.json ^| findstr attestation_token') do set ATTEST_LINE=%%a
REM Note: You may need to manually set ATTEST_TOKEN if the above doesn't parse cleanly
echo   NOTE: Copy the attestation_token value and set it below if needed.
echo.

REM Step 4: GET /protected
echo [4/6] Calling GET /protected...
echo   (If this fails, manually: set ATTEST_TOKEN=value_from_step_3, then run step 4 again)

REM Uncomment and set manually if the for loop above didn't work:
REM set ATTEST_TOKEN=paste_here

curl -s %API_ENDPOINT%/protected -H "Authorization: Bearer %TOKEN%" -H "X-Attestation-Token: %ATTEST_TOKEN%"
echo.
echo.

REM Step 5: Failure test - missing attestation
echo [5/6] Testing missing attestation token (expect 403)...
curl -s -o nul -w "  HTTP Status: %%{http_code}" %API_ENDPOINT%/protected -H "Authorization: Bearer %TOKEN%"
echo.
echo.

REM Step 6: Failure test - missing body field
echo [6/6] Testing missing integrity_token (expect 400)...
curl -s -X POST %API_ENDPOINT%/attest -H "Content-Type: application/json" -H "Authorization: Bearer %TOKEN%" -d "{\"platform\": \"android\"}"
echo.
echo.

echo === Tests complete ===
del attest_response.json 2>nul
