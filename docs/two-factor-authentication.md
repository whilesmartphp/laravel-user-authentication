# Two-factor authentication

An access token permits access to your application. A pending two-factor token permits only completion of a specific sign-in challenge. Password login, OAuth callbacks and Firebase callbacks return the following data for accounts with two-factor authentication enabled, without an access token:

```json
{
  "two_factor_required": true,
  "method": "totp",
  "two_factor_token": "<opaque-pending-token>"
}
```

The examples use the default `/api` route prefix. Pending tokens are bound to the account, factor policy, method and purpose. They expire after five minutes by default. Completing or replacing a challenge invalidates its pending token, code and magic link. Only the newest challenge for an account is valid.

## TOTP enrollment

1. Send an authenticated `POST /api/2fa/setup`. Save the returned secret in an authenticator app using the QR URI. The secret is returned only during enrollment.
2. Send an authenticated `POST /api/2fa/confirm` with `{"code":"123456"}` using a current six-digit TOTP code. Save the eight returned recovery codes securely; they are returned only once.

Confirmation rejects an already enabled account. Five failed confirmation attempts invalidate setup by default. Confirmation revokes every other access token and marks the current bearer as having completed two-factor authentication. Existing sessions on other devices must sign in again.

The enrollment code's timestep is consumed. Wait for a new authenticator code before using TOTP again. Each accepted timestep is recorded under a database lock, so the same timestep cannot authenticate another challenge or disable two-factor authentication. Recovery codes are case-sensitive, ten-character alphanumeric strings, consumed once under a lock and encrypted at rest.

Setup and confirmation require a real Sanctum bearer token. Stateful session authentication alone does not provide a verified bearer.

## Email and SMS

The host application configures an account's factor through its `twoFactorAuth` relationship with `type` equal to `email` or `phone` and `is_enabled` set to true, after verifying ownership of that contact. When enabling a factor outside the TOTP confirmation endpoint, revoke existing access tokens as part of the same transaction. The host application must prevent unauthenticated changes to these settings.

Listen to `VerificationCodeGeneratedEvent` to deliver the code and optional magic link. These two-factor codes are generated and stored locally even when SmartPings handles other package verification flows. Contact-only provider verification cannot prove possession of a specific pending challenge. Do not log event payloads, codes, pending tokens or magic-link URLs.

Codes use `verification.code_length`, clamped to 4 through 8 digits (six by default). They are stored as hashes on the account's pending challenge, independently of registration and password-reset verification codes.

## Complete a sign-in

Send `POST /api/2fa/verify`:

```json
{
  "two_factor_token": "<opaque-pending-token>",
  "code": "123456"
}
```

Use a current TOTP code, the email/SMS code for that pending challenge, or an unused recovery code. A successful response includes an access token with the explicit `2fa-verified` ability and public user identity fields: `id`, `first_name`, `last_name`, `username`, `email`, `phone` and `email_verified_at`. It never includes the factor relationship, secret or recovery codes. Completion dispatches `UserLoggedInEvent` and invokes the original sign-in action's after hooks (`login` or `oauthCallback`). The completion request uses the `verifyTwoFactor` before hook.

For email/SMS, resend with `POST /api/2fa/resend` and `{"two_factor_token":"<opaque-pending-token>"}`. Save the replacement pending token from the response. Earlier codes, links and pending tokens stop working. TOTP cannot be resent.

## Magic links

Set `USER_AUTH_MAGIC_LINK_URL` to an HTTPS frontend confirmation page. Without it, only numeric codes are sent. Email/SMS challenges include a link to that page with `token` and `two_factor_token` query parameters. Opening the page must display a confirmation action without authenticating. GET requests to package verification endpoints do not consume anything.

After the user confirms, the frontend sends `POST /api/2fa/verify-link`:

```json
{
  "two_factor_token": "<opaque-pending-token-from-link>",
  "token": "<64-character-alphanumeric-link-token>"
}
```

Both values must belong to the same pending login. Consumption is atomic and single use. Links cannot satisfy TOTP. Changing the factor policy, replacing the challenge or completing it by code invalidates the link. The link shares the pending challenge's expiry and attempt budget. Remove query parameters from browser history after reading them; avoid analytics and third-party resources on the confirmation page.

## Disable

Send an authenticated `POST /api/2fa/disable` using a bearer that explicitly completed two-factor authentication.

For TOTP, submit a fresh TOTP code or unused recovery code in `code`. An access token alone never permits disabling, including when recovery codes are exhausted.

For email/SMS, first omit both `code` and `two_factor_token` to issue a fresh disable challenge. Then submit both the returned pending token and its code to the same endpoint. A login challenge cannot disable the factor, and a disable challenge cannot authenticate a login. Disable challenges do not include magic links. Successful disabling revokes all access tokens.

## Limits and application routes

Named limiters apply independently per IP and per account. Rotating pending tokens or IP addresses does not reset the account limit. Defaults are five requests per minute for verification, link verification, setup, confirmation and disable, and three for resend. Rate-limited requests return HTTP 429.

| Environment override | Default |
| --- | --- |
| `USER_AUTH_2FA_ATTEMPTS` | 5 failed attempts per challenge or setup |
| `USER_AUTH_2FA_EXPIRY_MINUTES` | 5 |
| `USER_AUTH_2FA_RATE_MINUTES` | 1 |
| `USER_AUTH_2FA_VERIFY_LIMIT` | 5 |
| `USER_AUTH_2FA_RESEND_LIMIT` | 3 |
| `USER_AUTH_2FA_LINK_LIMIT` | 5 |
| `USER_AUTH_2FA_SETUP_LIMIT` | 5 |
| `USER_AUTH_2FA_CONFIRM_LIMIT` | 5 |
| `USER_AUTH_2FA_DISABLE_LIMIT` | 5 |

Pending tokens are bounded encrypted strings of 100 through 2048 characters. Code inputs accept only 4 through 8 digits or a ten-character alphanumeric recovery code; TOTP itself requires six digits. Link tokens require exactly 64 alphanumeric characters.

Apply `['auth:sanctum', 'two-factor']` to your application's protected routes. The package applies both middleware to its authenticated routes. The middleware checks the current token's actual abilities list; Sanctum's wildcard ability does not qualify. It rejects unverified tokens with HTTP 403 and requires a fresh primary sign-in, without issuing a new challenge. Custom user models should use `HasTwoFactorAuth`, which hides the factor relationship during serialization.

Run the package migrations before serving these endpoints. The factor owner and challenge token identities have unique database constraints.
