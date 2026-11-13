# Two-factor authentication

An access token permits access to your application. A pending two-factor token permits only completion of a specific sign-in challenge. Password login, passkey login, OAuth callbacks and Firebase callbacks return the following data for accounts with two-factor authentication enabled, without an access token:

```json
{
  "two_factor_required": true,
  "factor_id": 1,
  "method": "totp",
  "factors": [{"id": 1, "type": "totp", "label": "Phone", "confirmed_at": "2026-06-01T12:00:00Z", "last_used_at": null}],
  "two_factor_token": "<opaque-pending-token>"
}
```

The examples use the default `/api` route prefix. Pending tokens are bound to the account, factor policy, method and purpose. They expire after five minutes by default. Completing or replacing a challenge invalidates its pending token, code and magic link. Only the newest challenge for an account and purpose is valid. Confirming, changing or removing a confirmed factor invalidates outstanding pending tokens. Adding a factor that is not yet confirmed leaves them valid. Pending challenges carry a policy derived from the owner’s confirmed factors; factor changes also invalidate existing policies permanently.

## TOTP enrollment

1. Send an authenticated `POST /api/2fa/setup` with `{"type":"totp","label":"Phone"}`. Save the returned `factor_id`. Save the returned secret in an authenticator app using the QR URI. The secret is returned only during enrollment.
2. Send an authenticated `POST /api/2fa/confirm` with `{"factor_id":1,"code":"123456"}` using a current six-digit TOTP code. The first confirmed factor returns ten recovery codes. Save them securely; they are shown only once. Later confirmations preserve the owner’s existing codes and return an empty recovery-code list.

Confirmation rejects an already confirmed factor. An owner can register multiple factors, up to `two_factor.max_factors` (five by default), including unconfirmed factors. Only one email and one phone factor per owner is permitted. These limits are enforced under locks on the owner and their factors. Five failed confirmation attempts invalidate setup by default. Confirmation revokes every other access token and marks the current bearer as having completed two-factor authentication. Existing sessions on other devices must sign in again.

The enrollment code's timestep is consumed. Wait for a new authenticator code before using TOTP again. Each accepted timestep is recorded under a database lock, so the same timestep cannot authenticate another challenge or disable two-factor authentication. Recovery codes are case-sensitive, ten-character alphanumeric strings, generated with a cryptographically secure random source and stored individually using Laravel’s salted password hashing. They belong to the owner, independently of factors and APP_KEY rotation. Verification locks unused rows, checks the password hashes, and conditionally marks the matching row used. Used rows remain with `used_at` for auditing.

Setup and confirmation require a real Sanctum bearer token. Stateful session authentication alone does not provide a verified bearer, and confirmation requested through a session currently fails with HTTP 500.

## Email and SMS

Send `POST /api/2fa/setup` with `{"type":"email","label":"Work inbox"}` or `{"type":"phone","label":"Mobile"}`. The owner must already have that contact recorded. Setup returns `factor_id` and `two_factor_token` and dispatches a delivery event. Confirm with `factor_id`, that pending token and the delivered `code`. No secret is stored for these types. Changing the account’s delivery contact invalidates its existing pending challenges.

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

Use a current TOTP code, the email/SMS code for that pending challenge, or an unused recovery code. A successful response includes an access token with the explicit `2fa-verified` ability and public user identity fields: `id`, `first_name`, `last_name`, `username`, `email`, `phone` and `email_verified_at`. It never includes the factor relationship, secret or recovery codes. Completion dispatches `UserLoggedInEvent` and invokes the original sign-in action's after hooks (`login`, `oauthCallback` or `passkeyLogin`). The completion request uses the `verifyTwoFactor` before hook.

For email/SMS, resend with `POST /api/2fa/resend` and `{"two_factor_token":"<opaque-pending-token>","factor_id":1}`. Save the replacement pending token from the response. Earlier codes, links and pending tokens stop working. The same endpoint selects any of the confirmed factors advertised in the pending response. For TOTP it returns a fresh pending token without sending a code.

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

Send an authenticated `POST /api/2fa/disable` with `factor_id`, using a bearer that explicitly completed two-factor authentication.

For TOTP, submit a fresh TOTP code or unused recovery code in `code`. An access token alone never permits disabling, including when recovery codes are exhausted.

For email/SMS, first omit both `code` and `two_factor_token` to issue a fresh disable challenge. Then submit both the returned pending token and its code to the same endpoint. A login challenge cannot disable the factor, and a disable challenge cannot authenticate a login. Disable challenges do not include magic links. Successful removal of a confirmed factor revokes all access tokens. Removing the last confirmed factor deletes the owner’s recovery codes, even if unconfirmed factors remain. An unconfirmed factor can be removed with its ID without a code.

## Limits and application routes

Named limiters apply independently per IP and per account. Rotating pending tokens or IP addresses does not reset the account limit. Defaults are five requests per minute for verification, link verification, setup, confirmation and disable, and three for resend. Rate-limited requests return HTTP 429.

| Environment override | Default |
| --- | --- |
| `USER_AUTH_2FA_MAX_FACTORS` | 5 |
| `USER_AUTH_2FA_CHALLENGE_RETENTION_HOURS` | 24 |
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

Apply `['auth:sanctum', 'two-factor']` to your application's protected routes. The package applies both middleware to its authenticated routes. The middleware checks the current token's actual abilities list; Sanctum's wildcard ability does not qualify. It rejects unverified tokens with HTTP 403 and requires a fresh primary sign-in, without issuing a new challenge. Custom user models must use `HasTwoFactorAuth`, which exposes `factors()`, `recoveryCodes()` and `hasTwoFactorEnabled()` and hides both relationships during serialization. A factor is enabled exactly when `confirmed_at` is set.

Run the package migrations before serving these endpoints. The tables are `auth_factors`, `auth_recovery_codes` and `auth_challenges`. Multiple factors share one polymorphic owner. Challenge tokens, magic-link hashes and optional binding keys are unique.

## Listing and recovery codes

`GET /api/2fa/factors` returns only `id`, `type`, `label`, `confirmed_at` and `last_used_at` for the current owner. Successful verification updates `last_used_at`.

`POST /api/2fa/recovery-codes` requires an authenticated bearer with the explicit `2fa-verified` ability and at least one confirmed factor. It deletes all previous recovery codes, including spent rows, and returns ten new codes once. No endpoint returns stored codes or their hashes.

## Custom factor types

Implement `Whilesmart\UserAuthentication\Interfaces\FactorType` and register its class under `two_factor.types.<key>`. The contract supplies the key, secret requirement, per-owner uniqueness, delivery contact, enrollment data, challenge issuance and code verification. The registered key must match `key()` and fit the challenge method’s 16-character limit. Only TOTP stores an encrypted secret among the built-in types. Custom implementations must set the relevant code or link expiry when issuing challenges. The service sets `expires_at` to the later expiry. New types require no schema or controller changes.

## Challenge retention

`AuthChallenge` implements Laravel’s `Prunable` behavior. The host must schedule pruning explicitly because package models are outside the application’s default model directory:

```php
use Illuminate\Support\Facades\Schedule;
use Whilesmart\UserAuthentication\Models\AuthChallenge;

Schedule::command('model:prune', ['--model' => [AuthChallenge::class]])->daily();
```

Pruning removes challenges after `expires_at` plus `two_factor.challenge_retention_hours` (24 hours by default), including consumed challenges. `expires_at` is indexed and is the later of `code_expires_at` and `link_expires_at`. The nullable owner and factor, binding key and separate expiries also support authentication challenges outside two-factor sign-in without another schema change.
