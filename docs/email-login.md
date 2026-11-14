# Email sign-in without a password

Enable `email_login.enabled` and set `email_login.url` to your frontend's confirmation page. Both endpoints use the package route prefix (default `api`). Apply the package migrations before enabling this feature.

```dotenv
USER_AUTH_EMAIL_LOGIN_ENABLED=true
USER_AUTH_EMAIL_LOGIN_CREATE_USERS=false
USER_AUTH_EMAIL_LOGIN_URL=https://app.example.com/sign-in/confirm
```

## Request a challenge

```http
POST /api/login/email
Content-Type: application/json

{"email":"person@example.com"}
```

Valid requests return the same response whether the address has an account:

```json
{
  "success": true,
  "message": "If this email can sign in, a code has been sent.",
  "data": []
}
```

The status is 202. With `create_users` false, unknown addresses receive nothing. With it true, the account is created only after successful verification. Email domain restrictions apply when requesting a challenge. Addresses are trimmed and normalized to lowercase.

Listen for `VerificationCodeGeneratedEvent`. Its `contact` is the address, `code` is a six digit string, `purpose` is `contact_login`, `type` is `email`, and `magicLink` is the frontend URL with a `token` query parameter. The package delegates delivery to this event, as it does for verification and email 2FA. The event is dispatched after the response is sent, so a slow listener does not reveal through response time whether an account exists. A queued listener is still recommended for mail delivery. Keep codes and link tokens out of logs.

Issuance performs hashing and a challenge write even for unknown addresses. A new request replaces both previous credentials for that address. Only hashes are stored. Code and link share an attempt budget and can each succeed only once.

## Complete sign-in

Submit the code as a string to preserve leading zeros:

```http
POST /api/login/email/verify
Content-Type: application/json

{"email":"person@example.com","code":"012345"}
```

Or have the frontend ask the person to confirm, then submit the link token:

```http
POST /api/login/email/verify
Content-Type: application/json

{"token":"<token-from-link>"}
```

Send either the email/code pair or the token, never both. GET requests to the verification endpoint return 405 and cannot consume a challenge. The configured frontend page must not automatically submit on GET; require an explicit confirmation action so mail scanners cannot sign in.

Success verifies the email and returns the normal login response: a bearer token and the user model with its `$hidden` attributes omitted. New accounts dispatch `UserRegisteredEvent`; completed sign-ins dispatch `UserLoggedInEvent` and run the normal login after hooks. Accounts with 2FA enabled receive the existing pending two-factor response without an authentication token. Complete that challenge through the existing 2FA endpoints.

Invalid, expired, consumed, or exhausted challenges return 422. Successful verification consumes both credentials atomically. Challenges for existing accounts are bound to that account; a sign-up challenge cannot sign in to an account created separately in the meantime. Email-only accounts receive an unguessable random password, which is never returned. Custom user models must support creating a user with email, email verification time, password, and an empty first name; supply other required application fields through model defaults or model creation hooks.

## Configuration

All keys below are under `user-authentication.email_login`.

| Key | Environment variable | Default |
| --- | --- | --- |
| `enabled` | `USER_AUTH_EMAIL_LOGIN_ENABLED` | `false` |
| `create_users` | `USER_AUTH_EMAIL_LOGIN_CREATE_USERS` | `false` |
| `url` | `USER_AUTH_EMAIL_LOGIN_URL` | unset (code delivery only) |
| `code_expiry_minutes` | `USER_AUTH_EMAIL_LOGIN_CODE_EXPIRY_MINUTES` | `10` |
| `link_expiry_minutes` | `USER_AUTH_EMAIL_LOGIN_LINK_EXPIRY_MINUTES` | `15` |
| `attempts` | `USER_AUTH_EMAIL_LOGIN_ATTEMPTS` | `5` |
| `rate_limits.minutes` | `USER_AUTH_EMAIL_LOGIN_RATE_MINUTES` | `1` |
| `rate_limits.issue_ip` | `USER_AUTH_EMAIL_LOGIN_ISSUE_IP_LIMIT` | `10` |
| `rate_limits.issue_email` | `USER_AUTH_EMAIL_LOGIN_ISSUE_EMAIL_LIMIT` | `3` |
| `rate_limits.verify_ip` | `USER_AUTH_EMAIL_LOGIN_VERIFY_IP_LIMIT` | `20` |
| `rate_limits.verify_email` | `USER_AUTH_EMAIL_LOGIN_VERIFY_EMAIL_LIMIT` | `5` |

Named limiters `email-login-issue` and `email-login-verify` each enforce independent IP and normalized email limits. Link verification resolves the email from the stored token hash before applying the email limit. Exceeding a limit returns 429. Disabled endpoints return 404.

The request hooks are `emailLoginRequest` and `emailLoginVerify`. Their after hooks run on successful requests, including a pending 2FA response. The normal `login` after hook runs when authentication completes, including after 2FA.

`ContactLoginService` accepts a delivery channel and contact independently of email. It shares `AuthChallenge` storage with 2FA and isolates contact sign-in through its purpose and binding key. Contact sign-in challenges have no factor, record the requesting IP address and user agent, and belong to the account when one exists. First sign-in challenges have no owner. A future channel can use the same consumption path; this feature exposes email delivery only.
