# Passkey Authentication

This package supports WebAuthn passkeys for passwordless and second-factor authentication. Passkeys are discoverable credentials that let users sign in with a biometric sensor, PIN, or security key.

## Table of Contents

- [Overview](#overview)
- [Requirements](#requirements)
- [Configuration](#configuration)
- [Endpoints](#endpoints)
- [Registration Flow](#registration-flow)
- [Login Flow](#login-flow)
  - [With Email](#with-email)
  - [Passwordless](#passwordless)
- [Frontend Integration](#frontend-integration)
- [Origin and RP ID](#origin-and-rp-id)
- [Security Considerations](#security-considerations)
- [Troubleshooting](#troubleshooting)
- [Local Development with ngrok](#local-development-with-ngrok)

## Overview

Passkeys in this package are stored as WebAuthn credentials linked to the package's user model through a polymorphic relation. Each user can have multiple passkeys (e.g., one on their laptop, one on their phone).

Key features:

- **Configurable resident credentials** — opt-in to discoverable credentials for true passwordless login, or keep them off for second-factor-only use.
- **Email-based passkey login** — the backend filters the allowed credentials to those belonging to a specific user.
- **Passwordless passkey login** — when resident keys are enabled, the backend returns an empty `allowCredentials` list, letting the browser show the passkey picker.

## Requirements

- PHP 8.3+
- `web-auth/webauthn-lib` is installed automatically with the package.
- A browser and authenticator that support WebAuthn (Chrome, Edge, Safari, Firefox; Touch ID, Windows Hello, YubiKey, etc.).
- For mobile and roaming authenticators, the frontend must be served over **HTTPS** (or `localhost` for some browsers).

## Configuration

All passkey settings live under the `passkey` key in `config/user-authentication.php` and are driven by environment variables.

```php
'passkey' => [
    'session_lifetime' => env('USER_AUTH_PASSKEY_SESSION_LIFETIME', 5), // minutes
    'domain' => env('USER_AUTH_PASSKEY_DOMAIN', 'localhost'),
    'attestations' => array_map('strtolower', array_map('trim', array_filter(explode(',', env('USER_AUTH_PASSKEY_ATTESTATIONS', 'none')), 'strlen'))),
    'allowed_origins' => array_map('strtolower', array_map('trim', array_filter(explode(',', env('USER_AUTH_PASSKEY_ALLOWED_ORIGINS', '')), 'strlen'))),
],
```

### Environment Variables

| Variable | Default | Purpose |
|----------|---------|---------|
| `USER_AUTH_PASSKEY_SESSION_LIFETIME` | `5` | How many minutes the server-side registration/login challenge is cached. |
| `USER_AUTH_PASSKEY_DOMAIN` | (empty) | The relying party ID (RP ID) host. Must include the scheme, e.g. `https://app.example.com`. |
| `USER_AUTH_PASSKEY_ALLOWED_ORIGINS` | (empty) | Full origins (scheme + host + port) allowed to perform WebAuthn ceremonies. Required for HTTPS deployments. |
| `USER_AUTH_PASSKEY_ATTESTATIONS` | `none` | Comma-separated attestation formats. Options: `none`, `packed`, `fido`. |
| `USER_AUTH_PASSKEY_RESIDENT_KEYS` | `false` | Request discoverable (resident) credentials. Required for passwordless login without email. |

### Important: include the scheme in `USER_AUTH_PASSKEY_DOMAIN`

The backend extracts the RP ID host with PHP's `parse_url()`. If you provide a bare hostname such as `app.example.com`, `parse_url()` returns `null` for the host and the `rp.id` is dropped from the registration options. The browser then falls back to the origin's effective domain, while the server verification may use a different host, causing an **"rpId hash mismatch"** error.

Always set the domain with a scheme:

```bash
# Good
USER_AUTH_PASSKEY_DOMAIN=https://app.example.com

# Bad — will drop rp.id
USER_AUTH_PASSKEY_DOMAIN=app.example.com
```

For local HTTPS tunnels such as ngrok, set both the frontend origin and domain to the ngrok URL:

```bash
USER_AUTH_PASSKEY_ALLOWED_ORIGINS=https://abc123.ngrok-free.app
USER_AUTH_PASSKEY_DOMAIN=https://abc123.ngrok-free.app
```

## Endpoints

All passkey endpoints are prefixed with the configured route prefix (default: `api`).

| Method | Endpoint | Auth | Description |
|--------|----------|------|-------------|
| `POST` | `/passkeys/register/options` | Yes | Get WebAuthn creation options for the authenticated user. |
| `POST` | `/passkeys/register` | Yes | Store a new passkey for the authenticated user. |
| `POST` | `/passkeys/login/options` | No | Get WebAuthn request options. Email is optional for passwordless flow. |
| `POST` | `/passkeys/login` | No | Verify a passkey assertion and return a Sanctum token. |
| `GET`  | `/passkeys` | Yes | List the authenticated user's passkeys. |
| `DELETE` | `/passkeys/{id}` | Yes | Delete a passkey. |

## Registration Flow

Passkey registration must happen while the user is authenticated, because the credential is attached to their account.

### 1. Get registration options

```bash
curl -X POST https://app.example.com/api/passkeys/register/options \
  -H "Authorization: Bearer {token}" \
  -H "Content-Type: application/json" \
  -d '{"name":"MacBook Touch ID"}'
```

Response:

```json
{
  "status": "success",
  "data": {
    "options": "{\"challenge\":\"...\",\"rp\":{\"name\":\"Laravel\",\"id\":\"app.example.com\"},\"user\":{...},...}",
    "session_id": "reg_xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
  }
}
```

The `options` value is a JSON string. Parse it on the frontend and convert base64url fields to `ArrayBuffer` before calling the WebAuthn API.

### 2. Create the credential in the browser

```javascript
const publicKey = JSON.parse(options);
publicKey.challenge = base64urlToArrayBuffer(publicKey.challenge);
publicKey.user.id = base64urlToArrayBuffer(publicKey.user.id);

const credential = await navigator.credentials.create({ publicKey });
```

### 3. Send the credential to the server

Convert the credential's binary fields back to base64url and POST them:

```bash
curl -X POST https://app.example.com/api/passkeys/register \
  -H "Authorization: Bearer {token}" \
  -H "Content-Type: application/json" \
  -d '{
    "session_id": "reg_xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
    "name": "MacBook Touch ID",
    "passkey": {
      "id": "...",
      "rawId": "...",
      "type": "public-key",
      "response": {
        "clientDataJSON": "...",
        "attestationObject": "...",
        "transports": ["internal"]
      }
    }
  }'
```

## Login Flow

### With Email

When the email is provided, the backend returns only that user's credentials, which is useful if you want to keep a traditional username/email step.

#### 1. Get login options

```bash
curl -X POST https://app.example.com/api/passkeys/login/options \
  -H "Content-Type: application/json" \
  -d '{"email":"user@example.com"}'
```

#### 2. Get the credential

```javascript
const publicKey = JSON.parse(options);
publicKey.challenge = base64urlToArrayBuffer(publicKey.challenge);
publicKey.allowCredentials.forEach(c => c.id = base64urlToArrayBuffer(c.id));

const credential = await navigator.credentials.get({ publicKey });
```

#### 3. Verify the assertion

```bash
curl -X POST https://app.example.com/api/passkeys/login \
  -H "Content-Type: application/json" \
  -d '{
    "session_id": "log_xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
    "passkey": {
      "id": "...",
      "rawId": "...",
      "type": "public-key",
      "response": {
        "clientDataJSON": "...",
        "authenticatorData": "...",
        "signature": "...",
        "userHandle": "..."
      }
    }
  }'
```

Response includes a Sanctum bearer token:

```json
{
  "status": "success",
  "data": {
    "token": "...",
    "token_type": "Bearer",
    "user": { ... }
  }
}
```

### Passwordless

Omit the email from the login-options request. The backend returns an empty `allowCredentials` list, which tells the browser to show the passkey picker and use any discoverable credential.

This requires resident keys to be enabled:

```bash
USER_AUTH_PASSKEY_RESIDENT_KEYS=true
```

```bash
curl -X POST https://app.example.com/api/passkeys/login/options \
  -H "Content-Type: application/json" \
  -d '{}'
```

The rest of the flow is identical to the email-based flow.

## Frontend Integration

The key pieces of a passkey frontend implementation are:

1. **Convert server options to WebAuthn format** — base64url strings must become `ArrayBuffer`s.
2. **Convert the browser credential back to JSON** — binary fields become base64url strings.
3. **Call the API** — send requests to the route prefix configured in the package (default `/api`).

### Base64url helpers

```javascript
function base64urlToArrayBuffer(base64url) {
  const base64 = base64url.replace(/-/g, '+').replace(/_/g, '/');
  const bin = atob(base64);
  const buf = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) buf[i] = bin.charCodeAt(i);
  return buf.buffer;
}

function arrayBufferToBase64url(buf) {
  const bytes = new Uint8Array(buf);
  let bin = '';
  for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
  return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}
```

## Origin and RP ID

WebAuthn is strict about the relationship between the frontend origin and the RP ID.

- **Origin** — the scheme + host + port where the JavaScript runs (`https://app.example.com`).
- **RP ID** — the host component extracted from `USER_AUTH_PASSKEY_DOMAIN` (`app.example.com`).

The browser requires the origin's host to match or be a registrable domain suffix of the RP ID. The server verifies the same relationship through `allowed_origins`.

### Example setups

#### Local HTTPS development with ngrok

Frontend tunnel: `https://abc123.ngrok-free.app -> http://localhost:5173`
Backend: `http://localhost:8000`

```bash
USER_AUTH_PASSKEY_ALLOWED_ORIGINS=https://abc123.ngrok-free.app
USER_AUTH_PASSKEY_DOMAIN=https://abc123.ngrok-free.app
```

The frontend must be opened through the ngrok HTTPS URL, not `localhost:5173`.

#### Production

```bash
USER_AUTH_PASSKEY_ALLOWED_ORIGINS=https://app.example.com
USER_AUTH_PASSKEY_DOMAIN=https://app.example.com
```

#### Bare hostname bug

If you set only the bare hostname:

```bash
USER_AUTH_PASSKEY_DOMAIN=app.example.com
```

the backend extracts `null` as the RP ID and the registration options omit `rp.id`. The browser then uses the origin host (`app.example.com`) while the server verification may use the request host, producing an **"rpId hash mismatch"** error.

## Security Considerations

- **HTTPS in production** — WebAuthn requires a secure origin in all modern browsers.
- **Allowed origins** — restrict `USER_AUTH_PASSKEY_ALLOWED_ORIGINS` to your actual frontend origins. Do not use wildcard origins.
- **RP ID scope** — choosing a broad RP ID (e.g., `example.com`) makes the passkey usable across all subdomains. Choose the narrowest RP ID that fits your architecture.
- **Resident keys** — when `USER_AUTH_PASSKEY_RESIDENT_KEYS=true`, the package requests discoverable credentials (`residentKey: required`). This stores user-identifying information on the authenticator; ensure this aligns with your privacy policy.
- **Session lifetime** — the challenge cache is short (5 minutes by default). Do not increase it significantly.

## Troubleshooting

### "rpId hash mismatch"

- `USER_AUTH_PASSKEY_DOMAIN` is missing the scheme. Use `https://app.example.com`, not `app.example.com`.
- The frontend origin does not match the configured RP ID or allowed origins.
- You are opening the frontend through a different URL than the one configured (e.g., `localhost:5173` instead of the ngrok URL).

### "Invalid origin"

- `USER_AUTH_PASSKEY_ALLOWED_ORIGINS` does not include the frontend origin.
- The frontend is served over HTTP but the origin is not `localhost`.

### "This passkey is not valid"

- The session ID expired or was not sent back.
- The credential ID does not exist in the database.
- The assertion signature could not be verified. Check the Laravel logs for the exact WebAuthn error.

### Passkey picker does not appear for passwordless login

- `USER_AUTH_PASSKEY_RESIDENT_KEYS` is not set to `true`. Passwordless login requires discoverable credentials.
- The passkey was not created as a discoverable credential. The package requests `residentKey: required` when resident keys are enabled, but the authenticator may ignore this if it does not support resident keys.
- The browser has no discoverable credentials for the RP ID.
