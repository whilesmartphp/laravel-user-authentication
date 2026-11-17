# Login with Whilesmart

Add Whilesmart sign-in to a server-hosted website while keeping its own users, sessions, two-factor policy and agents. The package uses public OpenID Connect discovery and OAuth authorization code exchange with S256 PKCE.

## Configuration

Register a confidential application in your Whilesmart workspace's Console, under Applications. Set an exact HTTPS callback matching this package's route, for example `https://your-site.example/api/oauth/whilesmart/callback`. Request `openid profile email` for sign-in. Keep development and production registrations separate. Save the secret when Console displays it.

```dotenv
USER_AUTH_WHILESMART_ISSUER=https://auth.whilesmart.com
USER_AUTH_WHILESMART_CLIENT_ID=your-client-id-here
USER_AUTH_WHILESMART_CLIENT_SECRET=your-client-secret-here
USER_AUTH_WHILESMART_REDIRECT_URI=https://your-site.example/api/oauth/whilesmart/callback
```

Run your application's migrations to create the issuer/subject identity table. OAuth routes must be enabled. The normal route prefix is `api`; adjust your registered callback if you change it. Trust only your actual reverse proxies so Laravel recognizes HTTPS and marks the browser cookie Secure. Use a shared cache supporting atomic locks across all application instances and keep your Laravel encryption key stable.

## Browser flow

1. Request `GET /api/oauth/whilesmart/login` from your website, allowing the response cookie. The JSON `data.url` is the authorization destination.
2. Navigate the browser to that URL. Whilesmart asks the person to sign in and consent.
3. Whilesmart returns the browser to your registered callback. The callback consumes its browser-bound transaction once and returns your normal package login response, including a local Sanctum token or a pending local two-factor challenge. Your website's callback integration handles that response using its existing login UI.

The callback is a JSON API, not an automatic redirect to your application's home page. Keep the login start and callback on the same HTTPS origin. A server-rendered host may customize the callback response through the existing response formatter or controller publishing mechanism. Do not forward local tokens through query strings.

State, nonce and PKCE are generated and stored server-side for ten minutes. The host-only HttpOnly SameSite=Lax cookie binds the browser. Discovery and all discovered endpoints must use the configured HTTPS issuer host and port. Identity tokens require RS256, an RSA key of at least 2048 bits, correct issuer/audience/nonce and valid times; user-info must identify the same subject.

## Existing accounts and linking

A Whilesmart identity is keyed by issuer plus subject, independently of email. A new local account requires a verified Whilesmart email and passes the package's email-domain restrictions. When that email already exists locally, ordinary sign-in returns 409 instead of silently linking accounts.

After authenticating locally and completing any required two-factor challenge, POST `/api/oauth/whilesmart/link` with the local Sanctum personal access token. Navigate to `data.url` as above. The callback rechecks that token's validity and returns `Whilesmart account linked.` without issuing another local token. An identity cannot be linked to a different local account. Subsequent sign-ins resolve the linked account before examining email.

Existing social-provider identities remain separate. Whilesmart login uses the configured user model, normal OAuth login/callback hooks, the OAuth-authenticated event and normal local two-factor sign-in enforcement. Your response formatter continues to control JSON responses.

## Optional delegated API credentials

The package discards provider credentials by default. To retain encrypted credentials for your own application code, enable `USER_AUTH_WHILESMART_RETAIN_TOKENS=true` and set `user-authentication.whilesmart.scopes` to the identity scopes plus the delegated permissions your application needs. Production file reads and offline access require Whilesmart permission review; source workspaces must also allow delegation.

```php
config(['user-authentication.whilesmart.scopes' => [
    'openid', 'profile', 'email', 'files.selected.read', 'offline_access',
]]);
```

Resolve the logged-in user's association using its user type and ID plus your configured issuer. Read `credentials` from `WhilesmartIdentity`; the model encrypts it at rest and hides it from serialization. Use its access token as an explicit bearer credential when calling the public Files API for a selected ID. Provider tokens do not authenticate your local Laravel routes. Your application's agents use that same limited user delegation and must keep your own approval rules.

Access tokens last fifteen minutes. Refresh with the public token endpoint and the confidential client credentials, persisting the replacement encrypted token atomically under a shared lock. Refresh families expire thirty days after code exchange. Never retry a consumed or uncertain refresh: replay revokes the family. Restart authorization instead. The package does not automatically refresh credentials. To disconnect remotely, revoke the grant through the public revocation endpoint or Accounts Connected Apps; deleting a local association alone does not revoke remote consent.

## API responses

| Route | Success | Main errors |
| --- | --- | --- |
| `GET /oauth/whilesmart/login` | 200 with authorization URL and browser cookie | 503 when configuration or discovery is unavailable |
| `POST /oauth/whilesmart/link` | 200 with authorization URL and browser cookie | 401/403 for local authentication; 400 when linking cannot begin |
| `GET /oauth/whilesmart/callback` | 200 with local login, two-factor challenge or link confirmation | 400 for failed/expired/replayed authorization; 409 for identity collisions; 422 for missing verified email or disallowed domain |

All three routes are throttled to twenty requests per minute and return `Cache-Control: no-store`. The callback accepts GET only. Use HTTPS in production and avoid logging OAuth callback queries, token responses or retained credentials.

## Limits

Only confidential server clients are supported by this adapter. Browser bindings and transactions last ten minutes. Identity-only sign-in and selected-file reads do not provide editor embedding or write access. The default scopes create accounts; if you omit verified email, only a previously linked account can sign in. Automatic provider refresh, unlink management and provider-token export are left to the host application. Keep the same encryption key when retaining credentials and use a shared lock-capable cache for multiple instances.
