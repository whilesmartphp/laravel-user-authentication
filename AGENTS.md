# AGENTS.md — whilesmart/laravel-user-authentication

This is a **Laravel package** (not a standalone app). Tests use **Orchestra Testbench**.

## Quick commands

| Command | What it does |
|---------|-------------|
| `composer test` | Run all tests with coverage |
| `composer pint` | Format code (PSR-12 preset — **not** the Laravel preset) |
| `composer pint:test` | Check formatting only |
| `composer phpstan` | Static analysis, level 5 (`src/`, 2048M memory) |
| `composer phpmd` | Mess detection on `src/` |
| `composer phpcs:test` | PHPCS check on `src/` |
| `composer openapi` | Generate `docs/api.json` from PHP attributes |
| `composer serve` | Build workbench + start dev server |

**Lint pipeline order:** `pint:test` → `phpcs:test` → `phpstan` → `phpmd`

## Docker dev (alternative to direct composer)

```bash
make up         # docker compose up -d
make install    # up + composer install
make test       # test in container
make lint       # pint + phpcs + phpstan + phpmd
make shell      # bash in container
make fresh      # down + up + install
```

## Architecture

- **Namespace:** `Whilesmart\UserAuthentication\` → `src/`
- **Test namespace:** `Whilesmart\UserAuthentication\Tests\` → `tests/`
- **Service provider:** `UserAuthenticationServiceProvider` — auto-loads routes, migrations, translations, publishes config/docs/controllers
- **Routes auto-register** under `USER_AUTH_ROUTE_PREFIX` (default: `api`). Disable via config keys `register_routes` / `register_oauth_routes`.
- **Config:** All env-driven with `USER_AUTH_*` prefix, published to `config/user-authentication.php`
- **Test base class:** `tests/TestCase.php` — extends `Orchestra\Testbench\TestCase`, uses `RefreshDatabase`, loads `SocialiteServiceProvider`, creates users via `createUser()` helper
- **Key deps:** Sanctum (API tokens), Socialite (OAuth), kreait/laravel-firebase, web-auth/webauthn-lib, smartpings/php-sdk
- **User model:** `src/Models/User.php` — uses `HasApiTokens`, `HasPasskeys`

## Package structure

| Directory | Purpose |
|-----------|---------|
| `src/Http/Controllers/Auth/` | `AuthController`, `PasskeyController`, `PasswordResetController` |
| `src/Models/` | `User`, `VerificationCode`, `OauthAccount`, `Passkey` |
| `src/Services/` | `SmartPingsVerificationService`, `PasskeyService` |
| `src/Events/` | 7 events (register, login, logout, verification, password reset, OAuth) |
| `src/Traits/` | `ApiResponse`, `HasMiddlewareHooks`, `HasPasskeys`, `Loggable` |
| `config/` | `user-authentication.php` |
| `routes/` | `user-authentication.php` (auth + passkey), `social-login.php` (OAuth) |

## Key quirks

- **Pint uses PSR-12** (`--preset psr12`), not the default Laravel preset
- **PHPStan level 5** — run on `src/` only, includes Larastan + Carbon extensions
- **Tests use SQLite** (Testbench default), but Docker env spins up MySQL
- **Migrations load from two places:** package's `database/migrations/` and `workbench/database/migrations/` (for test schema)
- **OAuth callback** supports both GET and POST (`Route::match`)
- **Firebase OAuth** uses a dedicated endpoint `/oauth/firebase/{driver}/callback`
- **Passkey session** is stored in cache, configurable lifetime
- **Passkey origin/rp config** requires `USER_AUTH_PASSKEY_ALLOWED_ORIGINS` set to the full origin(s) where the frontend is served (e.g. `https://app.example.com`). `USER_AUTH_PASSKEY_DOMAIN` must also include the scheme (e.g. `https://app.example.com`) because the backend extracts the host with `parse_url()`; a bare hostname causes `rp.id` to be dropped and an **rpId hash mismatch** during registration
- **Passkey resident keys** are opt-in via `USER_AUTH_PASSKEY_RESIDENT_KEYS`. Required for passwordless login without email; disabled by default
- **Email restrictions** support whitelist/blacklist mode via env vars

## Commits

Conventional commit prefixes — short, lowercase, no trailing `.`:

```
feat:       New feature
enh:        Enhancement to existing feature
fix:        Bug fix
chore:      Tooling, deps, CI, refactors with no behaviour change
docs:       Documentation only
```

Use scopes for context when helpful: `feat(oauth):`, `feat(docs):`, `chore(deps):`.

**Capitalize the first word after the colon:** `feat: Add feature`, not `feat: add feature`.

**Do not commit** unless explicitly asked. Before committing, inspect `git status`, `git diff`, and recent log; stage only intended files.
