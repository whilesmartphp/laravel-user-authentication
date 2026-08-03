# Laravel User Authentication Package

## Project Overview

This is `whilesmart/laravel-user-authentication`, a Laravel package maintained by **WhileSmart** for managing user authentication across PHP projects. It provides API-first authentication endpoints for registration, login, logout, password reset, OAuth (Google, Apple, etc. via Socialite and Firebase), email/phone verification, and two-factor authentication (TOTP and magic links).

- **Package name:** `whilesmart/laravel-user-authentication`
- **Current version:** `1.0.5`
- **License:** MIT
- **PHP requirement:** `^8.3`
- **Primary language:** English (code, comments, and documentation)

The package is intended to be installed into a Laravel application via Composer. It auto-registers its service provider, routes, migrations, and translations.

## Technology Stack

| Layer | Technology |
|-------|------------|
| Language | PHP 8.3+ |
| Framework | Laravel (package built with Orchestra Testbench) |
| API Authentication | Laravel Sanctum |
| OAuth | Laravel Socialite + Kreait Laravel Firebase |
| 2FA | PragmaRX Google2FA Laravel |
| Managed Verification | SmartPings PHP SDK (`smartpings/php-sdk`) |
| Testing | PHPUnit + Orchestra Testbench |
| Code Style | Laravel Pint (PSR-12 preset), PHP_CodeSniffer |
| Static Analysis | PHPStan level 5 + Larastan |
| Mess Detection | PHPMD |
| Documentation | OpenAPI (Swagger PHP attributes) |
| Local Runtime | Docker Compose (PHP 8.3 CLI + MySQL 8.0) |

## Directory Structure

```
config/                         Package configuration
  user-authentication.php       Main config file (env-driven)
database/migrations/            Package migrations
docs/                           Markdown guides for consumers
  installation.md
  verification.md
  customization.md
lang/en/                        Translation files
routes/                         Route definitions
  user-authentication.php       Core auth + 2FA routes
  social-login.php              OAuth routes
src/                            Package source (PSR-4: Whilesmart\UserAuthentication\)
  Documentation/                OpenAPI docs class
  Enums/                        HookAction enum
  Events/                       Laravel events dispatched by the package
  Http/Controllers/Auth/        Auth, PasswordReset, TwoFactor controllers
  Http/Middleware/              two-factor middleware
  Interfaces/                   ResponseFormatterInterface, MiddlewareHookInterface
  Models/                       User, VerificationCode, OauthAccount, TwoFactorAuth, MagicLink
  ResponseFormatters/           Default JSON response formatter
  Rules/                        EmailDomainRestriction validation rule
  Services/                     SmartPingsVerificationService, TwoFactorService
  Traits/                       ApiResponse, HasMiddlewareHooks, HasTwoFactorAuth, Loggable
  UserAuthenticationServiceProvider.php
tests/                          PHPUnit feature tests
  Feature/                      One test class per feature area
  TestCase.php                  Base Orchestra Testbench test case
workbench/                      Orchestra Testbench workbench app
  app/Models/User.php
  database/migrations/          Sanctum + OAuth migration stubs for tests
demo/                           React + Vite demo frontend (see note below)
```

## Code Organization

- **Controllers** live in `src/Http/Controllers/Auth/` and extend `Illuminate\Routing\Controller`. They use the `ApiResponse`, `HasMiddlewareHooks`, and `Loggable` traits.
- **Models** are in `src/Models/`. The default `User` model extends `Authenticatable`, uses Sanctum, and includes the `HasTwoFactorAuth` trait. Consumers can override the user model via `config('user-authentication.user_model')`.
- **Services** encapsulate verification and 2FA logic:
  - `SmartPingsVerificationService` delegates sending/verifying codes to SmartPings when enabled.
  - `TwoFactorService` handles TOTP, email/SMS challenges, and magic-link generation.
- **Events** provide extensibility hooks: `UserRegisteredEvent`, `UserLoggedInEvent`, `UserLoggedOutEvent`, `VerificationCodeGeneratedEvent`, `PasswordResetCodeGeneratedEvent`, `PasswordResetCompleteEvent`, `OauthUserAuthenticatedEvent`.
- **Traits**:
  - `ApiResponse` delegates response formatting to the configured formatter.
  - `HasMiddlewareHooks` runs configurable `before`/`after` hooks around controller actions.
  - `HasTwoFactorAuth` adds the polymorphic `twoFactorAuth` relation and `hasTwoFactorEnabled()` helper.
- **Interfaces** allow customization:
  - `ResponseFormatterInterface` for custom API response shapes.
  - `MiddlewareHookInterface` for injecting request/response hooks.

## Routes

Routes are prefixed with `config('user-authentication.route_prefix')` (default: `api`).

Core routes (`routes/user-authentication.php`):
- `POST /register`
- `POST /login`
- `POST /logout` (auth:sanctum)
- `POST /send-verification-code`
- `POST /verify-code`
- `POST /password/reset-code`
- `POST /password/reset`
- `POST /2fa/setup` (auth:sanctum)
- `POST /2fa/confirm` (auth:sanctum)
- `POST /2fa/disable` (auth:sanctum)
- `POST /2fa/verify` (throttled)
- `POST /2fa/resend` (throttled)
- `GET /2fa/verify-link/{user}` (signed URL)

OAuth routes (`routes/social-login.php`):
- `GET /oauth/{driver}/login`
- `GET /oauth/{driver}/callback`
- `POST /oauth/firebase/{driver}/callback`

## Configuration

The main config file is `config/user-authentication.php`. Important settings:

- `user_model` — override the default user model.
- `route_prefix` — prefix for all package routes (`USER_AUTH_ROUTE_PREFIX`).
- `register_routes` / `register_oauth_routes` — toggle route registration.
- `response_formatter` — class implementing `ResponseFormatterInterface`.
- `verification.*` — email/phone verification toggles, code length/expiry, rate limits, provider.
- `smartpings.*` — SmartPings credentials.
- `email_restrictions.*` — whitelist/blacklist email domains.
- `oauth_scopes` — per-provider Socialite scopes.
- `encrypt_oauth_tokens` — encrypt stored OAuth tokens.
- `middleware_hooks` — array of hook classes.

Environment variables are documented in `README.md` and start with `USER_AUTH_*` and `SMARTPINGS_*`.

## Build and Test Commands

### Composer scripts (run from repo root)

```bash
composer test            # Run PHPUnit tests with coverage via Orchestra Testbench
composer pint            # Apply Laravel Pint (PSR-12 preset)
composer pint:test       # Check Laravel Pint formatting without fixing
composer lint            # Alias for pint (applies fixes)
composer phpstan         # Run PHPStan level 5 on src/
composer phpmd           # Run PHPMD on src/
composer phpcs           # Run PHP CodeBeautifier on src/
composer phpcs:test      # Run PHP_CodeSniffer on src/
composer openapi         # Generate docs/api.json from OpenAPI attributes
composer build           # Build workbench skeleton
composer serve           # Build and serve the workbench locally
composer clear           # Purge workbench skeleton
composer prepare         # Discover package in workbench
```

### Make commands (Docker)

The project includes a `Makefile` that wraps Docker Compose commands:

```bash
make fresh      # Down, up, and install dependencies
make setup      # fresh + test
make install    # Start containers and run composer install
make test       # Run tests inside the app container
make pint       # Run pint inside container
make lint       # pint + phpcs + phpstan + phpmd
make build      # Build workbench inside container
make serve      # Serve workbench inside container
make up/down/restart/logs/shell  # Docker lifecycle commands
```

Docker Compose (`docker-compose.yml`) defines:
- `app`: PHP 8.3 CLI container, running `tail -f /dev/null`, with the repo mounted at `/app`.
- `mysql`: MySQL 8.0 service for local development/testing.

## Testing Strategy

- **Framework:** PHPUnit through Orchestra Testbench.
- **Test location:** `tests/Feature/`
- **Base class:** `Whilesmart\UserAuthentication\Tests\TestCase`
- **Database:** Tests use a SQLite file at `database/database.sqlite` (created on the fly if missing) with `RefreshDatabase`.
- **Coverage:** The `tests.yml` GitHub Action enforces a minimum code-coverage threshold of **65.8%**.
- **Test categories:**
  - `AuthenticationTest` — registration, login (email/phone/username), password reset, verification flows, SmartPings integration.
  - `VerificationSecurityTest` — rate limiting, expiration, bypass prevention.
  - `TwoFactorAuthenticationTest`, `TwoFactorMiddlewareTest`, `TwoFactorVerifyTest` — TOTP setup/confirm/disable, middleware interception, recovery codes, magic links.
  - `OauthTest` — Socialite callback handling and OAuth account linking.
  - `EmailRestrictionTest` — whitelist/blacklist domain validation.
  - `LogoutTest`, `MagicLinkTest`.

Run tests locally:

```bash
vendor/bin/testbench package:test
# or with coverage
vendor/bin/testbench package:test --coverage
```

## Code Style Guidelines

- **PSR-12** is the canonical style, enforced by Laravel Pint (`composer pint:test`).
- **PHP_CodeSniffer** (`composer phpcs:test`) provides an additional standards check.
- **PHPStan** runs at level 5 with Larastan; `phpstan.neon` includes the Larastan and Carbon extensions.
- **PHPMD** uses `phpmd.xml`, which imports standard rulesets with relaxed thresholds for Laravel-typical patterns.
- Class/method comments use Laravel-style docblocks.
- `@codeCoverageIgnore` is used on enum methods and the OpenAPI docs class.
- `@phpstan-ignore-next-line` is used sparingly where static analysis cannot infer framework behavior.

## Commit Message Conventions

This project follows [Conventional Commits](https://www.conventionalcommits.org/) with a custom type list. Commit messages are validated by the `commits.yml` GitHub Actions workflow using `@commitlint/config-conventional`.

Format:

```
<type>(<scope>): <subject>

<body>

<footer>
```

- **Type** (required): One of `feat`, `fix`, `docs`, `style`, `refactor`, `test`, `chore`, `build`, `ci`, `enh`, `enhance`, `tweak`, `imp`, `improve`.
- **Scope** (optional): A short name of the affected part of the codebase, e.g., `auth`, `2fa`, `tests`.
- **Subject** (required): A brief description in sentence-case, starting with a capital letter. Maximum **80 characters**.
- **Body** (optional): A more detailed explanation of the change.
- **Footer** (optional): Related issue references, breaking change notes, etc.

Example:

```
feat(auth): Add TOTP-based two-factor authentication

Introduces the TwoFactorAuth model, HasTwoFactorAuth trait, and
TwoFactorService to support TOTP setup, verification, and recovery codes.

Refs: #21
```

For the full shared convention, see [WhileSmart Commit Conventions](https://github.com/whilesmart/conventions/blob/main/commits.md).

## Security Considerations

- **Verification codes** are stored as bcrypt hashes in the `verification_codes` table.
- **Rate limiting** is applied to password-reset and verification-code endpoints, keyed by both IP and contact.
- **2FA secrets and recovery codes** are encrypted at rest via Eloquent casts (`encrypted`, `encrypted:array`).
- **OAuth tokens** can be optionally encrypted via `encrypt_oauth_tokens` config.
- **Magic links** are single-use, signed, and expire.
- **Email domain restrictions** support whitelist or blacklist modes.
- **SmartPings** mode delegates verification to an external service; missing credentials throw an exception at service construction.
- Controllers do not trust frontend flags for verification status; backend state is checked during registration.

## CI/CD and Automation

GitHub Actions workflows are in `.github/workflows/`:

- `tests.yml` — Runs the test suite on PHP 8.3/8.4/8.5 against MySQL 5.7 and enforces coverage.
- `lint-sniffs.yml` — Runs `phpcs:test`, `phpstan`, `phpmd`, `pint:test`, and verifies OpenAPI generation.
- `run-tests.yml` — Legacy/test workflow using PHP 8.2 and SQLite.
- `validate-docs.yml` — Validates documentation using the whilesmart docs-kit action when docs change.
- `pre-release.yml` / `release.yml` — WhileSmart shared workflows for release management.
- `commits.yml` — Validates conventional commit messages; allowed types include `feat`, `fix`, `docs`, `style`, `refactor`, `test`, `chore`, `build`, `ci`, `enh`, `enhance`, `tweak`, `imp`, `improve`. Subject should be sentence-case and header max 80 chars.

## Publishing and Customization

Consumers can publish package assets into their app:

```bash
php artisan vendor:publish --tag=laravel-user-authentication-config
php artisan vendor:publish --tag=laravel-user-authentication-migrations
php artisan vendor:publish --tag=laravel-user-authentication-routes
php artisan vendor:publish --tag=laravel-user-authentication-controllers
php artisan vendor:publish --tag=laravel-user-authentication-docs
```

Customization points:
- Implement `ResponseFormatterInterface` for custom JSON envelopes.
- Implement `MiddlewareHookInterface` and register classes in `middleware_hooks`.
- Listen to package events for side effects (email/SMS, logging, analytics).

## Notes for Agents

- The package is **not** a standalone Laravel app; it is a package tested inside an Orchestra Testbench workbench.
- The `demo/` directory contains a React + Vite frontend. Its `README.md` references passkey endpoints, but those endpoints are not currently implemented in this package; treat that README as stale unless you find matching source code.
- Always run `composer test` after non-trivial changes.
- Run `composer pint:test`, `composer phpstan`, and `composer phpmd` before considering lint-clean work complete.
- When adding new events, models, or config keys, update the relevant documentation in `docs/` and the OpenAPI documentation class in `src/Documentation/UserAuthOpenApiDocs.php`.
- Migrations in `database/migrations/` are loaded automatically by the service provider; workbench-specific migrations live in `workbench/database/migrations/`.
- Never commit or push codes to the remote repository without authorization from the user.
