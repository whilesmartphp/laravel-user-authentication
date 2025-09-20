# Laravel User Authentication Package

A comprehensive Laravel authentication package with support for registration, login, password reset, OAuth integration, and configurable email/phone verification.

## Features

* **Complete Authentication System:**
  * User registration with customizable fields
  * Login with email, phone, or username
  * Password reset functionality
  * OAuth integration (Google, Apple, etc.)
  
* **Email/Phone Verification:**
  * Configurable verification before registration
  * Event-driven integration with any email/SMS provider
  * Built-in SmartPings integration for managed verification
  * Rate limiting and security features
  * 5-minute code expiry (configurable)

* **Developer-Friendly:**
  * OpenAPI documentation with PHP attributes
  * Customizable response formatting
  * Middleware hooks for custom logic
  * Event system for extensibility

* **Security Features:**
  * Backend verification validation
  * Rate limiting protection
  * Secure code generation and storage

## Quick Start

```bash
composer require whilesmart/laravel-user-authentication
php artisan migrate
```

That's it! The package will auto-register routes and work out of the box.

**📖 [Full Installation Guide](docs/installation.md)**

## Email/Phone Verification

### Option 1: SmartPings Integration (Managed)

For hassle-free verification with SmartPings handling the entire flow:

```bash
# .env
USER_AUTH_REQUIRE_EMAIL_VERIFICATION=true
USER_AUTH_REQUIRE_PHONE_VERIFICATION=false
USER_AUTH_VERIFICATION_PROVIDER=smartpings
USER_AUTH_SELF_MANAGED=false
USER_AUTH_ROUTE_PREFIX=api

SMARTPINGS_CLIENT_ID=your-client-id
SMARTPINGS_SECRET_ID=your-secret-id
```

All configuration is now environment-driven for better deployment flexibility.

### Option 2: Custom Provider (Self-Managed)

Set up email or phone verification with event-driven integration:

```bash
# .env
USER_AUTH_REQUIRE_EMAIL_VERIFICATION=true
USER_AUTH_REQUIRE_PHONE_VERIFICATION=false
USER_AUTH_VERIFICATION_PROVIDER=default
USER_AUTH_SELF_MANAGED=true
USER_AUTH_CODE_LENGTH=6
USER_AUTH_CODE_EXPIRY_MINUTES=5
USER_AUTH_RATE_LIMIT_ATTEMPTS=3
USER_AUTH_RATE_LIMIT_MINUTES=5
USER_AUTH_ROUTE_PREFIX=api
```

Create event listeners to send codes via your preferred provider:

```php
class SendVerificationCodeEmailListener {
    public function handle(VerificationCodeGeneratedEvent $event) {
        Mail::raw("Your code: {$event->code}", function($msg) use ($event) {
            $msg->to($event->contact)->subject('Verification Code');
        });
    }
}
```

**📖 [Complete Verification Setup Guide](docs/verification.md)**

## Environment Variables

All package configuration is now environment-driven. Add these variables to your `.env` file:

### Core Settings
```bash
# Route prefix for all authentication endpoints (default: api)
USER_AUTH_ROUTE_PREFIX=api
```

### Verification Settings
```bash
# Email verification (default: false)
USER_AUTH_REQUIRE_EMAIL_VERIFICATION=false

# Phone verification (default: false)
USER_AUTH_REQUIRE_PHONE_VERIFICATION=false

# Verification provider: 'default' or 'smartpings' (default: default)
USER_AUTH_VERIFICATION_PROVIDER=default

# Self-managed verification (default: true)
# Set to false when using SmartPings to let them handle the flow
USER_AUTH_SELF_MANAGED=true

# Verification code length (default: 6)
USER_AUTH_CODE_LENGTH=6

# Code expiry time in minutes (default: 5)
USER_AUTH_CODE_EXPIRY_MINUTES=5

# Rate limiting attempts before blocking (default: 3)
USER_AUTH_RATE_LIMIT_ATTEMPTS=3

# Rate limiting window in minutes (default: 5)
USER_AUTH_RATE_LIMIT_MINUTES=5
```

### SmartPings Integration
```bash
# Required when USER_AUTH_VERIFICATION_PROVIDER=smartpings
SMARTPINGS_CLIENT_ID=your-client-id
SMARTPINGS_SECRET_ID=your-secret-id
```

## Available Endpoints

* `POST /api/register` - Register a new user
* `POST /api/login` - User login  
* `POST /api/logout` - User logout
* `POST /api/send-verification-code` - Send verification code
* `POST /api/verify-code` - Verify submitted code
* `POST /api/password/reset-code` - Request password reset
* `POST /api/password/reset` - Reset password
* `GET /api/oauth/{provider}/login` - OAuth login
* `GET /api/oauth/{provider}/callback` - OAuth callback

## Events

The package dispatches events for extensibility:

* `UserRegisteredEvent` - After successful registration
* `UserLoggedInEvent` - After successful login  
* `UserLoggedOutEvent` - After logout
* `VerificationCodeGeneratedEvent` - When verification codes are generated
* `PasswordResetCodeGeneratedEvent` - When password reset codes are generated
* `PasswordResetCompleteEvent` - After password reset

## OpenAPI Documentation

To include the authentication endpoints in your OpenAPI specification, publish the documentation class:

```bash
php artisan vendor:publish --provider="Whilesmart\UserAuthentication\UserAuthenticationServiceProvider" --tag="laravel-user-authentication-docs"
```

This will create `app/Http/Documentation/UserAuthOpenApiDocs.php` containing all OpenAPI attributes for the authentication endpoints. Your OpenAPI generator will automatically discover and include these endpoints.

### Alternative: Publish specific tags

```bash
# Publish only documentation
php artisan vendor:publish --tag="laravel-user-authentication-docs"

# Publish only configuration  
php artisan vendor:publish --tag="laravel-user-authentication-config"

# Publish everything
php artisan vendor:publish --provider="Whilesmart\UserAuthentication\UserAuthenticationServiceProvider"
```

## Documentation

* **📖 [Installation Guide](docs/installation.md)** - Complete installation instructions
* **📖 [Email/Phone Verification](docs/verification.md)** - Set up verification with any provider
* **📖 [Customization Guide](docs/customization.md)** - Response formatting, middleware hooks

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.