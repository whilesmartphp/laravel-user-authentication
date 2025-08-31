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

Set up email or phone verification before registration with event-driven integration:

```php
// Enable in config/user-authentication.php
'verification' => [
    'require_email_verification' => true,
    'code_expiry_minutes' => 5,
],

// Create event listeners to send codes via your preferred provider
class SendVerificationCodeEmailListener {
    public function handle(VerificationCodeGeneratedEvent $event) {
        Mail::raw("Your code: {$event->code}", function($msg) use ($event) {
            $msg->to($event->contact)->subject('Verification Code');
        });
    }
}
```

**📖 [Complete Verification Setup Guide](docs/verification.md)**

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

## Documentation

* **📖 [Installation Guide](docs/installation.md)** - Complete installation instructions
* **📖 [Email/Phone Verification](docs/verification.md)** - Set up verification with any provider
* **📖 [Customization Guide](docs/customization.md)** - Response formatting, middleware hooks

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.