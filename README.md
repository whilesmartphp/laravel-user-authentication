# Whilesmart Laravel User Authentication Package

This Laravel package provides a complete authentication solution with registration, login, password reset, and OpenAPI documentation, all ready to use out of the box.

## Features

* **Ready-to-use authentication endpoints:**
    * Registration (first\_name, last\_name, email, phone)
    * Login
    * Password reset (forgot password, reset password)
* **OpenAPI documentation:** Automatically generated documentation using PHP attributes.
* **Customizable user model:** Includes `phone` field.
* **Verification interface:** Enables custom verification logic (e.g., email verification).
* **Configuration file:** Easily customize settings.
* **Laravel agnostic considerations:** designed with future framework agnosticism in mind.

## Installation

1.  **Require the package:**

    ```bash
    composer require whilesmart/laravel-user-authentication
    ```

2.  **Publish the configuration and migrations:**

    ```bash
    php artisan vendor:publish --provider="Whilesmart\Laravel\User\Authentication\Providers\AuthenticationServiceProvider"
    php artisan migrate
    ```

3.  **Implement Verification (Optional):**
    * Create a class that implements `Whilesmart\Laravel\User\Authentication\Interfaces\VerifierInterface`.
    * Bind your implementation in a service provider.
    * Configure the verification setting in `config/authentication.php`.

## Usage

After installation, the following API endpoints will be available:

* **POST /api/register:** Register a new user.
* **POST /api/login:** Log in an existing user.
* **POST /api/password/forgot:** Request a password reset.
* **POST /api/password/reset:** Reset a password.
* **OpenAPI Documentation:** Accessible via a route that your OpenAPI package defines.

**Example Registration Request:**

```json
{
    "first_name": "John",
    "last_name": "Doe",
    "email": "[email address removed]",
    "phone": "+15551234567",
    "password": "password123",
    "password_confirmation": "password123"
}
