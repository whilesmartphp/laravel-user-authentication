# Whilesmart Laravel User Authentication Package

This Laravel package provides a complete authentication solution with registration, login, password reset, and OpenAPI
documentation, all ready to use out of the box.

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

### 1. Require the package

   ```bash
   composer require whilesmart/laravel-user-authentication
   ```

### 2. Publish the configuration and migrations:

You do not need to publish the migrations and configurations except if you want to make modifications. You can choose to
publish
the migrations, routes, controllers separately or all at once.

#### 2.1 Publishing only the routes

Run the command below to publish only the routes.

```bash
php artisan vendor:publish --tag=laravel-user-authentication-routes
php artisan migrate
```

The routes will be available at `routes/user-authentication.php`. You should `require` this file in your
`api.php` file.

```php
    require 'user-authentication.php';
```

#### 2.2 Publishing only the migrations

+If you would like to make changes to the migration files, run the command below to publish only the migrations.

```bash
php artisan vendor:publish --tag=laravel-user-authentication-migrations
php artisan migrate
```

The migrations will be available in the `database/migrations` folder.

#### 2.3 Publish only the controllers

To publish the controllers, run the command below

```bash
php artisan vendor:publish --tag=laravel-user-authentication-controllers
php artisan migrate
```

The controllers will be available in the `app/Http/Controllers/Api/Auth` directory.
Finally, change the namespace in the published controllers to your namespace.

#### Note: Publishing the controllers will also publish the routes. See section 2.1

#### 2.4 Publish  the config

To publish the config, run the command below

```bash
php artisan vendor:publish --tag=laravel-user-authentication-config
```

The config file will be available in the `config/user-authentication.php`.
The config file has the folowing variables:

- `register_routes`: Default `true`. Auto registers the routes. If you do not want to auto-register the routes, set the
  value to `false
- `route_prefix`: Default `api`. Defines the prefix for the auto-registered routes.

#### 2.5 Publish everything

To publish the migrations, config, routes, and controllers, you can run the command below

```bash
php artisan vendor:publish --tag=laravel-user-authentication
php artisan migrate
```

#### Note: See section 2.1 above to make the routes accessible

### 3. Updates to the User model

Add the following to the `$fillable` variable in your User model:

```php
'first_name',
'last_name',
'username',
'phone'
```

### 5. **Events Emitted**

This package emits the following events:

1. **UserRegisteredEvent:** This event is emitted after a user successfully registers

```php
UserRegisteredEvent::dispatch($user);
```

2. **UserLoggedInEvent:**: This event is emitted after a user successfully logs in

```php
UserLoggedInEvent::dispatch($user);
```

3. **UserLoggedOutEvent:** This event is emitted after a user successfully logs out

```php
UserLoggedOutEvent::dispatch($user);
```

4. **PasswordResetCompleteEvent:** This event is emitted after a user successfully reset their password

```php
PasswordResetCompleteEvent::dispatch($user);
```

5. **PasswordResetCodeGeneratedEvent:** This event is emitted after a user requests to reset their password

```php
PasswordResetCodeGeneratedEvent::dispatch($email, $verificationCode);
```

## Usage

After installation, the following API endpoints will be available:

* **POST /api/register:** Register a new user.
* **POST /api/login:** Log in an existing user.
* **POST /api/logout:** Logs out an existing user.
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
