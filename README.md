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
The config file has the following variables:

- `register_routes`: Default `true`. Auto registers the routes. If you do not want to auto-register the routes, set the
  value to `false
- `register_oauth_routes`: Default `true`. Auto registers the oauth routes. If you do not want to auto-register the
  oauth routes, set the
  value to `false
- `route_prefix`: Default `api`. Defines the prefix for the auto-registered routes.
- `response_formatter`: Default `\Whilesmart\UserAuthentication\ResponseFormatters\DefaultResponseFormatter::class`. Defines the class responsible for formatting API responses.
- `middleware_hooks`: Default `[]`. An array of classes implementing `\Whilesmart\UserAuthentication\Interfaces\MiddlewareHookInterface` to run custom logic before authentication actions.

#### 2.5 Publish everything

To publish the migrations, config, routes, and controllers, you can run the command below

```bash
php artisan vendor:publish --tag=laravel-user-authentication
php artisan migrate
```

#### Note: See section 2.1 above to make the routes accessible

### 3. Oauth Configuration

This package uses `laravel/socialite` for oauth. Please refer to
the [Socialite Documentation](https://laravel.com/docs/12.x/socialite) if your application requires oauth.

### 4. Updates to the User model

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

## Customization

### Custom Response Formatting

This package allows you to customize the format of API responses by implementing the `ResponseFormatterInterface`.

1.  **Create a Custom Formatter:**
    Create a class that implements `Whilesmart\UserAuthentication\Interfaces\ResponseFormatterInterface`.

    ```php
    namespace App\ResponseFormatters;

    use Illuminate\Http\JsonResponse;
    use Whilesmart\UserAuthentication\Interfaces\ResponseFormatterInterface;

    class CustomResponseFormatter implements ResponseFormatterInterface
    {
        public function success(array $data = [], string $message = 'Operation successful', int $statusCode = 200): JsonResponse
        {
            return response()->json([
                'status' => 'success',
                'message' => $message,
                'data' => $data,
            ], $statusCode);
        }

        public function failure(string $message = 'Operation failed', int $statusCode = 400, array $errors = []): JsonResponse
        {
            return response()->json([
                'status' => 'error',
                'message' => $message,
                'errors' => $errors,
            ], $statusCode);
        }
    }
    ```

2.  **Register Your Custom Formatter:**
    Update the `config/user-authentication.php` file to use your custom formatter:

    ```php
    // config/user-authentication.php
    return [
        // ...
        'response_formatter' => \App\ResponseFormatters\CustomResponseFormatter::class,
        // ...
    ];
    ```

### Middleware Hooks

You can inject custom logic before certain authentication actions by implementing the `MiddlewareHookInterface`.

#### Hook Actions

The package provides predefined hook actions through the `HookAction` enum for type safety:

```php
use Whilesmart\UserAuthentication\Enums\HookAction;

// Available predefined actions:
HookAction::REGISTER             // 'register'
HookAction::LOGIN               // 'login'
HookAction::LOGOUT              // 'logout'
HookAction::OAUTH_LOGIN         // 'oauthLogin'
HookAction::OAUTH_CALLBACK      // 'oauthCallback'
HookAction::PASSWORD_RESET_REQUEST  // 'passwordResetRequest'
HookAction::PASSWORD_RESET      // 'passwordReset'
```

You can also use custom string actions for your own implementations:

```php
$this->runBeforeHooks($request, 'myCustomAction');
```

1.  **Create a Middleware Hook:**
    Create a class that implements `Whilesmart\UserAuthentication\Interfaces\MiddlewareHookInterface`.

    ```php
    namespace App\Http\Middleware;

    use Illuminate\Http\Request;
    use Whilesmart\UserAuthentication\Interfaces\MiddlewareHookInterface;
    use Whilesmart\UserAuthentication\Enums\HookAction;

    class CustomAuthHook implements MiddlewareHookInterface
    {
        public function before(Request $request, string $action): ?Request
        {
            // Perform actions before the main controller logic
            // The $action parameter will contain the string value of the action
            
            // Example: Handle specific predefined actions
            switch ($action) {
                case HookAction::LOGIN->value:
                    \Log::info("User attempting to log in: " . $request->input('email'));
                    break;
                case HookAction::REGISTER->value:
                    \Log::info("New user registration attempt");
                    break;
                case 'myCustomAction':
                    // Handle your custom action
                    break;
            }

            // For example, logging, additional validation, or modifying the request.
            \Log::info("Before {$action} action for user: " . ($request->user()->id ?? 'Guest'));

            // If you want to stop the request and return a response,
            // you can throw an exception or return a JsonResponse directly.
            // For example:
            // if ($action === HookAction::LOGIN->value && $request->input('email') === 'blocked@example.com') {
            //     abort(response()->json(['message' => 'User blocked'], 403));
            // }

            return $request; // Always return the request
        }

        public function after(Request $request, JsonResponse $response, string $action): JsonResponse
        {
            // Perform actions after the main controller logic and before the response is sent.
            // The $action parameter will contain the string value of the action.

            // Example: Modify the response based on the action
            switch ($action) {
                case HookAction::LOGIN->value:
                    \Log::info("User successfully logged in. Response status: " . $response->getStatusCode());
                    break;
                case HookAction::REGISTER->value:
                    \Log::info("User registered. Response status: " . $response->getStatusCode());
                    break;
            }

            // For example, logging, adding headers, or modifying the response content.
            \Log::info("After {$action} action. Response status: " . $response->getStatusCode());

            return $response; // Always return the response
        }
    }
    ```

2.  **Register Your Middleware Hook:**
    Add your hook class to the `middleware_hooks` array in `config/user-authentication.php`:

    ```php
    // config/user-authentication.php
    return [
        // ...
        'middleware_hooks' => [
            \App\Http\Middleware\CustomAuthHook::class,
            // Add more hooks as needed
        ],
        // ...
    ];
    ```

## Usage

After installation, the following API endpoints will be available:

* **POST /api/register:** Register a new user.
* **POST /api/login:** Log in an existing user.
* **POST /api/logout:** Logs out an existing user.
* **POST /api/password/forgot:** Request a password reset.
* **POST /api/password/reset:** Reset a password.
* **GET /api/oauth/{provider}/login:** Initiate oauth login.
* **GET /api/oauth/{provider}/callback:** Oauth login callback.
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
```

## Development Environment

This package includes a minimal Docker setup for local development and testing.

### Prerequisites

*   Docker and Docker Compose installed on your system.

### Setup

1.  **Build and Start Containers:**
    Navigate to the root of the package and run:

    ```bash
    docker-compose up --build -d
    ```

    This will build the `app` service (PHP environment) and start the `mysql` service.

2.  **Install Composer Dependencies:**
    Once the `app` container is running, execute Composer install within the container:

    ```bash
    docker-compose exec app composer install
    ```

3.  **Run Migrations:**
    Run the database migrations to set up the necessary tables:

    ```bash
    docker-compose exec app vendor/bin/testbench migrate
    ```

### Usage

You can now execute `testbench` commands or run tests within the `app` container:

```bash
docker-compose exec app vendor/bin/testbench package:test
docker-compose exec app vendor/bin/testbench serve
```