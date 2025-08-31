# Customization

## Custom Response Formatting

This package allows you to customize the format of API responses by implementing the `ResponseFormatterInterface`.

1. **Create a Custom Formatter:**
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

2. **Register Your Custom Formatter:**
   Update the `config/user-authentication.php` file to use your custom formatter:

   ```php
   // config/user-authentication.php
   return [
       // ...
       'response_formatter' => \App\ResponseFormatters\CustomResponseFormatter::class,
       // ...
   ];
   ```

## Middleware Hooks

You can inject custom logic before certain authentication actions by implementing the `MiddlewareHookInterface`.

### Hook Actions

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

1. **Create a Middleware Hook:**
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
           switch ($action) {
               case HookAction::LOGIN->value:
                   \Log::info("User attempting to log in: " . $request->input('email'));
                   break;
               case HookAction::REGISTER->value:
                   \Log::info("New user registration attempt");
                   break;
           }

           return $request; // Always return the request
       }

       public function after(Request $request, JsonResponse $response, string $action): JsonResponse
       {
           // Perform actions after the main controller logic
           \Log::info("After {$action} action. Response status: " . $response->getStatusCode());

           return $response; // Always return the response
       }
   }
   ```

2. **Register Your Middleware Hook:**
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