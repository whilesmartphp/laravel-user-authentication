<?php

namespace Whilesmart\UserAuthentication;

use Illuminate\Cache\RateLimiting\Limit;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\RateLimiter;
use Illuminate\Support\Facades\Route;
use Illuminate\Support\ServiceProvider;
use Whilesmart\UserAuthentication\Interfaces\ResponseFormatterInterface;
use Whilesmart\UserAuthentication\Services\SmartPingsVerificationService;
use Whilesmart\UserAuthentication\Services\TwoFactorService;

class UserAuthenticationServiceProvider extends ServiceProvider
{
    /**
     * Register services.
     *
     * @return void
     */
    public function register()
    {
        $this->mergeConfigFrom(
            __DIR__ . '/../config/user-authentication.php',
            'user-authentication'
        );

        $this->registerBindings();
    }

    private function registerBindings(): void
    {
        $this->app->bind(
            ResponseFormatterInterface::class,
            function () {
                $formatter = config('user-authentication.response_formatter');

                return new $formatter();
            }
        );

        $this->app->singleton(
            SmartPingsVerificationService::class
        );
    }

    /**
     * Bootstrap services.
     *
     * @return void
     */
    public function boot()
    {
        $this->registerTwoFactorLimiters();
        $this->registerPasskeyLimiters();
        $this->registerRoutes();
        $this->registerPublishing();
        $this->app['router']->aliasMiddleware(
            'two-factor',
            \Whilesmart\UserAuthentication\Http\Middleware\RedirectIfTwoFactorEnabled::class
        );
    }

    private function registerTwoFactorLimiters(): void
    {
        foreach (['verify', 'resend', 'link', 'setup', 'confirm', 'disable'] as $operation) {
            RateLimiter::for('two-factor-' . $operation, function (Request $request) use ($operation) {
                $token = $request->input('two_factor_token');
                if (in_array($operation, ['verify', 'resend', 'link'], true)) {
                    $account = is_string($token) && strlen($token) <= 2048
                        ? app(TwoFactorService::class)->accountKey($token) : 'invalid';
                } else {
                    $user = $request->user();
                    $account = $user
                        ? hash('sha256', $user->getMorphClass() . ':' . $user->getAuthIdentifier()) : 'guest';
                }
                $minutes = max(1, (int) config('user-authentication.two_factor.rate_limits.minutes', 1));
                $attempts = max(1, (int) config('user-authentication.two_factor.rate_limits.' . $operation, 5));

                return [
                    Limit::perMinutes($minutes, $attempts)->by($operation . ':ip:' . $request->ip()),
                    Limit::perMinutes($minutes, $attempts)->by($operation . ':account:' . $account),
                ];
            });
        }
    }

    private function registerPasskeyLimiters(): void
    {
        foreach (['login-options', 'login', 'register-options', 'register'] as $action) {
            RateLimiter::for('passkey-' . $action, function (Request $request) use ($action) {
                $limits = [Limit::perMinute((int) config('user-authentication.passkey.rate_limits.ip'))
                    ->by($action . ':ip:' . $request->ip())];
                $email = str_starts_with($action, 'register')
                    ? $request->user()?->email
                    : $request->input('email');
                if (is_string($email) && $email !== '') {
                    $limits[] = Limit::perMinute((int) config('user-authentication.passkey.rate_limits.email'))
                        ->by($action . ':email:' . hash('sha256', strtolower(trim($email))));
                }
                return $limits;
            });
        }
    }

    private function registerPublishing(): void
    {
        $this->loadTranslationsFrom(__DIR__ . '/../lang', 'user-authentication');

        $this->loadMigrationsFrom(__DIR__ . '/../database/migrations');

        $this->publishesMigrations([
            __DIR__ . '/../database/migrations' => database_path('migrations'),
        ], ['laravel-user-authentication', 'laravel-user-authentication-migrations']);

        if ($this->app->runningInConsole()) {
            $this->publishes([
                __DIR__ . '/../database/migrations' => database_path('migrations'),
            ], 'migrations');
        }

        $this->publishes([
            __DIR__ . '/../routes/user-authentication.php' => base_path('routes/user-authentication.php'),
        ], ['laravel-user-authentication',
            'laravel-user-authentication-routes',
            'laravel-user-authentication-controllers']);

        $this->publishes([
            __DIR__ . '/Http/Controllers' => app_path('Http/Controllers/Api'),
        ], ['laravel-user-authentication', 'laravel-user-authentication-controllers']);

        $this->publishes([
            __DIR__ . '/../config/user-authentication.php' => config_path('user-authentication.php'),
        ], ['laravel-user-authentication', 'laravel-user-authentication-config']);

        $this->publishes([
            __DIR__ . '/Documentation/UserAuthOpenApiDocs.php' => app_path(
                'Http/Documentation/UserAuthOpenApiDocs.php'
            ),
        ], ['laravel-user-authentication', 'laravel-user-authentication-docs', 'laravel-user-authentication-openapi']);
    }

    private function registerRoutes(): void
    {
        $routes = ['register_routes' => 'user-authentication', 'register_oauth_routes' => 'social-login'];
        foreach ($routes as $key => $file) {
            if (! config('user-authentication.' . $key, true)) {
                continue;
            }
            Route::prefix(config('user-authentication.route_prefix', 'api') ?: '')->group(function () use ($file) {
                $this->loadRoutesFrom(__DIR__ . '/../routes/' . $file . '.php');
            });
        }
    }
}
