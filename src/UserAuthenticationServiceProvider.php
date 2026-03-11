<?php

namespace Whilesmart\UserAuthentication;

use Illuminate\Support\Facades\Route;
use Illuminate\Support\ServiceProvider;
use Whilesmart\UserAuthentication\Interfaces\ResponseFormatterInterface;
use Whilesmart\UserAuthentication\Services\SmartPingsVerificationService;

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

        $this->loadTranslationsFrom(__DIR__ . '/../lang', 'user-authentication');

        $this->loadMigrationsFrom(__DIR__ . '/../database/migrations');

        $this->publishesMigrations([
            __DIR__ . '/../database/migrations' => database_path('migrations'),
        ], ['laravel-user-authentication', 'laravel-user-authentication-migrations']);

        if (config('user-authentication.register_routes', true)) {
            $prefix = config('user-authentication.route_prefix', 'api');
            if ($prefix) {
                Route::prefix($prefix)->group(function () {
                    $this->loadRoutesFrom(__DIR__ . '/../routes/user-authentication.php');
                });
            } else {
                $this->loadRoutesFrom(__DIR__ . '/../routes/user-authentication.php');
            }
        }
        if (config('user-authentication.register_oauth_routes', true)) {
            $prefix = config('user-authentication.route_prefix', 'api');
            if ($prefix) {
                Route::prefix($prefix)->group(function () {
                    $this->loadRoutesFrom(__DIR__ . '/../routes/social-login.php');
                });
            } else {
                $this->loadRoutesFrom(__DIR__ . '/../routes/social-login.php');
            }
        }

        $this->loadMigrationsFrom(__DIR__ . '/../database/migrations');

        // This is vital for Bruno/Web testing:
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

        // Publish config
        $this->publishes([
            __DIR__ . '/../config/user-authentication.php' => config_path('user-authentication.php'),
        ], ['laravel-user-authentication', 'laravel-user-authentication-config']);

        // Publish OpenAPI documentation
        $this->publishes([
            __DIR__ . '/Documentation/UserAuthOpenApiDocs.php' => app_path(
                'Http/Documentation/UserAuthOpenApiDocs.php'
            ),
        ], ['laravel-user-authentication', 'laravel-user-authentication-docs', 'laravel-user-authentication-openapi']);

        // Register Middleware
        $this->app['router']->aliasMiddleware(
            'two-factor',
            \Whilesmart\UserAuthentication\Http\Middleware\RedirectIfTwoFactorEnabled::class
        );
    }
}
