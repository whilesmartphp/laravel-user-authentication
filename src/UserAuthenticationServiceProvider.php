<?php

namespace Whilesmart\UserAuthentication;

use Illuminate\Support\Facades\Route;
use Illuminate\Support\ServiceProvider;

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
            __DIR__.'/../config/user-authentication.php',
            'user-authentication'
        );

        $this->app->bind(
            \Whilesmart\UserAuthentication\Interfaces\ResponseFormatterInterface::class,
            function ($app) {
                $formatter = config('user-authentication.response_formatter');

                return new $formatter;
            }
        );

        $this->app->singleton(
            \Whilesmart\UserAuthentication\Services\SmartPingsVerificationService::class
        );
    }

    /**
     * Bootstrap services.
     *
     * @return void
     */
    public function boot()
    {

        $this->loadMigrationsFrom(__DIR__.'/../database/migrations');

        $this->publishesMigrations([
            __DIR__.'/../database/migrations' => database_path('migrations'),
        ], ['laravel-user-authentication', 'laravel-user-authentication-migrations']);

        if (config('user-authentication.register_routes', true)) {
            $prefix = config('user-authentication.route_prefix', 'api');
            if ($prefix) {
                Route::prefix($prefix)->group(function () {
                    $this->loadRoutesFrom(__DIR__.'/../routes/user-authentication.php');
                });
            } else {
                $this->loadRoutesFrom(__DIR__.'/../routes/user-authentication.php');
            }
        }
        if (config('user-authentication.register_oauth_routes', true)) {
            $prefix = config('user-authentication.route_prefix', 'api');
            if ($prefix) {
                Route::prefix($prefix)->group(function () {
                    $this->loadRoutesFrom(__DIR__.'/../routes/social-login.php');
                });
            } else {
                $this->loadRoutesFrom(__DIR__.'/../routes/social-login.php');
            }
        }

        $this->publishes([
            __DIR__.'/../routes/user-authentication.php' => base_path('routes/user-authentication.php'),
        ], ['laravel-user-authentication', 'laravel-user-authentication-routes', 'laravel-user-authentication-controllers']);

        $this->publishes([
            __DIR__.'/Http/Controllers' => app_path('Http/Controllers/Api'),
        ], ['laravel-user-authentication', 'laravel-user-authentication-controllers']);

        // Publish config
        $this->publishes([
            __DIR__.'/../config/user-authentication.php' => config_path('user-authentication.php'),
        ], ['laravel-user-authentication', 'laravel-user-authentication-config']);

        // Publish OpenAPI documentation
        $this->publishes([
            __DIR__.'/Documentation/UserAuthOpenApiDocs.php' => app_path('Http/Documentation/UserAuthOpenApiDocs.php'),
        ], ['laravel-user-authentication', 'laravel-user-authentication-docs', 'laravel-user-authentication-openapi']);
    }
}
