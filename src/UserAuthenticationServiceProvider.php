<?php

namespace Whilesmart\LaravelUserAuthentication;

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
        //
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

        if (config('laravel-user-authentication.register_routes', true)) {
            $this->loadRoutesFrom(__DIR__.'/../routes/laravel-user-authentication.php');
        }
        $this->publishes([
            __DIR__.'/../routes/laravel-user-authentication.php' => base_path('routes/laravel-user-authentication.php'),
        ], ['laravel-user-authentication', 'laravel-user-authentication-routes', 'laravel-user-authentication-controllers']);

        $this->publishes([
            __DIR__.'/Http/Controllers' => app_path('Http/Controllers/Api'),
        ], ['laravel-user-authentication', 'laravel-user-authentication-controllers']);

        // Publish config
        $this->publishes([
            __DIR__.'/../config/laravel-user-authentication.php' => config_path('laravel-user-authentication.php'),
        ], ['laravel-user-authentication', 'laravel-user-authentication-controllers']);
    }
}
