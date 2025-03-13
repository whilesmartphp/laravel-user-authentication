<?php

namespace Whilesmart\LaravelUserAuthentication;

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
        ], ['user-authentication', 'user-authentication-migrations']);

        Route::prefix('api')->group(function () {
            $this->loadRoutesFrom(__DIR__.'/../routes/user-authentication.php');
        });

        $this->publishes([
            __DIR__.'/../routes/user-authentication.php' => base_path('routes/user-authentication.php'),
        ], ['user-authentication', 'user-authentication-routes', 'user-authentication-controllers']);

        $this->publishes([
            __DIR__.'/Http/Controllers' => app_path('Http/Controllers/Api'),
        ], ['user-authentication', 'user-authentication-controllers']);

        // Publish config
        $this->publishes([
            __DIR__.'/../config/user-authentication.php' => config_path('user-authentication.php'),
        ], ['user-authentication', 'user-authentication-controllers']);
    }
}
