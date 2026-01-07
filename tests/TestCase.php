<?php

namespace Whilesmart\UserAuthentication\Tests;

use Faker\Factory;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\Hash;
use Orchestra\Testbench\Attributes\WithMigration;
use PragmaRX\Google2FALaravel\ServiceProvider as Google2FAServiceProvider;
use Whilesmart\UserAuthentication\Models\User;

use function Orchestra\Testbench\workbench_path;

#[WithMigration]
abstract class TestCase extends \Orchestra\Testbench\TestCase
{
    use RefreshDatabase;

    protected function createUser(array $attributes = []): User
    {
        return User::create(array_merge([
            'email' => Factory::create()->unique()->safeEmail,
            'password' => Hash::make('password123'),
            'first_name' => 'John',
            'last_name' => 'Doe',
            'two_factor_enabled' => false,
            'two_factor_secret' => null,
            'two_factor_type' => 'totp',
        ], $attributes));
    }

    protected function defineDatabaseMigrations()
    {
        $this->loadMigrationsFrom(
            workbench_path('database/migrations')
        );
    }

    protected function getPackageProviders($app)
    {
        return [
            'Whilesmart\UserAuthentication\UserAuthenticationServiceProvider',
            Google2FAServiceProvider::class,
        ];
    }

    protected function getEnvironmentSetUp($app)
    {
        // Use your package's User model for authentication
        $app['config']->set('auth.providers.users.model', \Whilesmart\UserAuthentication\Models\User::class);
        $app['config']->set('user-authentication.user_model', \Whilesmart\UserAuthentication\Models\User::class);

        // Crucial for DecryptException: Set a stable key
        $app['config']->set('app.key', 'base64:yl96S6X6X6X6X6X6X6X6X6X6X6X6X6X6X6X6X6X6X6=');
    }

    protected function defineRoutes($router)
    {
        $router->get('/api/user-profile', function () {
            return response()->json(['message' => 'Access Granted']);
        })->middleware(['web', 'auth', \Whilesmart\UserAuthentication\Http\Middleware\RedirectIfTwoFactorEnabled::class]);

    }
}
