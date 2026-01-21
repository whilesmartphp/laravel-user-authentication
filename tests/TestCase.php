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
        // Use a hardcoded key string
        $app['config']->set('app.key', 'base64:u8699SXL9N99Fz3E1lV9f8R96789012345678901234=');

        // Also, ensure the session driver is 'array' for testing to avoid the Cookie error
        $app['config']->set('session.driver', 'array');

        $app->singleton('encrypter', function ($app) {
            $config = $app->make('config')->get('app');
            $key = $config['key'];

            if (str_starts_with($key, 'base64:')) {
                $key = base64_decode(substr($key, 7));
            }

            return new \Illuminate\Encryption\Encrypter($key, $config['cipher']);
        });
    }

    protected function defineRoutes($router)
    {
        $router->get('/api/user-profile', function () {
            return response()->json(['message' => 'Access Granted']);
        })->middleware(['web', 'auth', \Whilesmart\UserAuthentication\Http\Middleware\RedirectIfTwoFactorEnabled::class]);

    }
}
