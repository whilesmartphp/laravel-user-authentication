<?php

namespace Whilesmart\UserAuthentication\Tests;

use Faker\Factory;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\Hash;
use Laravel\Socialite\Facades\Socialite;
use Laravel\Socialite\SocialiteServiceProvider;
use Orchestra\Testbench\Attributes\WithMigration;
use PragmaRX\Google2FALaravel\ServiceProvider as Google2FAServiceProvider;
use Whilesmart\UserAuthentication\Models\User;

use function Orchestra\Testbench\workbench_path;

#[WithMigration]
abstract class TestCase extends \Orchestra\Testbench\TestCase
{
    use RefreshDatabase;

    protected function setUp(): void
    {
        parent::setUp();

        // Default safe config for every test
        config()->set('user-authentication.verification.require_email_verification', false);
    }

    protected function createUser(array $attributes = []): User
    {
        return User::create(array_merge([
            'email' => Factory::create()->unique()->safeEmail,
            'password' => Hash::make('password123'),
            'first_name' => 'John',
            'last_name' => 'Doe',
        ], $attributes));
    }

    /**
     * Define database migrations.
     *
     * @return void
     */
    protected function defineDatabaseMigrations()
    {
        $this->loadMigrationsFrom(
            workbench_path('database/migrations')
        );
    }

    protected function getPackageProviders($app)
    {
        return [
            \Laravel\Sanctum\SanctumServiceProvider::class,
            'Whilesmart\UserAuthentication\UserAuthenticationServiceProvider',
            SocialiteServiceProvider::class,

        ];
    }

    protected function getPackageAliases($app)
    {
        return [
            'Socialite' => Socialite::class,
            Google2FAServiceProvider::class,
        ];
    }

    protected function getEnvironmentSetUp($app)
    {
        // Use a hardcoded key string
        $app['config']->set('app.key', 'base64:u8699SXL9N99Fz3E1lV9f8R96789012345678901234=');
        $app['config']->set('app.cipher', 'AES-256-CBC');

        // Also, ensure the session driver is 'array' for testing to avoid the Cookie error
        $app['config']->set('session.driver', 'array');

        // Add Sanctum Guard Configuration
        $app['config']->set('auth.guards.sanctum', [
            'driver' => 'sanctum',
            'provider' => 'users',
        ]);

        // Create an absolute path to the sqlite file in your tests directory
        $dbPath = __DIR__.'/../database/database.sqlite';

        // If the file doesn't exist, create it on the fly so the test doesn't crash
        if (! file_exists($dbPath)) {
            touch($dbPath);
        }

        $app['config']->set('auth.providers.users.model', \Whilesmart\UserAuthentication\Models\User::class);
        $app['config']->set('database.default', 'testing');
        $app['config']->set('database.connections.testing', [
            'driver' => 'sqlite',
            'database' => $dbPath,
            'prefix' => '',
        ]);

        // Re-add the Sanctum Guard to fix the other failure
        $app['config']->set('auth.guards.sanctum', [
            'driver' => 'sanctum',
            'provider' => 'users',
        ]);

        // $app->singleton('encrypter', function ($app) {
        //     $config = $app->make('config')->get('app');
        //     $key = $config['key'];

        //     if (str_starts_with($key, 'base64:')) {
        //         $key = base64_decode(substr($key, 7));
        //     }

        //     return new \Illuminate\Encryption\Encrypter($key, $config['cipher']);
        // });
    }

    // protected function defineRoutes($router)
    // {
    //     $router->get('/api', function () {
    //         return response()->json(['message' => 'Access Granted']);
    //     })->middleware(['web', 'auth', \Whilesmart\UserAuthentication\Http\Middleware\RedirectIfTwoFactorEnabled::class]);

    // }
}
