<?php

namespace Whilesmart\UserAuthentication\Tests;

use Faker\Factory;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\Hash;
use Laravel\Sanctum\SanctumServiceProvider;
use Laravel\Socialite\Facades\Socialite;
use Laravel\Socialite\SocialiteServiceProvider;
use Orchestra\Testbench\Attributes\WithMigration;
use PragmaRX\Google2FALaravel\ServiceProvider as Google2FAServiceProvider;
use Symfony\Component\Uid\Uuid;
use Webauthn\CredentialRecord;
use Webauthn\TrustPath\EmptyTrustPath;
use Whilesmart\UserAuthentication\Models\Passkey;
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

    /**
     * Helper to create a test user.
     */
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
     * Helper to create a test passkey for a user.
     */
    protected function createPasskey(User $user, string $credentialId = 'dGVzdA'): Passkey
    {
        $unique = bin2hex(random_bytes(8));

        $record = new CredentialRecord(
            publicKeyCredentialId: 'test-id-' . $unique,
            type: 'public-key',
            transports: ['internal'],
            attestationType: 'none',
            trustPath: new EmptyTrustPath(),
            aaguid: Uuid::fromString('00000000-0000-0000-0000-000000000000'),
            credentialPublicKey: 'key',
            userHandle: (string) $user->id,
            counter: 0,
        );

        $data = Passkey::webAuthnSerializer()->serialize($record, 'json');

        return $user->passkeys()->create([
            'name' => 'Test Passkey',
            'credential_id' => $credentialId . '-' . $unique,
            'data' => $data,
        ]);
    }

    /**
     * Define database migrations.
     */
    protected function defineDatabaseMigrations()
    {
        $this->loadMigrationsFrom(
            workbench_path('database/migrations')
        );
    }

    /**
     * Get package providers.
     */
    protected function getPackageProviders($app)
    {
        return [
            \Whilesmart\UserAuthentication\UserAuthenticationServiceProvider::class,
            SanctumServiceProvider::class,
            SocialiteServiceProvider::class,
            Google2FAServiceProvider::class,
        ];
    }

    /**
     * Get package aliases.
     */
    protected function getPackageAliases($app)
    {
        return [
            'Socialite' => Socialite::class,
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
    }
}
