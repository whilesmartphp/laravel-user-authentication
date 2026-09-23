<?php

namespace Whilesmart\UserAuthentication\Tests;

use Faker\Factory;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\Hash;
use Laravel\Sanctum\SanctumServiceProvider;
use Laravel\Socialite\Facades\Socialite;
use Laravel\Socialite\SocialiteServiceProvider;
use Orchestra\Testbench\Attributes\WithMigration;
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
        ];
    }

    /**
     * Define environment setup.
     */
    protected function getEnvironmentSetUp($app)
    {
        $app['config']->set('auth.guards.sanctum', [
            'driver' => 'sanctum',
            'provider' => 'users',
        ]);
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
}
