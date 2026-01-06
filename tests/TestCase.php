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
}
