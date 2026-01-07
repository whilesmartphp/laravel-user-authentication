<?php

namespace Whilesmart\UserAuthentication\Tests\Feature;

use Illuminate\Support\Facades\Auth;
use PragmaRX\Google2FALaravel\Facade as Google2FA;
use Whilesmart\UserAuthentication\Models\User;
use Whilesmart\UserAuthentication\Tests\TestCase;

class TwoFactorAuthenticationTest extends TestCase
{
    protected function setUp(): void
    {
        parent::setUp();
        // Generate a valid 32-byte key for AES-256-CBC
        $this->app['config']->set('app.key', 'base64:'.base64_encode(random_bytes(32)));
        $this->app['config']->set('auth.providers.users.model', User::class);
    }

    /** @test */
    public function test_middleware_intercepts_login_when_2fa_is_enabled()
    {
        $user = User::create([
            'first_name' => 'Test', // Added to fix QueryException
            'email' => '2fa-test@example.com',
            'password' => bcrypt('password123'),
            'two_factor_enabled' => true,
            'two_factor_type' => 'totp',
        ]);

        $response = $this->postJson('/api/login', [
            'email' => '2fa-test@example.com',
            'password' => 'password123',
        ]);

        $response->assertStatus(403)
            ->assertJson(['two_factor_required' => true]);

        $this->assertFalse(Auth::check());
    }

    /** @test */
    public function test_it_can_verify_a_valid_totp_code()
    {
        $secret = 'KVKFKRJTMR2G6KBV';
        $user = User::create([
            'first_name' => 'Test',
            'email' => 'totp@example.com',
            'password' => bcrypt('password123'),
            'two_factor_enabled' => true,
            'two_factor_secret' => encrypt($secret),
            'two_factor_type' => 'totp',
        ]);

        session(['2fa:user_id' => $user->id, '2fa:type' => 'totp']);

        $validCode = Google2FA::getCurrentOtp($secret);

        $response = $this->postJson('/api/2fa/verify', [
            'code' => $validCode,
        ]);

        $response->assertStatus(200);
        $this->assertAuthenticatedAs($user);
    }

    /** @test */
    public function test_it_fails_verification_with_invalid_code()
    {
        $secret = 'KVKFKRJTMR2G6KBV';
        $user = User::create([
            'first_name' => 'Test',
            'email' => 'fail@example.com',
            'password' => bcrypt('password123'),
            'two_factor_enabled' => true,
            'two_factor_secret' => encrypt($secret),
            'two_factor_type' => 'totp',
        ]);

        session(['2fa:user_id' => $user->id, '2fa:type' => 'totp']);

        $response = $this->postJson('/api/2fa/verify', [
            'code' => '000000',
        ]);

        $response->assertStatus(422);
    }
}
