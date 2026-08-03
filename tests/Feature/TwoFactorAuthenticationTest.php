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
    }

    /** @test */
    public function test_user_can_initiate_2fa_setup()
    {
        $user = $this->createUser();
        $this->actingAs($user, 'sanctum');

        $response = $this->postJson('/api/2fa/setup');

        $response->assertStatus(200)
            ->assertJsonStructure(['data' => ['secret', 'qr_code_url']]);

        $this->assertDatabaseHas('two_factor_auths', [
            'authenticatable_id' => $user->id,
            'is_enabled' => false,
        ]);
    }

    /** @test */
    public function test_user_can_confirm_and_enable_2fa()
    {
        $user = $this->createUser();
        $this->actingAs($user, 'sanctum');

        // Create the pending record
        $secret = 'KVKFKRJTMR2G6KBV';
        $user->twoFactorAuth()->create([
            'secret' => $secret, // Model cast handles encryption
            'type' => 'totp',
            'is_enabled' => false,
        ]);

        $validCode = Google2FA::getCurrentOtp($secret);

        $response = $this->postJson('/api/2fa/confirm', ['code' => $validCode]);

        $response->assertStatus(200)
            ->assertJsonStructure(['data' => ['recovery_codes']]);

        $this->assertTrue($user->fresh()->hasTwoFactorEnabled());
    }

    /** @test */
    public function test_it_can_verify_via_recovery_code()
    {
        $user = $this->createUser();
        $user->twoFactorAuth()->create([
            'secret' => 'KVKFKRJTMR2G6KBV',
            'type' => 'totp',
            'is_enabled' => true,
            'recovery_codes' => ['ABCDE12345', 'XYZ789'],
        ]);

        session(['2fa:user_id' => $user->id, '2fa:type' => 'totp']);

        // Try login with recovery code
        $response = $this->postJson('/api/2fa/verify', ['code' => 'ABCDE12345']);

        $response->assertStatus(200);
        $this->assertAuthenticatedAs($user);

        // Assert code was consumed (removed from DB)
        $updatedCodes = $user->fresh()->twoFactorAuth->getRawOriginal('recovery_codes');
        $this->assertStringNotContainsString('ABCDE12345', $updatedCodes);
    }

    /** @test */
    public function test_middleware_intercepts_login_when_2fa_is_enabled()
    {
        $user = User::create([
            'first_name' => 'Test',
            'email' => '2fa-test@example.com',
            'password' => bcrypt('password123'),
        ]);

        $user->twoFactorAuth()->create([
            'type' => 'totp',
            'is_enabled' => true,
            'secret' => 'KVKFKRJTMR2G6KBV',
        ]);

        $response = $this->postJson('/api/login', [
            'email' => '2fa-test@example.com',
            'password' => 'password123',
        ]);

        $response->assertStatus(200);
        $response->assertJson([
            'success' => true,
            'message' => 'Two-factor authentication required.',
            'data' => [
                'two_factor_required' => true,
                'method' => 'totp',
            ],
        ]);
        // Ensure the user remains unauthenticated/not logged in
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
        ]);
        $user->twoFactorAuth()->create([
            'type' => 'totp',
            'is_enabled' => true,
            'secret' => $secret, // Cast handles encryption
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
        ]);
        $user->twoFactorAuth()->create([
            'type' => 'totp',
            'is_enabled' => true,
            'secret' => $secret, // Cast handles encryption
        ]);

        session(['2fa:user_id' => $user->id, '2fa:type' => 'totp']);

        $response = $this->postJson('/api/2fa/verify', [
            'code' => '000000',
        ]);

        $response->assertStatus(422);
    }

    /** @test */
    public function test_cannot_confirm_2fa_without_initiating_setup()
    {
        $user = $this->createUser();
        $this->actingAs($user, 'sanctum');

        $response = $this->postJson('/api/2fa/confirm', ['code' => '123456']);

        $response->assertStatus(400)
            ->assertJsonFragment(['message' => '2FA setup has not been initiated.']);
    }

    /** @test */
    public function test_cannot_disable_2fa_when_not_enabled()
    {
        $user = $this->createUser();
        $this->actingAs($user, 'sanctum');

        $response = $this->postJson('/api/2fa/disable', ['code' => '123456']);

        $response->assertStatus(400)
            ->assertJsonFragment(['message' => 'Two-factor authentication is not enabled.']);
    }

    /** @test */
    public function test_cannot_disable_2fa_with_invalid_code()
    {
        $user = $this->createUser();
        $this->actingAs($user, 'sanctum');
        $secret = 'KVKFKRJTMR2G6KBV';
        $user->twoFactorAuth()->create([
            'secret' => $secret,
            'type' => 'totp',
            'is_enabled' => true,
        ]);

        $response = $this->postJson('/api/2fa/disable', ['code' => '000000']);

        $response->assertStatus(422)
            ->assertJsonFragment(['message' => 'Invalid code. Could not disable 2FA.']);
    }

    /** @test */
    public function test_user_can_disable_2fa_with_valid_code()
    {
        $user = $this->createUser();
        $this->actingAs($user, 'sanctum');
        $secret = 'KVKFKRJTMR2G6KBV';
        $user->twoFactorAuth()->create([
            'secret' => $secret,
            'type' => 'totp',
            'is_enabled' => true,
        ]);

        $validCode = Google2FA::getCurrentOtp($secret);

        $response = $this->postJson('/api/2fa/disable', ['code' => $validCode]);

        $response->assertStatus(200)
            ->assertJsonFragment(['message' => 'Two-factor authentication has been disabled.']);

        $this->assertDatabaseMissing('two_factor_auths', [
            'authenticatable_id' => $user->id,
        ]);
    }

    /** @test */
    public function test_resend_fails_for_totp()
    {
        $user = $this->createUser();
        session(['2fa:user_id' => $user->id, '2fa:type' => 'totp', '2fa:contact' => $user->email]);

        $response = $this->postJson('/api/2fa/resend');

        $response->assertStatus(400)
            ->assertJsonFragment(['message' => 'TOTP codes are generated by your authenticator app.']);
    }

    /** @test */
    public function test_resend_succeeds_for_email_2fa()
    {
        $user = $this->createUser();
        session(['2fa:user_id' => $user->id, '2fa:type' => 'email', '2fa:contact' => $user->email]);

        $response = $this->postJson('/api/2fa/resend');

        $response->assertStatus(200)
            ->assertJsonFragment(['message' => 'A new verification code has been sent.']);
    }
}
