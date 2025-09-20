<?php

use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\Config;
use Illuminate\Support\Facades\Hash;
use Orchestra\Testbench\Attributes\WithMigration;
use Whilesmart\UserAuthentication\Models\VerificationCode;

#[WithMigration]
class VerificationSecurityTest extends TestCase
{
    use RefreshDatabase;

    private array $validRegistrationData = [
        'email' => 'test@example.com',
        'first_name' => 'John',
        'last_name' => 'Doe',
        'password' => 'password123',
    ];

    /** @test */
    public function verification_code_send_is_rate_limited_by_contact()
    {
        Config::set('user-authentication.verification.rate_limit_attempts', 2);
        Config::set('user-authentication.verification.rate_limit_minutes', 5);

        $verificationData = [
            'contact' => 'test@example.com',
            'type' => 'email',
            'purpose' => 'registration',
        ];

        // First two requests should succeed
        $this->postJson('/api/send-verification-code', $verificationData)->assertStatus(200);
        $this->postJson('/api/send-verification-code', $verificationData)->assertStatus(200);

        // Third request should be rate limited by contact hash
        $response = $this->postJson('/api/send-verification-code', $verificationData);
        $response->assertStatus(429)
            ->assertJson([
                'success' => false,
                'message' => 'Too many attempts, please try again later.',
            ]);
    }

    /** @test */
    public function expired_verification_codes_are_cleaned_up()
    {
        // Create some expired codes
        VerificationCode::create([
            'contact' => 'test1@example.com',
            'code' => Hash::make('123456'),
            'purpose' => 'registration_email',
            'expires_at' => now()->subHours(1),
        ]);

        VerificationCode::create([
            'contact' => 'test2@example.com',
            'code' => Hash::make('654321'),
            'purpose' => 'registration_email',
            'expires_at' => now()->addMinutes(5), // Not expired
        ]);

        $this->assertEquals(2, VerificationCode::count());

        // Trigger cleanup by sending a new verification code
        $this->postJson('/api/send-verification-code', [
            'contact' => 'test3@example.com',
            'type' => 'email',
            'purpose' => 'registration',
        ]);

        // Should have cleaned up the expired one and added a new one
        $this->assertEquals(2, VerificationCode::count());
        $this->assertDatabaseMissing('verification_codes', [
            'contact' => 'test1@example.com',
        ]);
    }

    /** @test */
    public function registration_bypasses_verification_when_disabled_via_env()
    {
        // Test that env variables are properly respected
        Config::set('user-authentication.verification.require_email_verification', false);

        $response = $this->postJson('/api/register', $this->validRegistrationData);

        $response->assertStatus(201);
        $this->assertDatabaseHas('users', ['email' => 'test@example.com']);
    }

    /** @test */
    public function registration_enforces_verification_when_enabled_via_env()
    {
        // Test that env variables are properly respected
        Config::set('user-authentication.verification.require_email_verification', true);

        $response = $this->postJson('/api/register', $this->validRegistrationData);

        $response->assertStatus(422)
            ->assertJson([
                'success' => false,
                'message' => 'Email verification required. Please verify your email first.',
            ]);

        $this->assertDatabaseMissing('users', ['email' => 'test@example.com']);
    }

    /** @test */
    public function smartpings_fallback_throws_exception_when_credentials_missing()
    {
        // Enable SmartPings but don't provide credentials
        Config::set('user-authentication.verification.provider', 'smartpings');
        Config::set('user-authentication.verification.self_managed', false);
        Config::set('user-authentication.smartpings.client_id', null);
        Config::set('user-authentication.smartpings.secret_id', null);

        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('SmartPings verification is enabled but credentials are missing');

        // This should throw an exception when the service is instantiated
        app(\Whilesmart\UserAuthentication\Services\SmartPingsVerificationService::class);
    }

    /** @test */
    public function registration_is_completely_blocked_when_verification_required_and_not_completed()
    {
        // CRITICAL SECURITY TEST: Ensure no bypass is possible
        Config::set('user-authentication.verification.require_email_verification', true);

        // Try various registration attempts that should all fail
        $registrationData = $this->validRegistrationData;

        // Attempt 1: Direct registration
        $response = $this->postJson('/api/register', $registrationData);
        $response->assertStatus(422);
        $this->assertDatabaseMissing('users', ['email' => 'test@example.com']);

        // Attempt 2: Registration with additional fields
        $response = $this->postJson('/api/register', array_merge($registrationData, [
            'username' => 'testuser',
            'phone' => '+1234567890',
        ]));
        $response->assertStatus(422);
        $this->assertDatabaseMissing('users', ['email' => 'test@example.com']);

        // Attempt 3: Registration with unverified code exists
        VerificationCode::create([
            'contact' => 'test@example.com',
            'code' => Hash::make('123456'),
            'purpose' => 'registration_email',
            'expires_at' => now()->addMinutes(5),
            'verified_at' => null, // Not verified
        ]);

        $response = $this->postJson('/api/register', $registrationData);
        $response->assertStatus(422);
        $this->assertDatabaseMissing('users', ['email' => 'test@example.com']);
    }

    /** @test */
    public function two_step_verification_requires_both_send_and_verify_steps()
    {
        Config::set('user-authentication.verification.require_email_verification', true);

        // Step 1: Cannot register without any verification
        $response = $this->postJson('/api/register', $this->validRegistrationData);
        $response->assertStatus(422)
            ->assertJson(['success' => false, 'message' => 'Email verification required. Please verify your email first.']);

        // Step 2: Send verification code
        $response = $this->postJson('/api/send-verification-code', [
            'contact' => 'test@example.com',
            'type' => 'email',
            'purpose' => 'registration',
        ]);
        $response->assertStatus(200);

        // Step 3: Registration should still fail even after sending code (not verified yet)
        $response = $this->postJson('/api/register', $this->validRegistrationData);
        $response->assertStatus(422)
            ->assertJson(['success' => false, 'message' => 'Email verification required. Please verify your email first.']);

        // Step 4: Verify the code
        $codeRecord = VerificationCode::where('contact', 'test@example.com')->first();
        $this->assertNotNull($codeRecord);
        $this->assertNull($codeRecord->verified_at); // Should not be verified yet

        // Create a known verification code for testing
        VerificationCode::where('contact', 'test@example.com')->delete();
        VerificationCode::create([
            'contact' => 'test@example.com',
            'code' => Hash::make('123456'),
            'purpose' => 'registration_email',
            'expires_at' => now()->addMinutes(5),
        ]);

        $response = $this->postJson('/api/verify-code', [
            'contact' => 'test@example.com',
            'code' => '123456',
            'type' => 'email',
            'purpose' => 'registration',
        ]);
        $response->assertStatus(200);

        // Step 5: Now registration should succeed
        $response = $this->postJson('/api/register', $this->validRegistrationData);
        $response->assertStatus(201);
        $this->assertDatabaseHas('users', ['email' => 'test@example.com']);
    }

    /** @test */
    public function verification_security_prevents_timing_attacks()
    {
        Config::set('user-authentication.verification.require_email_verification', true);

        // Test that non-existent verification codes return same response as wrong codes
        $response1 = $this->postJson('/api/verify-code', [
            'contact' => 'nonexistent@example.com',
            'code' => '123456',
            'type' => 'email',
            'purpose' => 'registration',
        ]);

        VerificationCode::create([
            'contact' => 'test@example.com',
            'code' => Hash::make('654321'),
            'purpose' => 'registration_email',
            'expires_at' => now()->addMinutes(5),
        ]);

        $response2 = $this->postJson('/api/verify-code', [
            'contact' => 'test@example.com',
            'code' => '123456', // Wrong code
            'type' => 'email',
            'purpose' => 'registration',
        ]);

        // Both should return the same error message and status
        $response1->assertStatus(400)->assertJson(['success' => false, 'message' => 'Invalid or expired code.']);
        $response2->assertStatus(400)->assertJson(['success' => false, 'message' => 'Invalid or expired code.']);
    }

    /** @test */
    public function verification_codes_have_proper_expiration_enforcement()
    {
        Config::set('user-authentication.verification.require_email_verification', true);
        Config::set('user-authentication.verification.code_expiry_minutes', 5);

        // Create an expired code
        VerificationCode::create([
            'contact' => 'test@example.com',
            'code' => Hash::make('123456'),
            'purpose' => 'registration_email',
            'expires_at' => now()->subMinutes(1), // Expired 1 minute ago
        ]);

        // Verification should fail
        $response = $this->postJson('/api/verify-code', [
            'contact' => 'test@example.com',
            'code' => '123456',
            'type' => 'email',
            'purpose' => 'registration',
        ]);
        $response->assertStatus(400)
            ->assertJson(['success' => false, 'message' => 'Invalid or expired code.']);

        // Registration should fail
        $response = $this->postJson('/api/register', $this->validRegistrationData);
        $response->assertStatus(422)
            ->assertJson(['success' => false, 'message' => 'Email verification required. Please verify your email first.']);
    }
}
