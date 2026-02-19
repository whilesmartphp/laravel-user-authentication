<?php

namespace Whilesmart\UserAuthentication\Tests\Feature;

use Faker\Factory;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Hash;
use Whilesmart\UserAuthentication\Events\PasswordResetCodeGeneratedEvent;
use Whilesmart\UserAuthentication\Events\PasswordResetCompleteEvent;
use Whilesmart\UserAuthentication\Events\VerificationCodeGeneratedEvent;
use Whilesmart\UserAuthentication\Models\VerificationCode;
use Whilesmart\UserAuthentication\Services\SmartPingsVerificationService;
use Whilesmart\UserAuthentication\Tests\TestCase;

class AuthenticationTest extends TestCase
{
    public function test_api_user_can_register_successfully()
    {
        $faker = Factory::create();
        $response = $this->postJson('/api/register', [
            'email' => $faker->unique()->safeEmail,
            'first_name' => $faker->firstName,
            'last_name' => $faker->lastName,
            'username' => $faker->userName,
            'phone' => $faker->phoneNumber,
            'password' => 'password123',
        ]);

        $response->assertStatus(201)
            ->assertJsonStructure([
                'success',
                'data' => ['user', 'token'],
                'message',
            ]);

        $this->assertDatabaseHas('users', ['email' => $response->json('data.user.email')]);
    }

    public function test_api_user_receives_register_validation_error_when_required_fields_are_missing()
    {
        $response = $this->postJson('/api/register', []);

        $response->assertStatus(422)
            ->assertJson([
                'success' => false,
                'message' => 'Validation failed.',
                'errors' => [[
                    'email' => ['The email field is required.'],
                    'first_name' => ['The first name field is required.'],
                    'password' => ['The password field is required.'],
                ]],
            ]);
    }

    public function test_api_user_can_login_successfully_with_email()
    {
        $user = $this->createUser();
        $response = $this->postJson('/api/login', [
            'email' => $user->email,
            'password' => 'password123',
        ]);

        $response->assertStatus(200)->assertJsonStructure(['success', 'data' => ['token', 'user']]);
    }

    public function test_api_user_can_login_successfully_with_username()
    {
        $faker = Factory::create();
        $this->postJson('/api/register', [
            'username' => 'testuser',
            'password' => 'password123',
            'first_name' => 'John',
            'last_name' => 'Doe',
            'email' => $faker->unique()->safeEmail,
        ]);

        $response = $this->postJson('/api/login', [
            'username' => 'testuser',
            'password' => 'password123',
        ]);

        $response->assertStatus(200);
    }

    public function test_api_user_can_login_successfully_with_phone()
    {
        $faker = Factory::create();
        $this->postJson('/api/register', [
            'phone' => '1234567890',
            'password' => 'password123',
            'first_name' => 'John',
            'last_name' => 'Doe',
            'email' => $faker->unique()->safeEmail,
        ]);

        $response = $this->postJson('/api/login', [
            'phone' => '1234567890',
            'password' => 'password123',
        ]);

        $response->assertStatus(200);
    }

    public function test_api_user_login_failed_with_invalid_credentials()
    {
        $user = $this->createUser();
        $response = $this->postJson('/api/login', [
            'email' => $user->email,
            'password' => 'wrongpassword',
        ]);

        $response->assertStatus(401)->assertJson(['success' => false]);
    }

    public function test_api_user_login_failed_with_unregistered_user()
    {
        $faker = Factory::create();
        $response = $this->postJson('/api/login', [
            'email' => $faker->unique()->safeEmail,
            'password' => 'password123',
        ]);

        $response->assertStatus(401);
    }

    public function test_api_user_receives_login_validation_error_when_required_fields_are_missing()
    {
        $response = $this->postJson('/api/login', []);
        $response->assertStatus(422);
    }

    public function test_send_password_reset_code()
    {
        Event::fake();
        $user = $this->createUser();
        $response = $this->postJson('/api/password/reset-code', ['email' => $user->email]);

        $response->assertStatus(200);
        Event::assertDispatched(PasswordResetCodeGeneratedEvent::class);
    }

    public function test_send_password_reset_code_rate_limit()
    {
        $user = $this->createUser();
        for ($i = 0; $i < 6; $i++) {
            $this->postJson('/api/password/reset-code', ['email' => $user->email]);
        }
        $response = $this->postJson('/api/password/reset-code', ['email' => $user->email]);
        $response->assertStatus(429);
    }

    public function test_reset_password_with_code()
    {
        Event::fake();
        $user = $this->createUser();
        $verificationCode = 123456;

        VerificationCode::create([
            'contact' => $user->email,
            'code' => Hash::make($verificationCode),
            'purpose' => 'password_reset',
            'expires_at' => now()->addMinutes(15),
        ]);

        $response = $this->postJson('/api/password/reset', [
            'email' => $user->email,
            'code' => $verificationCode,
            'new_password' => 'newpassword123',
            'new_password_confirmation' => 'newpassword123',
        ]);

        $response->assertStatus(200);
        Event::assertDispatched(PasswordResetCompleteEvent::class);
    }

    public function test_reset_password_with_invalid_code()
    {
        $user = $this->createUser();
        $response = $this->postJson('/api/password/reset', [
            'email' => $user->email,
            'code' => 123456,
            'new_password' => 'newpassword123',
            'new_password_confirmation' => 'newpassword123',
        ]);

        $response->assertStatus(400);
    }

    public function test_send_verification_code_successfully()
    {
        Event::fake();
        $email = 'test@example.com';
        $response = $this->postJson('/api/send-verification-code', [
            'contact' => $email,
            'type' => 'email',
            'purpose' => 'registration',
        ]);

        $response->assertStatus(200);
        Event::assertDispatched(VerificationCodeGeneratedEvent::class);
    }

    public function test_send_verification_code_phone_successfully()
    {
        Event::fake();
        $phone = '001234567890';
        $response = $this->postJson('/api/send-verification-code', [
            'contact' => $phone,
            'type' => 'phone',
            'purpose' => 'registration',
        ]);

        $response->assertStatus(200);
        Event::assertDispatched(VerificationCodeGeneratedEvent::class);
    }

    public function test_send_verification_code_validation_error()
    {
        $response = $this->postJson('/api/send-verification-code', []);
        $response->assertStatus(422);
    }

    public function test_send_verification_code_rate_limit()
    {
        $email = 'limit@example.com';
        for ($i = 0; $i < 6; $i++) {
            $this->postJson('/api/send-verification-code', ['contact' => $email, 'type' => 'email', 'purpose' => 'registration']);
        }
        $response = $this->postJson('/api/send-verification-code', ['contact' => $email, 'type' => 'email', 'purpose' => 'registration']);
        $response->assertStatus(429);
    }

    public function test_verify_code_successfully()
    {
        $email = 'verify@example.com';
        $code = 123456;
        VerificationCode::create([
            'contact' => $email,
            'code' => Hash::make($code),
            'purpose' => 'registration_email',
            'expires_at' => now()->addMinutes(5),
        ]);

        $response = $this->postJson('/api/verify-code', [
            'contact' => $email,
            'code' => (string) $code,
            'type' => 'email',
            'purpose' => 'registration',
        ]);

        $response->assertStatus(200);
    }

    public function test_verify_code_invalid_code()
    {
        $email = 'invalid@example.com';
        $response = $this->postJson('/api/verify-code', [
            'contact' => $email,
            'code' => '000000',
            'type' => 'email',
            'purpose' => 'registration',
        ]);

        $response->assertStatus(400);
    }

    public function test_verify_code_expired_code()
    {
        $email = 'expired@example.com';
        VerificationCode::create([
            'contact' => $email,
            'code' => Hash::make('123456'),
            'purpose' => 'registration_email',
            'expires_at' => now()->subMinutes(1),
        ]);

        $response = $this->postJson('/api/verify-code', [
            'contact' => $email,
            'code' => '123456',
            'type' => 'email',
            'purpose' => 'registration',
        ]);

        $response->assertStatus(400);
    }

    public function test_verify_code_no_code_found()
    {
        $response = $this->postJson('/api/verify-code', [
            'contact' => 'none@example.com',
            'code' => '123456',
            'type' => 'email',
            'purpose' => 'registration',
        ]);

        $response->assertStatus(400);
    }

    public function test_verify_code_validation_error()
    {
        $response = $this->postJson('/api/verify-code', []);
        $response->assertStatus(422);
    }

    public function test_register_without_verification_enabled()
    {
        $faker = Factory::create();
        $response = $this->postJson('/api/register', [
            'email' => $faker->unique()->safeEmail,
            'first_name' => $faker->firstName,
            'last_name' => $faker->lastName,
            'password' => 'password123',
        ]);

        $response->assertStatus(201);
    }

    public function test_register_with_email_verification_enabled_but_not_verified()
    {
        config(['user-authentication.verification.require_email_verification' => true]);
        $response = $this->postJson('/api/register', [
            'email' => 'unverified@example.com',
            'first_name' => 'John',
            'last_name' => 'Doe',
            'password' => 'password123',
        ]);

        $response->assertStatus(422);
    }

    public function test_register_with_email_verification_enabled_and_verified()
    {
        config(['user-authentication.verification.require_email_verification' => true]);
        $email = 'verified@example.com';
        VerificationCode::create([
            'contact' => $email,
            'code' => Hash::make('123456'),
            'purpose' => 'registration_email',
            'expires_at' => now()->addMinutes(5),
            'verified_at' => now(),
        ]);

        $response = $this->postJson('/api/register', [
            'email' => $email,
            'first_name' => 'John',
            'last_name' => 'Doe',
            'password' => 'password123',
        ]);

        $response->assertStatus(201);
    }

    public function test_register_with_phone_verification_enabled_but_not_verified()
    {
        config(['user-authentication.verification.require_phone_verification' => true]);
        $response = $this->postJson('/api/register', [
            'email' => 'phone@example.com',
            'phone' => '123456',
            'first_name' => 'John',
            'last_name' => 'Doe',
            'password' => 'password123',
        ]);

        $response->assertStatus(422);
    }

    public function test_register_with_phone_verification_enabled_and_verified()
    {
        config(['user-authentication.verification.require_phone_verification' => true]);
        $phone = '1234567890';
        VerificationCode::create([
            'contact' => $phone,
            'code' => Hash::make('123456'),
            'purpose' => 'registration_phone',
            'expires_at' => now()->addMinutes(5),
            'verified_at' => now(),
        ]);

        $response = $this->postJson('/api/register', [
            'email' => 'phone-verified@example.com',
            'phone' => $phone,
            'first_name' => 'John',
            'last_name' => 'Doe',
            'password' => 'password123',
        ]);

        $response->assertStatus(201);
    }

    public function test_smartpings_service_is_disabled_when_not_configured()
    {
        config(['user-authentication.verification.provider' => 'default']);
        $service = new SmartPingsVerificationService;
        $this->assertFalse($service->isEnabled());
    }

    public function test_smartpings_send_verification_returns_error_when_disabled()
    {
        config(['user-authentication.verification.provider' => 'default']);
        $service = new SmartPingsVerificationService;
        $result = $service->sendVerification('test@example.com', 'email');
        $this->assertFalse($result['success']);
    }

    public function test_send_verification_code_with_smartpings_enabled()
    {
        config([
            'user-authentication.verification.provider' => 'smartpings',
            'user-authentication.smartpings.client_id' => 'test',
            'user-authentication.smartpings.secret_id' => 'test',
        ]);

        $mock = $this->createMock(SmartPingsVerificationService::class);
        $mock->method('isEnabled')->willReturn(true);
        $mock->method('sendVerification')->willReturn(['success' => true, 'message' => 'Sent']);
        $this->app->bind(SmartPingsVerificationService::class, fn () => $mock);

        $response = $this->postJson('/api/send-verification-code', [
            'contact' => 'test@example.com', 'type' => 'email', 'purpose' => 'registration',
        ]);

        $response->assertStatus(200);
    }

    public function test_verify_code_with_smartpings_enabled()
    {
        config(['user-authentication.verification.provider' => 'smartpings']);
        $mock = $this->createMock(SmartPingsVerificationService::class);
        $mock->method('isEnabled')->willReturn(true);
        $mock->method('verify')->willReturn(true);
        $this->app->bind(SmartPingsVerificationService::class, fn () => $mock);

        $response = $this->postJson('/api/verify-code', [
            'contact' => 'test@example.com', 'code' => '123456', 'type' => 'email', 'purpose' => 'registration',
        ]);

        $response->assertStatus(200);
    }

    public function test_register_with_smartpings_email_verification_enabled_and_verified()
    {
        config(['user-authentication.verification.require_email_verification' => true, 'user-authentication.verification.provider' => 'smartpings']);
        $mock = $this->createMock(SmartPingsVerificationService::class);
        $mock->method('isEnabled')->willReturn(true);
        $mock->method('isVerified')->willReturn(true);
        $this->app->bind(SmartPingsVerificationService::class, fn () => $mock);

        $response = $this->postJson('/api/register', [
            'email' => 'sp@example.com', 'first_name' => 'J', 'last_name' => 'D', 'password' => 'password123',
        ]);

        $response->assertStatus(201);
    }

    public function test_register_with_smartpings_email_verification_enabled_but_not_verified()
    {
        config(['user-authentication.verification.require_email_verification' => true, 'user-authentication.verification.provider' => 'smartpings']);
        $mock = $this->createMock(SmartPingsVerificationService::class);
        $mock->method('isEnabled')->willReturn(true);
        $mock->method('isVerified')->willReturn(false);
        $this->app->bind(SmartPingsVerificationService::class, fn () => $mock);

        $response = $this->postJson('/api/register', [
            'email' => 'sp-fail@example.com', 'first_name' => 'J', 'last_name' => 'D', 'password' => 'password123',
        ]);

        $response->assertStatus(422);
    }
}
