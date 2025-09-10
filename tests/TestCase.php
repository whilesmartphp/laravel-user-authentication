<?php

use Faker\Factory;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Hash;
use Orchestra\Testbench\Attributes\WithMigration;
use Whilesmart\UserAuthentication\Events\PasswordResetCodeGeneratedEvent;
use Whilesmart\UserAuthentication\Events\PasswordResetCompleteEvent;
use Whilesmart\UserAuthentication\Events\VerificationCodeGeneratedEvent;
use Whilesmart\UserAuthentication\Models\User;
use Whilesmart\UserAuthentication\Models\VerificationCode;
use Whilesmart\UserAuthentication\Services\SmartPingsVerificationService;

use function Orchestra\Testbench\workbench_path;

#[WithMigration]
class TestCase extends \Orchestra\Testbench\TestCase
{
    use RefreshDatabase;

    protected function createUser(array $attributes = []): User
    {
        return User::create(array_merge([
            'email' => Factory::create()->unique()->safeEmail,
            'password' => Hash::make('password123'),
            'first_name' => 'John',
            'last_name' => 'Doe',
        ], $attributes));
    }

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
                'data' => [
                    'user',
                    'token',
                ],
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
                'errors' => [
                    [
                        'email' => ['The email field is required.'],
                        'first_name' => ['The first name field is required.'],
                        'password' => ['The password field is required.'],
                    ],
                ],
            ]);
    }

    public function test_api_user_can_login_successfully_with_email()
    {
        $user = $this->createUser();

        $response = $this->postJson('/api/login', [
            'email' => $user->email,
            'password' => 'password123',
        ]);

        $response->assertStatus(200)
            ->assertJsonStructure([
                'success',
                'data' => [
                    'token',
                    'user',
                ],
                'message',
            ]);
    }

    public function test_api_user_can_login_successfully_with_username()
    {
        $faker = Factory::create();
        $response = $this->postJson('/api/register', [
            'username' => 'testuser',
            'password' => 'password123',
            'first_name' => 'John',
            'last_name' => 'Doe',
            'email' => $faker->unique()->safeEmail,
        ]);

        $response->assertStatus(201);

        $response = $this->postJson('/api/login', [
            'username' => 'testuser',
            'password' => 'password123',
        ]);

        $response->assertStatus(200)
            ->assertJsonStructure([
                'success',
                'data' => [
                    'token',
                    'user',
                ],
                'message',
            ]);
    }

    public function test_api_user_can_login_successfully_with_phone()
    {
        $faker = Factory::create();
        $response = $this->postJson('/api/register', [
            'phone' => '1234567890',
            'password' => 'password123',
            'first_name' => 'John',
            'last_name' => 'Doe',
            'email' => $faker->unique()->safeEmail,
        ]);

        $response->assertStatus(201);

        $response = $this->postJson('/api/login', [
            'phone' => '1234567890',
            'password' => 'password123',
        ]);

        $response->assertStatus(200)
            ->assertJsonStructure([
                'success',
                'data' => [
                    'token',
                    'user',
                ],
                'message',
            ]);
    }

    public function test_api_user_login_failed_with_invalid_credentials()
    {
        $user = $this->createUser();

        $response = $this->postJson('/api/login', [
            'email' => $user->email,
            'password' => 'wrongpassword',
        ]);

        $response->assertStatus(401)
            ->assertJson([
                'success' => false,
                'message' => 'Invalid credentials',
            ]);
    }

    public function test_api_user_login_failed_with_unregistered_user()
    {
        $faker = Factory::create();
        $response = $this->postJson('/api/login', [
            'email' => $faker->unique()->safeEmail,
            'password' => 'password123',
        ]);

        $response->assertStatus(401)
            ->assertJson([
                'success' => false,
                'message' => 'Invalid credentials',
            ]);
    }

    public function test_api_user_receives_login_validation_error_when_required_fields_are_missing()
    {
        $response = $this->postJson('/api/login', []);

        $response->assertStatus(422)
            ->assertJson([
                'success' => false,
                'message' => 'Validation failed.',
                'errors' => [
                    [
                        'email' => ['The email field is required when none of phone / username are present.'],
                        'phone' => ['The phone field is required when none of email / username are present.'],
                        'username' => ['The username field is required when none of email / phone are present.'],
                        'password' => ['The password field is required.'],
                    ],
                ],
            ]);
    }

    public function test_send_password_reset_code()
    {
        Event::fake();

        $user = $this->createUser();

        $response = $this->postJson('/api/password/reset-code', ['email' => $user->email]);

        $response->assertStatus(200)
            ->assertJson(['message' => 'If this email matches a record, a password reset code has been sent.']);

        Event::assertDispatched(PasswordResetCodeGeneratedEvent::class);
    }

    public function test_send_password_reset_code_rate_limit()
    {
        $user = $this->createUser();

        for ($i = 0; $i < 6; $i++) {
            $this->postJson('/api/password/reset-code', ['email' => $user->email]);
        }

        $response = $this->postJson('/api/password/reset-code', ['email' => $user->email]);

        $response->assertStatus(429)
            ->assertJson(['message' => 'Too many attempts, please try again later.']);
    }

    public function test_reset_password_with_code()
    {
        Event::fake();

        $user = $this->createUser();
        $verificationCode = random_int(100000, 999999);

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

        $response->assertStatus(200)
            ->assertJson(['message' => 'Password has been reset successfully.']);

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

        $response->assertStatus(400)
            ->assertJson(['message' => 'Invalid or expired code.']);
    }

    public function test_send_verification_code_successfully()
    {
        Event::fake();

        $faker = Factory::create();
        $email = $faker->unique()->safeEmail;

        $response = $this->postJson('/api/send-verification-code', [
            'contact' => $email,
            'type' => 'email',
            'purpose' => 'registration',
        ]);

        $response->assertStatus(200)
            ->assertJson(['message' => 'Verification code sent to your email.']);

        Event::assertDispatched(VerificationCodeGeneratedEvent::class, function ($event) use ($email) {
            return $event->contact === $email
                && $event->type === 'email'
                && $event->purpose === 'registration_email';
        });

        $this->assertDatabaseHas('verification_codes', [
            'contact' => $email,
            'purpose' => 'registration_email',
        ]);
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

        $response->assertStatus(200)
            ->assertJson(['message' => 'Verification code sent to your phone.']);

        Event::assertDispatched(VerificationCodeGeneratedEvent::class, function ($event) use ($phone) {
            return $event->contact === $phone
                && $event->type === 'phone'
                && $event->purpose === 'registration_phone';
        });

        $this->assertDatabaseHas('verification_codes', [
            'contact' => $phone,
            'purpose' => 'registration_phone',
        ]);
    }

    public function test_send_verification_code_validation_error()
    {
        $response = $this->postJson('/api/send-verification-code', []);

        $response->assertStatus(422)
            ->assertJson([
                'success' => false,
                'message' => 'Validation failed.',
            ]);
    }

    public function test_send_verification_code_rate_limit()
    {
        $faker = Factory::create();
        $email = $faker->unique()->safeEmail;

        for ($i = 0; $i < 6; $i++) {
            $this->postJson('/api/send-verification-code', [
                'contact' => $email,
                'type' => 'email',
                'purpose' => 'registration',
            ]);
        }

        $response = $this->postJson('/api/send-verification-code', [
            'contact' => $email,
            'type' => 'email',
            'purpose' => 'registration',
        ]);

        $response->assertStatus(429)
            ->assertJson(['message' => 'Too many attempts, please try again later.']);
    }

    public function test_verify_code_successfully()
    {
        $faker = Factory::create();
        $email = $faker->unique()->safeEmail;
        $verificationCode = random_int(100000, 999999);

        VerificationCode::create([
            'contact' => $email,
            'code' => Hash::make($verificationCode),
            'purpose' => 'registration_email',
            'expires_at' => now()->addMinutes(5),
        ]);

        $response = $this->postJson('/api/verify-code', [
            'contact' => $email,
            'code' => (string) $verificationCode,
            'type' => 'email',
            'purpose' => 'registration',
        ]);

        $response->assertStatus(200)
            ->assertJson(['message' => 'Code verified successfully.']);

        $this->assertDatabaseHas('verification_codes', [
            'contact' => $email,
            'purpose' => 'registration_email',
        ]);
    }

    public function test_verify_code_invalid_code()
    {
        $faker = Factory::create();
        $email = $faker->unique()->safeEmail;
        $verificationCode = random_int(100000, 999999);
        $wrongCode = random_int(100000, 999999);

        while ($wrongCode === $verificationCode) {
            $wrongCode = random_int(100000, 999999);
        }

        VerificationCode::create([
            'contact' => $email,
            'code' => Hash::make($verificationCode),
            'purpose' => 'registration_email',
            'expires_at' => now()->addMinutes(5),
        ]);

        $response = $this->postJson('/api/verify-code', [
            'contact' => $email,
            'code' => (string) $wrongCode,
            'type' => 'email',
            'purpose' => 'registration',
        ]);

        $response->assertStatus(400)
            ->assertJson(['message' => 'Invalid or expired code.']);
    }

    public function test_verify_code_expired_code()
    {
        $faker = Factory::create();
        $email = $faker->unique()->safeEmail;
        $verificationCode = random_int(100000, 999999);

        VerificationCode::create([
            'contact' => $email,
            'code' => Hash::make($verificationCode),
            'purpose' => 'registration_email',
            'expires_at' => now()->subMinutes(1),
        ]);

        $response = $this->postJson('/api/verify-code', [
            'contact' => $email,
            'code' => (string) $verificationCode,
            'type' => 'email',
            'purpose' => 'registration',
        ]);

        $response->assertStatus(400)
            ->assertJson(['message' => 'Invalid or expired code.']);
    }

    public function test_verify_code_no_code_found()
    {
        $faker = Factory::create();
        $email = $faker->unique()->safeEmail;

        $response = $this->postJson('/api/verify-code', [
            'contact' => $email,
            'code' => '123456',
            'type' => 'email',
            'purpose' => 'registration',
        ]);

        $response->assertStatus(400)
            ->assertJson(['message' => 'Invalid or expired code.']);
    }

    public function test_verify_code_validation_error()
    {
        $response = $this->postJson('/api/verify-code', []);

        $response->assertStatus(422)
            ->assertJson([
                'success' => false,
                'message' => 'Validation failed.',
            ]);
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

        $response->assertStatus(201)
            ->assertJsonStructure([
                'success',
                'data' => [
                    'user',
                    'token',
                ],
                'message',
            ]);

        $this->assertDatabaseHas('users', ['email' => $response->json('data.user.email')]);
    }

    public function test_register_with_email_verification_enabled_but_not_verified()
    {
        config(['user-authentication.verification.require_email_verification' => true]);

        $faker = Factory::create();
        $response = $this->postJson('/api/register', [
            'email' => $faker->unique()->safeEmail,
            'first_name' => $faker->firstName,
            'last_name' => $faker->lastName,
            'password' => 'password123',
        ]);

        $response->assertStatus(422)
            ->assertJson([
                'success' => false,
                'message' => 'Email verification required. Please verify your email first.',
            ]);
    }

    public function test_register_with_email_verification_enabled_and_verified()
    {
        config(['user-authentication.verification.require_email_verification' => true]);

        $faker = Factory::create();
        $email = $faker->unique()->safeEmail;
        $verificationCode = random_int(100000, 999999);

        VerificationCode::create([
            'contact' => $email,
            'code' => Hash::make($verificationCode),
            'purpose' => 'registration_email',
            'expires_at' => now()->addMinutes(5),
            'verified_at' => now(),
        ]);

        $response = $this->postJson('/api/register', [
            'email' => $email,
            'first_name' => $faker->firstName,
            'last_name' => $faker->lastName,
            'password' => 'password123',
        ]);

        $response->assertStatus(201)
            ->assertJsonStructure([
                'success',
                'data' => [
                    'user',
                    'token',
                ],
                'message',
            ]);

        $this->assertDatabaseHas('users', ['email' => $email]);
    }

    public function test_register_with_phone_verification_enabled_but_not_verified()
    {
        config(['user-authentication.verification.require_phone_verification' => true]);

        $faker = Factory::create();
        $phone = '001234567890';

        $response = $this->postJson('/api/register', [
            'email' => $faker->unique()->safeEmail,
            'phone' => $phone,
            'first_name' => $faker->firstName,
            'last_name' => $faker->lastName,
            'password' => 'password123',
        ]);

        $response->assertStatus(422)
            ->assertJson([
                'success' => false,
                'message' => 'Phone verification required. Please verify your phone first.',
            ]);
    }

    public function test_register_with_phone_verification_enabled_and_verified()
    {
        config(['user-authentication.verification.require_phone_verification' => true]);

        $faker = Factory::create();
        $phone = '001234567890';
        $verificationCode = random_int(100000, 999999);

        VerificationCode::create([
            'contact' => $phone,
            'code' => Hash::make($verificationCode),
            'purpose' => 'registration_phone',
            'expires_at' => now()->addMinutes(5),
            'verified_at' => now(),
        ]);

        $response = $this->postJson('/api/register', [
            'email' => $faker->unique()->safeEmail,
            'phone' => $phone,
            'first_name' => $faker->firstName,
            'last_name' => $faker->lastName,
            'password' => 'password123',
        ]);

        $response->assertStatus(201)
            ->assertJsonStructure([
                'success',
                'data' => [
                    'user',
                    'token',
                ],
                'message',
            ]);

        $this->assertDatabaseHas('users', ['phone' => $phone]);
    }

    public function test_smartpings_service_is_disabled_when_not_configured()
    {
        config([
            'user-authentication.verification.provider' => 'default',
            'user-authentication.verification.self_managed' => true,
        ]);

        $service = new SmartPingsVerificationService;
        $this->assertFalse($service->isEnabled());
    }

    public function test_smartpings_send_verification_returns_error_when_disabled()
    {
        config([
            'user-authentication.verification.provider' => 'default',
            'user-authentication.verification.self_managed' => true,
        ]);

        $service = new SmartPingsVerificationService;
        $result = $service->sendVerification('test@example.com', 'email');

        $this->assertFalse($result['success']);
        $this->assertEquals('SmartPings verification is not enabled', $result['message']);
    }

    public function test_send_verification_code_with_smartpings_enabled()
    {
        config([
            'user-authentication.verification.provider' => 'smartpings',
            'user-authentication.verification.self_managed' => false,
            'user-authentication.smartpings.client_id' => 'test-client-id',
            'user-authentication.smartpings.secret_id' => 'test-secret-id',
        ]);

        $mockService = $this->createMock(SmartPingsVerificationService::class);
        $mockService->method('isEnabled')->willReturn(true);
        $mockService->method('sendVerification')->willReturn([
            'success' => true,
            'message' => 'Email verification sent successfully',
        ]);
        $this->app->bind(SmartPingsVerificationService::class, function () use ($mockService) {
            return $mockService;
        });

        $response = $this->postJson('/api/send-verification-code', [
            'contact' => 'test@example.com',
            'type' => 'email',
            'purpose' => 'registration',
        ]);

        $response->assertStatus(200)
            ->assertJson(['message' => 'Email verification sent successfully']);
    }

    public function test_verify_code_with_smartpings_enabled()
    {
        config([
            'user-authentication.verification.provider' => 'smartpings',
            'user-authentication.verification.self_managed' => false,
            'user-authentication.smartpings.client_id' => 'test-client-id',
            'user-authentication.smartpings.secret_id' => 'test-secret-id',
        ]);

        $mockService = $this->createMock(SmartPingsVerificationService::class);
        $mockService->method('isEnabled')->willReturn(true);
        $mockService->method('verify')->willReturn(true);
        $this->app->bind(SmartPingsVerificationService::class, function () use ($mockService) {
            return $mockService;
        });

        $response = $this->postJson('/api/verify-code', [
            'contact' => 'test@example.com',
            'code' => '123456',
            'type' => 'email',
            'purpose' => 'registration',
        ]);

        $response->assertStatus(200)
            ->assertJson(['message' => 'Code verified successfully.']);
    }

    public function test_register_with_smartpings_email_verification_enabled_and_verified()
    {
        config([
            'user-authentication.verification.require_email_verification' => true,
            'user-authentication.verification.provider' => 'smartpings',
            'user-authentication.verification.self_managed' => false,
            'user-authentication.smartpings.client_id' => 'test-client-id',
            'user-authentication.smartpings.secret_id' => 'test-secret-id',
        ]);

        $mockService = $this->createMock(SmartPingsVerificationService::class);
        $mockService->method('isEnabled')->willReturn(true);
        $mockService->method('isVerified')->willReturn(true);
        $this->app->bind(SmartPingsVerificationService::class, function () use ($mockService) {
            return $mockService;
        });

        $faker = Factory::create();
        $email = $faker->unique()->safeEmail;

        $response = $this->postJson('/api/register', [
            'email' => $email,
            'first_name' => $faker->firstName,
            'last_name' => $faker->lastName,
            'password' => 'password123',
        ]);

        $response->assertStatus(201)
            ->assertJsonStructure([
                'success',
                'data' => [
                    'user',
                    'token',
                ],
                'message',
            ]);

        $this->assertDatabaseHas('users', ['email' => $email]);
    }

    public function test_register_with_smartpings_email_verification_enabled_but_not_verified()
    {
        config([
            'user-authentication.verification.require_email_verification' => true,
            'user-authentication.verification.provider' => 'smartpings',
            'user-authentication.verification.self_managed' => false,
            'user-authentication.smartpings.client_id' => 'test-client-id',
            'user-authentication.smartpings.secret_id' => 'test-secret-id',
        ]);

        $mockService = $this->createMock(SmartPingsVerificationService::class);
        $mockService->method('isEnabled')->willReturn(true);
        $mockService->method('isVerified')->willReturn(false);
        $this->app->bind(SmartPingsVerificationService::class, function () use ($mockService) {
            return $mockService;
        });

        $faker = Factory::create();
        $email = $faker->unique()->safeEmail;

        $response = $this->postJson('/api/register', [
            'email' => $email,
            'first_name' => $faker->firstName,
            'last_name' => $faker->lastName,
            'password' => 'password123',
        ]);

        $response->assertStatus(422)
            ->assertJson([
                'success' => false,
                'message' => 'Email verification required. Please verify your email first.',
            ]);
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

    /**
     * Get package providers.
     *
     * @param  \Illuminate\Foundation\Application  $app
     * @return array<int, class-string<\Illuminate\Support\ServiceProvider>>
     */
    protected function getPackageProviders($app)
    {
        return [
            'Whilesmart\UserAuthentication\UserAuthenticationServiceProvider',
        ];
    }
}
