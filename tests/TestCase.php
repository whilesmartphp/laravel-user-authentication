<?php

use Faker\Factory;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Hash;
use Orchestra\Testbench\Attributes\WithMigration;
use Whilesmart\LaravelUserAuthentication\Events\PasswordResetCodeGeneratedEvent;
use Whilesmart\LaravelUserAuthentication\Events\PasswordResetCompleteEvent;
use Whilesmart\LaravelUserAuthentication\Models\User;
use Whilesmart\LaravelUserAuthentication\Models\VerificationCode;

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
        $response = $this->postJson('/register', [
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
        $response = $this->postJson('/register', []);

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

        $response = $this->postJson('/login', [
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
        $response = $this->postJson('/register', [
            'username' => 'testuser',
            'password' => 'password123',
            'first_name' => 'John',
            'last_name' => 'Doe',
            'email' => $faker->unique()->safeEmail,
        ]);

        $response->assertStatus(201);

        $response = $this->postJson('/login', [
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
        $response = $this->postJson('/register', [
            'phone' => '1234567890',
            'password' => 'password123',
            'first_name' => 'John',
            'last_name' => 'Doe',
            'email' => $faker->unique()->safeEmail,
        ]);

        $response->assertStatus(201);

        $response = $this->postJson('/login', [
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

        $response = $this->postJson('/login', [
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
        $response = $this->postJson('/login', [
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
        $response = $this->postJson('/login', []);

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

        $response = $this->postJson('/password/reset-code', ['email' => $user->email]);

        $response->assertStatus(200)
            ->assertJson(['message' => 'If this email matches a record, a password reset code has been sent.']);

        Event::assertDispatched(PasswordResetCodeGeneratedEvent::class);
    }

    public function test_send_password_reset_code_rate_limit()
    {
        $user = $this->createUser();

        for ($i = 0; $i < 6; $i++) {
            $this->postJson('/password/reset-code', ['email' => $user->email]);
        }

        $response = $this->postJson('/password/reset-code', ['email' => $user->email]);

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

        $response = $this->postJson('/password/reset', [
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

        $response = $this->postJson('/password/reset', [
            'email' => $user->email,
            'code' => 123456,
            'new_password' => 'newpassword123',
            'new_password_confirmation' => 'newpassword123',
        ]);

        $response->assertStatus(400)
            ->assertJson(['message' => 'Invalid or expired code.']);
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
            'Whilesmart\LaravelUserAuthentication\UserAuthenticationServiceProvider',
        ];
    }
}
