<?php

namespace Whilesmart\UserAuthentication\Tests\Feature;

use Illuminate\Contracts\Http\Kernel as HttpKernel;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Hash;
use Whilesmart\UserAuthentication\Events\UserLoggedInEvent;
use Whilesmart\UserAuthentication\Events\UserRegisteredEvent;
use Whilesmart\UserAuthentication\Events\VerificationCodeGeneratedEvent;
use Whilesmart\UserAuthentication\Interfaces\MiddlewareHookInterface;
use Whilesmart\UserAuthentication\Models\AuthChallenge;
use Whilesmart\UserAuthentication\Models\User;
use Whilesmart\UserAuthentication\Tests\TwoFactorTestCase;

class EmailLoginTest extends TwoFactorTestCase
{
    protected function setUp(): void
    {
        parent::setUp();
        config([
            'user-authentication.email_login.enabled' => true,
            'user-authentication.email_login.url' => 'https://auth.example.com/login',
            'user-authentication.email_login.rate_limits.issue_ip' => 100,
            'user-authentication.email_login.rate_limits.issue_email' => 100,
            'user-authentication.email_login.rate_limits.verify_ip' => 100,
            'user-authentication.email_login.rate_limits.verify_email' => 100,
        ]);
        Event::fake([VerificationCodeGeneratedEvent::class, UserLoggedInEvent::class, UserRegisteredEvent::class]);
    }

    private function issueEmail(string $email): array
    {
        $this->postJson('/api/login/email', ['email' => $email])->assertStatus(202);
        $event = Event::dispatched(VerificationCodeGeneratedEvent::class)->last()[0];
        parse_str(parse_url($event->magicLink, PHP_URL_QUERY), $query);

        return [$event->code, $query['token']];
    }

    public function test_disabled_endpoints_are_unavailable(): void
    {
        config(['user-authentication.email_login.enabled' => false]);
        $this->postJson('/api/login/email', ['email' => 'person@example.com'])->assertNotFound();
        $this->postJson('/api/login/email/verify', ['token' => str_repeat('a', 64)])->assertNotFound();
    }

    public function test_known_and_unknown_addresses_receive_identical_responses(): void
    {
        $user = $this->createUser();
        $this->withServerVariables(['REMOTE_ADDR' => '192.0.2.1', 'HTTP_USER_AGENT' => 'Email sign-in test']);
        $known = $this->postJson('/api/login/email', ['email' => $user->email])->assertStatus(202)->json();
        $unknown = $this->postJson('/api/login/email', ['email' => 'unknown@example.com'])->assertStatus(202)->json();
        $this->assertSame($known, $unknown);
        $this->assertDatabaseHas('auth_challenges', [
            'purpose' => 'contact_login', 'method' => 'email', 'contact' => $user->email,
            'authenticatable_type' => $user->getMorphClass(), 'authenticatable_id' => $user->getKey(),
            'factor_id' => null, 'ip_address' => '192.0.2.1', 'user_agent' => 'Email sign-in test',
        ]);
        $this->assertDatabaseHas('auth_challenges', [
            'purpose' => 'contact_login', 'method' => 'email', 'contact' => 'unknown@example.com',
            'authenticatable_type' => null, 'authenticatable_id' => null, 'factor_id' => null,
            'ip_address' => '192.0.2.1', 'user_agent' => 'Email sign-in test',
        ]);
        Event::assertDispatchedTimes(VerificationCodeGeneratedEvent::class, 1);
        Event::assertDispatched(VerificationCodeGeneratedEvent::class, fn ($event) => $event->contact === $user->email);
        $this->assertDatabaseMissing('users', ['email' => 'unknown@example.com']);
    }

    public function test_delivery_runs_after_the_response_is_sent(): void
    {
        $user = $this->createUser();
        $kernel = $this->app->make(HttpKernel::class);
        $request = Request::create('/api/login/email', 'POST', ['email' => $user->email], [], [], [
            'HTTP_ACCEPT' => 'application/json',
        ]);
        $response = $kernel->handle($request);
        $this->assertSame(202, $response->getStatusCode());
        Event::assertNotDispatched(VerificationCodeGeneratedEvent::class);
        $kernel->terminate($request, $response);
        Event::assertDispatchedTimes(VerificationCodeGeneratedEvent::class, 1);
    }

    public function test_code_sign_in_verifies_email_and_returns_only_public_user_fields(): void
    {
        $user = $this->createUser(['email_verified_at' => null]);
        [$code, $link] = $this->issueEmail($user->email);
        $challenge = AuthChallenge::where('contact', $user->email)->firstOrFail();
        $this->assertSame(hash('sha256', $link), $challenge->link_hash);
        $this->assertNotSame($code, $challenge->code_hash);
        $this->assertTrue(Hash::check($code, $challenge->code_hash));
        $response = $this->postJson('/api/login/email/verify', ['email' => $user->email, 'code' => $code])
            ->assertOk()->assertJsonStructure(['data' => ['token', 'token_type', 'user']]);
        $response->assertJsonPath('data.user.created_at', $user->created_at->toJSON())
            ->assertJsonMissingPath('data.user.password')
            ->assertJsonMissingPath('data.user.remember_token');
        $this->assertNotNull($user->fresh()->email_verified_at);
        Event::assertDispatched(UserLoggedInEvent::class);
        $this->postJson('/api/login/email/verify', ['email' => $user->email, 'code' => $code])->assertUnprocessable();
    }

    public function test_get_is_inert_and_post_consumes_both_credentials(): void
    {
        $user = $this->createUser();
        [$code, $token] = $this->issueEmail($user->email);
        $this->getJson('/api/login/email/verify?token=' . $token)->assertStatus(405);
        $this->assertSame(0, $user->tokens()->count());
        $this->postJson('/api/login/email/verify', ['token' => $token])->assertOk()
            ->assertJsonStructure(['data' => ['token']]);
        $this->postJson('/api/login/email/verify', ['token' => $token])->assertUnprocessable();
        $this->postJson('/api/login/email/verify', ['email' => $user->email, 'code' => $code])->assertUnprocessable();
    }

    public function test_wrong_codes_spend_budget_and_invalidate_the_link(): void
    {
        config(['user-authentication.email_login.attempts' => 2]);
        $user = $this->createUser();
        [$code, $token] = $this->issueEmail($user->email);
        $wrong = $code === '000000' ? '000001' : '000000';
        $this->postJson('/api/login/email/verify', ['email' => $user->email, 'code' => $wrong])->assertUnprocessable();
        $this->assertSame(1, AuthChallenge::where('contact', $user->email)->firstOrFail()->attempts);
        $this->postJson('/api/login/email/verify', ['email' => $user->email, 'code' => $wrong])->assertUnprocessable();
        $this->postJson('/api/login/email/verify', ['email' => $user->email, 'code' => $code])->assertUnprocessable();
        $this->postJson('/api/login/email/verify', ['token' => $token])->assertUnprocessable();
    }

    public function test_code_and_link_have_separate_expiries(): void
    {
        $user = $this->createUser();
        [$code, $token] = $this->issueEmail($user->email);
        $this->travel(11)->minutes();
        $this->postJson('/api/login/email/verify', ['email' => $user->email, 'code' => $code])->assertUnprocessable();
        $this->postJson('/api/login/email/verify', ['token' => $token])->assertOk();
        [, $token] = $this->issueEmail($user->email);
        $this->travel(16)->minutes();
        $this->postJson('/api/login/email/verify', ['token' => $token])->assertUnprocessable();
    }

    public function test_new_challenge_replaces_previous_credentials(): void
    {
        $user = $this->createUser();
        [, $oldToken] = $this->issueEmail($user->email);
        [, $newToken] = $this->issueEmail($user->email);
        $this->postJson('/api/login/email/verify', ['token' => $oldToken])->assertUnprocessable();
        $this->postJson('/api/login/email/verify', ['token' => $newToken])->assertOk();
        $this->assertSame(1, AuthChallenge::where('contact', $user->email)->count());
    }

    public function test_signup_creates_a_verified_user_and_dispatches_registration(): void
    {
        config(['user-authentication.email_login.create_users' => true]);
        [$code] = $this->issueEmail('new@example.com');
        $this->assertDatabaseMissing('users', ['email' => 'new@example.com']);
        $this->postJson('/api/login/email/verify', ['email' => 'new@example.com', 'code' => $code])->assertOk();
        $this->assertNotNull(User::where('email', 'new@example.com')->firstOrFail()->email_verified_at);
        Event::assertDispatched(UserRegisteredEvent::class);
        Event::assertDispatched(UserLoggedInEvent::class);
    }

    public function test_second_factor_is_required_before_issuing_a_token(): void
    {
        [$user, , , $codes] = $this->enroll();
        $tokenCount = $user->tokens()->count();
        Event::fake([VerificationCodeGeneratedEvent::class, UserLoggedInEvent::class]);
        [$code] = $this->issueEmail($user->email);
        $pending = $this->postJson('/api/login/email/verify', ['email' => $user->email, 'code' => $code])->assertOk()
            ->assertJsonPath('data.two_factor_required', true)->assertJsonMissingPath('data.token')
            ->json('data.two_factor_token');
        $this->assertSame($tokenCount, $user->tokens()->count());
        Event::assertNotDispatched(UserLoggedInEvent::class);
        $this->verify($pending, $codes[0])->assertOk()->assertJsonStructure(['data' => ['token']]);
        Event::assertDispatchedTimes(UserLoggedInEvent::class, 1);
    }

    public function test_factor_confirmation_invalidates_an_owned_email_challenge(): void
    {
        [$user, $token] = $this->enroll();
        $setup = $this->postJson('/api/2fa/setup', [], $this->bearer($token))->assertOk()->json('data');
        [$code, $link] = $this->issueEmail($user->email);
        $this->postJson('/api/2fa/confirm', [
            'factor_id' => $setup['factor_id'],
            'code' => app('pragmarx.google2fa')->getCurrentOtp($setup['secret']),
        ], $this->bearer($token))->assertOk();
        $this->postJson('/api/login/email/verify', ['email' => $user->email, 'code' => $code])
            ->assertUnprocessable();
        $this->postJson('/api/login/email/verify', ['token' => $link])->assertUnprocessable();
    }

    public function test_email_and_normal_login_hooks_run(): void
    {
        config(['user-authentication.middleware_hooks' => [EmailLoginHook::class]]);
        $user = $this->createUser();
        $this->postJson('/api/login/email', ['email' => $user->email])->assertStatus(202)
            ->assertHeader('X-After-emailLoginRequest', 'yes');
        $event = Event::dispatched(VerificationCodeGeneratedEvent::class)->last()[0];
        $this->postJson('/api/login/email/verify', ['email' => $user->email, 'code' => $event->code])
            ->assertOk()->assertHeader('X-After-login', 'yes')->assertHeader('X-After-emailLoginVerify', 'yes');
    }

    public function test_credentials_are_bound_to_the_address_and_original_account(): void
    {
        $user = $this->createUser();
        [$code, $token] = $this->issueEmail($user->email);
        $this->postJson('/api/login/email/verify', ['email' => 'other@example.com', 'code' => $code])
            ->assertUnprocessable();
        $this->postJson('/api/login/email/verify', ['email' => $user->email, 'token' => $token])
            ->assertUnprocessable();
        $this->postJson('/api/login/email/verify', ['token' => $token])->assertOk();
        config(['user-authentication.email_login.create_users' => true]);
        [$code] = $this->issueEmail('registered-later@example.com');
        $this->postJson('/api/register', [
            'email' => 'registered-later@example.com', 'first_name' => 'Person', 'password' => 'password123',
        ])->assertStatus(201);
        $this->postJson('/api/login/email/verify', [
            'email' => 'registered-later@example.com', 'code' => $code,
        ])->assertUnprocessable();
    }

    public function test_signup_can_be_disabled_after_issuance(): void
    {
        config(['user-authentication.email_login.create_users' => true]);
        [$code] = $this->issueEmail('new@example.com');
        config(['user-authentication.email_login.create_users' => false]);
        $this->postJson('/api/login/email/verify', ['email' => 'new@example.com', 'code' => $code])
            ->assertUnprocessable();
        $this->assertDatabaseMissing('users', ['email' => 'new@example.com']);
    }

    public function test_per_email_limits_apply_across_ips_and_to_link_verification(): void
    {
        config([
            'user-authentication.email_login.rate_limits.issue_email' => 1,
            'user-authentication.email_login.rate_limits.verify_email' => 1,
        ]);
        $user = $this->createUser();
        [$code, $token] = $this->issueEmail($user->email);
        $wrong = $code === '000000' ? '000001' : '000000';
        $this->withServerVariables(['REMOTE_ADDR' => '192.0.2.2']);
        $this->postJson('/api/login/email', ['email' => $user->email])->assertStatus(429);
        $this->postJson('/api/login/email/verify', ['email' => $user->email, 'code' => $wrong])
            ->assertStatus(422);
        $this->withServerVariables(['REMOTE_ADDR' => '192.0.2.3']);
        $this->postJson('/api/login/email/verify', ['token' => $token])->assertStatus(429);
    }

    public function test_per_ip_limits_apply_across_emails(): void
    {
        config([
            'user-authentication.email_login.rate_limits.issue_ip' => 1,
            'user-authentication.email_login.rate_limits.verify_ip' => 1,
        ]);
        $this->postJson('/api/login/email', ['email' => 'one@example.com'])->assertStatus(202);
        $this->postJson('/api/login/email', ['email' => 'two@example.com'])->assertStatus(429);
        $this->postJson('/api/login/email/verify', ['email' => 'one@example.com', 'code' => '000000'])
            ->assertUnprocessable();
        $this->postJson('/api/login/email/verify', ['email' => 'two@example.com', 'code' => '000000'])->assertStatus(429);
    }
}

class EmailLoginHook implements MiddlewareHookInterface
{
    public function before(Request $request, string $action): ?Request
    {
        return $request;
    }

    public function after(Request $request, JsonResponse $response, string $action): JsonResponse
    {
        $response->headers->set('X-After-' . $action, 'yes');

        return $response;
    }
}
