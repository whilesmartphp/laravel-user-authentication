<?php

namespace Whilesmart\UserAuthentication\Tests\Feature;

use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Event;
use Whilesmart\UserAuthentication\Events\UserLoggedInEvent;
use Whilesmart\UserAuthentication\Interfaces\MiddlewareHookInterface;
use Whilesmart\UserAuthentication\Models\Passkey;
use Whilesmart\UserAuthentication\Services\PasskeyService;
use Whilesmart\UserAuthentication\Tests\TwoFactorTestCase;

class TwoFactorVerifyTest extends TwoFactorTestCase
{
    public function test_passkey_login_requires_the_configured_second_factor()
    {
        config([
            'user-authentication.passkey.domain' => 'https://localhost',
            'user-authentication.passkey.allowed_origins' => ['https://localhost'],
            'user-authentication.middleware_hooks' => [TwoFactorLoginHook::class],
        ]);
        [$user, , , $codes] = $this->enroll();
        $passkey = $this->createPasskey($user);
        $service = new class () extends PasskeyService {
            public Passkey $passkey;

            public function verifyPasskey(array $passkey, string $options, ?string $userHandle = null): Passkey
            {
                return $this->passkey;
            }
        };
        $service->passkey = $passkey;
        $this->app->instance(PasskeyService::class, $service);
        $this->app['auth']->forgetGuards();
        Event::fake([UserLoggedInEvent::class]);
        $tokensBefore = $user->tokens()->count();
        $session = $this->postJson('/api/passkeys/login/options', ['email' => $user->email])
            ->assertOk()->json('data.session_id');
        $response = $this->postJson('/api/passkeys/login', [
            'session_id' => $session,
            'passkey' => ['id' => 'stubbed'],
        ])->assertOk()->assertJsonPath('data.two_factor_required', true)
            ->assertJsonPath('data.method', 'totp')->assertJsonMissingPath('data.token');
        $this->assertSame($tokensBefore, $user->tokens()->count());
        Event::assertNotDispatched(UserLoggedInEvent::class);
        $pending = $response->json('data.two_factor_token');
        $completed = $this->verify($pending, $codes[0])->assertOk()
            ->assertHeader('X-Login-Hook', 'passkeyLogin')
            ->assertJsonMissingPath('data.user.factors')
            ->assertJsonMissingPath('data.user.recovery_codes');
        Event::assertDispatchedTimes(UserLoggedInEvent::class, 1);
        $this->getJson('/api/passkeys', $this->bearer($completed->json('data.token')))
            ->assertOk()->assertJsonCount(1, 'data.passkeys');
        $this->verify($pending, $codes[0])->assertUnauthorized();
    }

    public function test_email_code_and_pending_token_are_single_use_and_response_is_safe()
    {
        $user = $this->emailUser();
        [$pending, $code] = $this->sentChallenge($user);
        $response = $this->verify($pending, $code)->assertOk();
        $response->assertJsonStructure(['data' => ['token', 'user' => ['id']]])
            ->assertJsonMissingPath('data.user.secret')
            ->assertJsonMissingPath('data.user.recovery_codes')
            ->assertJsonMissingPath('data.user.factors')
            ->assertJsonMissingPath('data.user.two_factor_auth');
        $this->verify($pending, $code)->assertUnauthorized();
        do {
            [$fresh, $freshCode] = $this->sentChallenge($user);
        } while ($freshCode === $code);
        $this->verify($fresh, $code)->assertUnprocessable();
        $response->assertJsonPath('data.user.created_at', $user->created_at->toJSON())
            ->assertJsonMissingPath('data.user.password');
        $this->postJson('/api/2fa/setup', [], $this->bearer($response->json('data.token')))->assertOk();
    }

    public function test_phone_code_verifies_through_login()
    {
        [$pending, $code] = $this->sentChallenge($this->emailUser('phone'));
        $this->verify($pending, $code)->assertOk();
    }

    public function test_totp_and_recovery_codes_cannot_be_replayed()
    {
        [$user, , $secret, $codes, $setupCode] = $this->enroll();
        $pending = $this->passwordLogin($user)->assertOk()->json('data.two_factor_token');
        $this->verify($pending, $setupCode)->assertUnprocessable();
        $this->verify($pending, $codes[0])->assertOk();
        $this->verify($pending, $codes[1])->assertUnauthorized();
        $pending = $this->passwordLogin($user)->assertOk()->json('data.two_factor_token');
        $this->verify($pending, $codes[0])->assertUnprocessable();
        $google = app('pragmarx.google2fa');
        $code = $google->oathTotp($secret, $google->getTimestamp() + 1);
        $this->verify($pending, $code)->assertOk();
        $pending = $this->passwordLogin($user)->assertOk()->json('data.two_factor_token');
        $this->verify($pending, $code)->assertUnprocessable();
        $this->assertNotContains($codes[0], $user->recoveryCodes()->whereNull('used_at')->pluck('code_hash')->all());
        $this->assertArrayNotHasKey('secret', $user->fresh()->factors()->first()->toArray());
        $this->assertArrayNotHasKey('recovery_codes', $user->fresh()->factors()->first()->toArray());
        $this->assertArrayNotHasKey('factors', $user->fresh()->load('factors')->toArray());
    }

    public function test_attempt_budget_invalidates_the_challenge()
    {
        config(['user-authentication.two_factor.attempts' => 2]);
        [$pending, $code] = $this->sentChallenge($this->emailUser());
        $wrong = $code === '000000' ? '111111' : '000000';
        $this->verify($pending, $wrong)->assertUnprocessable();
        $this->verify($pending, $wrong)->assertUnprocessable();
        $this->verify($pending, $code)->assertUnauthorized();
    }

    public function test_resend_replaces_pending_code_and_link()
    {
        $user = $this->emailUser();
        [$pending, $code, $link] = $this->sentChallenge($user);
        $fresh = $this->postJson('/api/2fa/resend', [
            'two_factor_token' => $pending,
            'factor_id' => $user->factors()->value('id'),
        ])
            ->assertOk()
            ->json('data.two_factor_token');
        $event = Event::dispatched(
            \Whilesmart\UserAuthentication\Events\VerificationCodeGeneratedEvent::class
        )->last()[0];
        $this->verify($pending, $code)->assertUnauthorized();
        $this->postJson('/api/2fa/verify-link', ['two_factor_token' => $fresh, 'token' => $link])
            ->assertUnprocessable();
        $this->verify($fresh, $event->code)->assertOk();
    }

    public function test_codes_are_bound_to_account_and_purpose()
    {
        $user = $this->emailUser();
        [$pending, $code] = $this->sentChallenge($user);
        [$otherPending, $otherCode] = $this->sentChallenge($this->emailUser());
        while ($code === $otherCode) {
            [$otherPending, $otherCode] = $this->sentChallenge($this->emailUser());
        }
        $this->verify($otherPending, $code)->assertUnprocessable();
        $token = $this->verify($pending, $code)->assertOk()->json('data.token');
        $disable = $this->postJson('/api/2fa/disable', [
            'factor_id' => $user->factors()->value('id') ?? 0,
        ], $this->bearer($token))
            ->assertOk()
            ->json('data.two_factor_token');
        $event = Event::dispatched(
            \Whilesmart\UserAuthentication\Events\VerificationCodeGeneratedEvent::class
        )->last()[0];
        $this->verify($disable, $event->code)->assertUnauthorized();
        $this->postJson('/api/2fa/disable', [
            'factor_id' => $user->factors()->value('id'),
            'two_factor_token' => $otherPending,
            'code' => $otherCode,
        ], $this->bearer($token))
            ->assertUnprocessable();
    }

    public function test_pending_tokens_expire_and_formats_are_bounded()
    {
        [$pending, $code] = $this->sentChallenge($this->emailUser());
        $this->verify('invalid', $code)->assertUnprocessable();
        $this->verify(str_repeat('a', 2049), $code)->assertUnprocessable();
        $this->verify($pending, str_repeat('a', 100))->assertUnprocessable();
        $this->travel(6)->minutes();
        $this->verify($pending, $code)->assertUnauthorized();
    }

    public function test_completion_dispatches_login_and_runs_login_after_hooks()
    {
        config(['user-authentication.middleware_hooks' => [TwoFactorLoginHook::class]]);
        $user = $this->emailUser();
        [$pending, $code] = $this->sentChallenge($user);
        Event::assertNotDispatched(UserLoggedInEvent::class);
        $this->verify($pending, $code)->assertOk()->assertHeader('X-Login-Hook', 'login');
        Event::assertDispatchedTimes(UserLoggedInEvent::class, 1);
    }
}

class TwoFactorLoginHook implements MiddlewareHookInterface
{
    public function before(Request $request, string $action): ?Request
    {
        return $request;
    }

    public function after(Request $request, JsonResponse $response, string $action): JsonResponse
    {
        $response->headers->set('X-Login-Hook', $action);

        return $response;
    }
}
