<?php

namespace Whilesmart\UserAuthentication\Tests;

use Illuminate\Support\Facades\Event;
use Whilesmart\UserAuthentication\Events\VerificationCodeGeneratedEvent;

abstract class TwoFactorTestCase extends TestCase
{
    protected function setUp(): void
    {
        parent::setUp();
        config(['user-authentication.magic_link.url' => 'https://auth.example.com/verify']);
        foreach (['verify', 'resend', 'link', 'setup', 'confirm', 'disable'] as $operation) {
            config(['user-authentication.two_factor.rate_limits.' . $operation => 100]);
        }
    }

    protected function bearer(string $token): array
    {
        $this->app['auth']->forgetGuards();

        return ['Authorization' => 'Bearer ' . $token];
    }

    protected function passwordLogin($user)
    {
        $this->app['auth']->forgetGuards();

        return $this->postJson('/api/login', ['email' => $user->email, 'password' => 'password123']);
    }

    protected function enroll(): array
    {
        $user = $this->createUser();
        $token = $this->passwordLogin($user)->assertOk()->json('data.token');
        $secret = $this->postJson('/api/2fa/setup', [], $this->bearer($token))->assertOk()->json('data.secret');
        $code = app('pragmarx.google2fa')->getCurrentOtp($secret);
        $codes = $this->postJson('/api/2fa/confirm', [
            'factor_id' => $user->factors()->value('id') ?? 0,
            'code' => $code,
        ], $this->bearer($token))
            ->assertOk()->json('data.recovery_codes');

        return [$user, $token, $secret, $codes, $code];
    }

    protected function emailUser(string $type = 'email')
    {
        $user = $this->createUser(['phone' => '+1555' . random_int(1000000, 9999999)]);
        $user->factors()->create(['type' => $type, 'confirmed_at' => now()]);

        return $user;
    }

    protected function sentChallenge($user): array
    {
        Event::fake([
            VerificationCodeGeneratedEvent::class,
            \Whilesmart\UserAuthentication\Events\UserLoggedInEvent::class,
        ]);
        $response = $this->passwordLogin($user)->assertOk()->assertJsonMissingPath('data.token');
        $event = Event::dispatched(VerificationCodeGeneratedEvent::class)->last()[0];
        parse_str(parse_url($event->magicLink, PHP_URL_QUERY), $query);

        return [$response->json('data.two_factor_token'), $event->code, $query['token'], $event->magicLink];
    }

    protected function verify(string $pending, string $code)
    {
        $this->app['auth']->forgetGuards();

        return $this->postJson('/api/2fa/verify', ['two_factor_token' => $pending, 'code' => $code]);
    }
}
