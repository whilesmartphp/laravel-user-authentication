<?php

namespace Whilesmart\UserAuthentication\Tests\Feature;

use Whilesmart\UserAuthentication\Tests\TwoFactorTestCase;

class TwoFactorMiddlewareTest extends TwoFactorTestCase
{
    public function test_wildcard_token_is_rejected_on_package_security_routes()
    {
        $user = $this->createUser();
        $token = $this->passwordLogin($user)->assertOk()->json('data.token');
        $user->factors()->create([
            'type' => 'totp',
            'confirmed_at' => now(),
            'secret' => app('pragmarx.google2fa')->generateSecretKey(),
        ]);
        foreach (['setup', 'confirm', 'disable'] as $action) {
            $this->postJson('/api/2fa/' . $action, [], $this->bearer($token))->assertForbidden();
        }
        $response = $this->passwordLogin($user)
            ->assertOk()
            ->assertJsonPath('data.two_factor_required', true)
            ->assertJsonMissingPath('data.token');
        $this->assertNotEmpty($response->json('data.two_factor_token'));
        $this->assertSame(1, $user->tokens()->count());
    }

    public function test_real_token_without_2fa_can_reach_setup()
    {
        $user = $this->createUser();
        $token = $this->passwordLogin($user)->assertOk()->json('data.token');
        $this->postJson('/api/2fa/setup', [], $this->bearer($token))->assertOk();
    }

    public function test_named_limiters_return_429_for_every_sensitive_operation()
    {
        foreach (['verify', 'resend', 'link', 'setup', 'confirm', 'disable'] as $operation) {
            config(['user-authentication.two_factor.rate_limits.' . $operation => 1]);
        }
        $user = $this->createUser();
        $token = $this->passwordLogin($user)->assertOk()->json('data.token');
        foreach (['setup', 'confirm', 'disable'] as $operation) {
            $this->postJson('/api/2fa/' . $operation, [], $this->bearer($token));
            $this->postJson('/api/2fa/' . $operation, [], $this->bearer($token))->assertStatus(429);
        }
        foreach (['verify', 'resend', 'verify-link'] as $operation) {
            $this->postJson('/api/2fa/' . $operation);
            $this->postJson('/api/2fa/' . $operation)->assertStatus(429);
        }
    }

    public function test_account_limiter_survives_ip_and_challenge_rotation()
    {
        config(['user-authentication.two_factor.rate_limits.verify' => 1]);
        $user = $this->emailUser();
        [$pending, $code] = $this->sentChallenge($user);
        $this->verify($pending, $code)->assertOk();
        [$fresh, $freshCode] = $this->sentChallenge($user);
        $this->withServerVariables(['REMOTE_ADDR' => '192.0.2.2']);
        $this->verify($fresh, $freshCode)->assertStatus(429);
    }
}
