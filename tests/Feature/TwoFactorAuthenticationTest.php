<?php

namespace Whilesmart\UserAuthentication\Tests\Feature;

use Illuminate\Support\Facades\Event;
use Whilesmart\UserAuthentication\Events\VerificationCodeGeneratedEvent;
use Whilesmart\UserAuthentication\Tests\TwoFactorTestCase;

class TwoFactorAuthenticationTest extends TwoFactorTestCase
{
    public function test_enabling_revokes_other_tokens_and_reconfirmation_is_rejected()
    {
        $user = $this->createUser();
        $old = $this->passwordLogin($user)->assertOk()->json('data.token');
        $current = $this->passwordLogin($user)->assertOk()->json('data.token');
        $secret = $this->postJson('/api/2fa/setup', [], $this->bearer($current))->assertOk()->json('data.secret');
        $code = app('pragmarx.google2fa')->getCurrentOtp($secret);
        $this->postJson('/api/2fa/confirm', [
            'factor_id' => $user->factors()->value('id') ?? 0,
            'code' => $code,
        ], $this->bearer($current))->assertOk();
        $this->postJson('/api/2fa/disable', [
            'factor_id' => $user->factors()->value('id') ?? 0,
        ], $this->bearer($old))->assertUnauthorized();
        $this->postJson('/api/2fa/confirm', [
            'factor_id' => $user->factors()->value('id') ?? 0,
            'code' => $code,
        ], $this->bearer($current))->assertStatus(400);
        $this->postJson('/api/2fa/setup', [], $this->bearer($current))->assertOk();
    }

    public function test_setup_and_confirm_reject_session_authentication()
    {
        $user = $this->createUser();
        $this->actingAs($user, 'web')->postJson('/api/2fa/setup')->assertForbidden();
        $this->actingAs($user, 'web')->postJson('/api/2fa/confirm')->assertForbidden();
        $this->assertSame(0, $user->factors()->count());
        $token = $this->passwordLogin($user)->assertOk()->json('data.token');
        $secret = $this->postJson('/api/2fa/setup', [], $this->bearer($token))->assertOk()->json('data.secret');
        $this->app['auth']->forgetGuards();
        $this->actingAs($user, 'web')->postJson('/api/2fa/confirm', [
            'factor_id' => $user->factors()->value('id') ?? 0,
            'code' => app('pragmarx.google2fa')->getCurrentOtp($secret),
        ])->assertForbidden();
        $this->assertNull($user->factors()->value('confirmed_at'));
        $this->assertSame(0, (int) $user->factors()->value('setup_attempts'));
    }

    public function test_disable_requires_a_factor_even_with_no_recovery_codes_remaining()
    {
        [$user, $token, , $codes] = $this->enroll();
        foreach ($codes as $index => $code) {
            $pending = $this->passwordLogin($user)->assertOk()->json('data.two_factor_token');
            $this->verify($pending, $code)->assertOk();
            if ($index === 3) {
                $this->travel(2)->minutes();
            }
        }
        $this->postJson('/api/2fa/disable', [
            'factor_id' => $user->factors()->value('id') ?? 0,
        ], $this->bearer($token))->assertUnprocessable();
        $this->assertTrue($user->fresh()->hasTwoFactorEnabled());
    }

    public function test_unused_recovery_code_disables_and_revokes_sessions()
    {
        [$user, $token, , $codes] = $this->enroll();
        $this->postJson('/api/2fa/disable', [
            'factor_id' => $user->factors()->value('id'),
            'code' => $codes[0],
        ], $this->bearer($token))->assertOk();
        $this->assertFalse($user->fresh()->hasTwoFactorEnabled());
        $this->postJson('/api/2fa/setup', [], $this->bearer($token))->assertUnauthorized();
    }

    public function test_fresh_totp_disables_but_the_setup_code_cannot_be_replayed()
    {
        [$user, $token, $secret, , $setupCode] = $this->enroll();
        $this->postJson('/api/2fa/disable', [
            'factor_id' => $user->factors()->value('id'),
            'code' => $setupCode,
        ], $this->bearer($token))->assertUnprocessable();
        $google = app('pragmarx.google2fa');
        $code = $google->oathTotp($secret, $google->getTimestamp() + 1);
        $this->postJson('/api/2fa/disable', [
            'factor_id' => $user->factors()->value('id'),
            'code' => $code,
        ], $this->bearer($token))->assertOk();
        $this->assertFalse($user->fresh()->hasTwoFactorEnabled());
    }

    public function test_email_disable_requires_a_fresh_bound_code()
    {
        $user = $this->emailUser();
        [$pending, $loginCode] = $this->sentChallenge($user);
        $token = $this->verify($pending, $loginCode)->assertOk()->json('data.token');
        $pending = $this->postJson('/api/2fa/disable', [
            'factor_id' => $user->factors()->value('id') ?? 0,
        ], $this->bearer($token))
            ->assertOk()
            ->json('data.two_factor_token');
        $event = Event::dispatched(VerificationCodeGeneratedEvent::class)->last()[0];
        $this->assertNull($event->magicLink);
        $this->assertSame('disable_2fa_email', $event->purpose);
        $this->postJson('/api/2fa/disable', [
            'factor_id' => $user->factors()->value('id'),
            'two_factor_token' => $pending,
            'code' => 'INVALID000',
        ], $this->bearer($token))
            ->assertUnprocessable();
        $this->assertTrue($user->fresh()->hasTwoFactorEnabled());
        $this->postJson('/api/2fa/disable', [
            'factor_id' => $user->factors()->value('id'),
            'two_factor_token' => $pending,
            'code' => $event->code,
        ], $this->bearer($token))
            ->assertOk();
        $this->assertFalse($user->fresh()->hasTwoFactorEnabled());
    }

    public function test_setup_attempt_budget_and_missing_setup()
    {
        config(['user-authentication.two_factor.attempts' => 1]);
        $user = $this->createUser();
        $token = $this->passwordLogin($user)->assertOk()->json('data.token');
        $this->postJson('/api/2fa/confirm', [
            'factor_id' => $user->factors()->value('id') ?? 0,
            'code' => '123456',
        ], $this->bearer($token))->assertStatus(400);
        $secret = $this->postJson('/api/2fa/setup', [], $this->bearer($token))->assertOk()->json('data.secret');
        $google = app('pragmarx.google2fa');
        $wrong = '000000';
        while ($google->verifyKey($secret, $wrong)) {
            $wrong = str_pad((string) ((int) $wrong + 1), 6, '0', STR_PAD_LEFT);
        }
        $this->postJson('/api/2fa/confirm', [
            'factor_id' => $user->factors()->value('id') ?? 0,
            'code' => $wrong,
        ], $this->bearer($token))->assertUnprocessable();
        $this->postJson('/api/2fa/confirm', [
            'factor_id' => $user->factors()->value('id') ?? 0,
            'code' => $google->getCurrentOtp($secret),
        ], $this->bearer($token))
            ->assertStatus(400);
    }
}
