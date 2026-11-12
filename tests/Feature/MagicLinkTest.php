<?php

namespace Whilesmart\UserAuthentication\Tests\Feature;

use Whilesmart\UserAuthentication\Tests\TwoFactorTestCase;

class MagicLinkTest extends TwoFactorTestCase
{
    public function test_get_is_inert_and_post_consumes_link_and_pending_once()
    {
        config(['user-authentication.magic_link.url' => 'https://auth.example.com/verify']);
        $user = $this->emailUser();
        [$pending, $code, $link, $url] = $this->sentChallenge($user);
        $this->assertStringStartsWith('https://auth.example.com/verify?', $url);
        $this->getJson('/api/2fa/verify?token=' . $link)->assertStatus(405);
        $this->getJson('/api/2fa/verify-link?token=' . $link)->assertStatus(405);
        $this->assertSame(0, $user->tokens()->count());
        $this->postJson('/api/2fa/verify-link', ['two_factor_token' => $pending, 'token' => $link])->assertOk()
            ->assertJsonMissingPath('data.user.two_factor_auth');
        $this->postJson('/api/2fa/verify-link', ['two_factor_token' => $pending, 'token' => $link])
            ->assertUnauthorized();
        $this->verify($pending, $code)->assertUnauthorized();
    }

    public function test_link_cannot_bypass_a_changed_totp_policy()
    {
        $user = $this->emailUser();
        [$pending, , $link] = $this->sentChallenge($user);
        $user->twoFactorAuth()->first()->update([
            'type' => 'totp',
            'secret' => app('pragmarx.google2fa')->generateSecretKey(),
        ]);
        $this->postJson('/api/2fa/verify-link', ['two_factor_token' => $pending, 'token' => $link])
            ->assertUnprocessable();
        $this->assertSame(0, $user->tokens()->count());
    }

    public function test_link_is_bound_to_its_pending_login_and_expires()
    {
        [$pending, , $link] = $this->sentChallenge($this->emailUser());
        [$other] = $this->sentChallenge($this->emailUser());
        $this->postJson('/api/2fa/verify-link', ['two_factor_token' => $other, 'token' => $link])
            ->assertUnprocessable();
        $this->postJson('/api/2fa/verify-link', ['two_factor_token' => $pending, 'token' => str_repeat('x', 65)])
            ->assertUnprocessable();
        $this->travel(6)->minutes();
        $this->postJson('/api/2fa/verify-link', ['two_factor_token' => $pending, 'token' => $link])
            ->assertUnauthorized();
    }

    public function test_issuing_another_login_invalidates_old_link()
    {
        $user = $this->emailUser();
        [$old, , $link] = $this->sentChallenge($user);
        [$pending, , $freshLink] = $this->sentChallenge($user);
        $this->postJson('/api/2fa/verify-link', ['two_factor_token' => $old, 'token' => $link])->assertUnauthorized();
        $this->postJson('/api/2fa/verify-link', ['two_factor_token' => $pending, 'token' => $link])
            ->assertUnprocessable();
        $this->postJson('/api/2fa/verify-link', ['two_factor_token' => $pending, 'token' => $freshLink])->assertOk();
    }
    public function test_link_stays_invalid_after_factor_policy_is_changed_back()
    {
        $user = $this->emailUser();
        [$pending, , $link] = $this->sentChallenge($user);
        $factor = $user->twoFactorAuth()->first();
        $factor->update(['type' => 'phone']);
        $factor->update(['type' => 'email']);
        $this->postJson('/api/2fa/verify-link', ['two_factor_token' => $pending, 'token' => $link])
            ->assertUnprocessable();
    }

}
