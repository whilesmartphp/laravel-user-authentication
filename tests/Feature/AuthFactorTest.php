<?php

namespace Whilesmart\UserAuthentication\Tests\Feature;

use Illuminate\Support\Facades\Crypt;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Hash;
use Whilesmart\UserAuthentication\Events\VerificationCodeGeneratedEvent;
use Whilesmart\UserAuthentication\Models\AuthChallenge;
use Whilesmart\UserAuthentication\Tests\TwoFactorTestCase;

class AuthFactorTest extends TwoFactorTestCase
{
    private function addTotp(string $token, string $label = 'Backup'): array
    {
        $setup = $this->postJson('/api/2fa/setup', ['type' => 'totp', 'label' => $label], $this->bearer($token))
            ->assertOk()->json('data');
        $code = app('pragmarx.google2fa')->getCurrentOtp($setup['secret']);
        $this->postJson('/api/2fa/confirm', [
            'factor_id' => $setup['factor_id'], 'code' => $code,
        ], $this->bearer($token))->assertOk();

        return $setup;
    }

    private function addEmail(string $token): array
    {
        Event::fake([VerificationCodeGeneratedEvent::class]);
        $setup = $this->postJson('/api/2fa/setup', ['type' => 'email'], $this->bearer($token))
            ->assertOk()->json('data');
        $event = Event::dispatched(VerificationCodeGeneratedEvent::class)->last()[0];
        $this->postJson('/api/2fa/confirm', [
            'factor_id' => $setup['factor_id'],
            'two_factor_token' => $setup['two_factor_token'],
            'code' => $event->code,
        ], $this->bearer($token))->assertOk();

        return $setup;
    }

    public function test_multiple_factors_and_listing_excludes_all_private_attributes()
    {
        [$user, $token] = $this->enroll();
        $second = $this->addTotp($token);
        $response = $this->getJson('/api/2fa/factors', $this->bearer($token))->assertOk()
            ->assertJsonCount(2, 'data.factors')->assertJsonPath('data.factors.1.label', 'Backup');
        foreach ($response->json('data.factors') as $factor) {
            $this->assertEqualsCanonicalizing(
                ['id', 'type', 'label', 'confirmed_at', 'last_used_at'],
                array_keys($factor)
            );
        }
        $this->assertTrue($user->fresh()->hasTwoFactorEnabled());
        $this->assertNotEquals($second['secret'], $user->factors()->first()->secret);
        $this->assertStringNotContainsString($second['secret'], $response->getContent());
    }

    public function test_duplicate_email_and_missing_phone_contact_are_refused()
    {
        [$user, $token] = $this->enroll();
        $this->addEmail($token);
        $this->postJson('/api/2fa/setup', ['type' => 'email'], $this->bearer($token))->assertUnprocessable();
        $this->postJson('/api/2fa/setup', ['type' => 'phone'], $this->bearer($token))->assertUnprocessable();
        $this->assertSame(2, $user->factors()->count());
    }

    public function test_phone_enrollment_replaces_pending_factor_and_rejects_confirmed_duplicate()
    {
        $user = $this->createUser(['phone' => '+15551234567']);
        $token = $this->passwordLogin($user)->assertOk()->json('data.token');
        Event::fake([VerificationCodeGeneratedEvent::class]);
        $setup = $this->postJson('/api/2fa/setup', ['type' => 'phone'], $this->bearer($token))
            ->assertOk()->json('data');
        $replacement = $this->postJson('/api/2fa/setup', ['type' => 'phone'], $this->bearer($token))
            ->assertOk()->json('data');
        $this->assertNotSame($setup['factor_id'], $replacement['factor_id']);
        $this->assertSame(1, $user->factors()->count());
        $setup = $replacement;
        $event = Event::dispatched(VerificationCodeGeneratedEvent::class)->last()[0];
        $this->postJson('/api/2fa/confirm', [
            'factor_id' => $setup['factor_id'],
            'two_factor_token' => $setup['two_factor_token'],
            'code' => $event->code,
        ], $this->bearer($token))->assertOk()->assertJsonCount(10, 'data.recovery_codes');
        $this->postJson('/api/2fa/setup', ['type' => 'phone'], $this->bearer($token))->assertUnprocessable();
    }

    public function test_maximum_counts_pending_and_confirmed_factors()
    {
        config(['user-authentication.two_factor.max_factors' => 2]);
        [$user, $token] = $this->enroll();
        $this->postJson('/api/2fa/setup', [], $this->bearer($token))->assertOk();
        $this->postJson('/api/2fa/setup', ['type' => 'email'], $this->bearer($token))->assertUnprocessable();
        $this->assertSame(2, $user->factors()->count());
    }

    public function test_restarting_totp_setup_keeps_one_pending_factor_and_room_for_other_types()
    {
        config(['user-authentication.two_factor.max_factors' => 3]);
        Event::fake([VerificationCodeGeneratedEvent::class]);
        $user = $this->createUser(['phone' => '+15551234567']);
        $token = $this->passwordLogin($user)->assertOk()->json('data.token');
        $first = $this->postJson('/api/2fa/setup', ['type' => 'totp'], $this->bearer($token))
            ->assertOk()->json('data');
        $second = $this->postJson('/api/2fa/setup', ['type' => 'totp'], $this->bearer($token))
            ->assertOk()->json('data');
        $this->assertNotSame($first['factor_id'], $second['factor_id']);
        $this->assertSame(1, $user->factors()->where('type', 'totp')->whereNull('confirmed_at')->count());
        foreach (['email', 'phone'] as $type) {
            $this->postJson('/api/2fa/setup', ['type' => $type], $this->bearer($token))->assertOk();
        }
        $this->assertSame(3, $user->factors()->whereNull('confirmed_at')->count());
        $this->postJson('/api/2fa/setup', ['type' => 'totp'], $this->bearer($token))->assertOk();
        $this->assertSame(3, $user->factors()->count());
    }

    public function test_recovery_codes_are_password_hashes_and_spent_rows_are_retained()
    {
        [$user, , , $codes] = $this->enroll();
        $this->assertCount(10, $codes);
        $rows = DB::table('auth_recovery_codes')->where('authenticatable_id', $user->id)->get();
        $this->assertCount(10, $rows);
        $this->assertTrue(Hash::check($codes[0], $rows[0]->code_hash));
        $this->assertNotSame($codes[0], $rows[0]->code_hash);
        $this->assertArrayNotHasKey('code_hash', $user->recoveryCodes()->first()->toArray());
        foreach ($codes as $code) {
            $this->assertStringNotContainsString($code, $rows->toJson());
        }
        try {
            Crypt::decryptString($rows[0]->code_hash);
            $this->fail('Password hashes must not be decryptable.');
        } catch (\Illuminate\Contracts\Encryption\DecryptException $exception) {
            $this->assertNotEmpty($exception->getMessage());
        }
        $pending = $this->passwordLogin($user)->assertOk()->json('data.two_factor_token');
        $this->verify($pending, $codes[0])->assertOk();
        $pending = $this->passwordLogin($user)->assertOk()->json('data.two_factor_token');
        $this->verify($pending, $codes[0])->assertUnprocessable();
        $this->assertSame(10, $user->recoveryCodes()->count());
        $this->assertSame(1, $user->recoveryCodes()->whereNotNull('used_at')->count());
    }

    public function test_regeneration_replaces_the_entire_owner_set()
    {
        [$user, $token, , $codes] = $this->enroll();
        $fresh = $this->postJson('/api/2fa/recovery-codes', [], $this->bearer($token))
            ->assertOk()->assertJsonCount(10, 'data.recovery_codes')->json('data.recovery_codes');
        $pending = $this->passwordLogin($user)->assertOk()->json('data.two_factor_token');
        $this->verify($pending, $codes[0])->assertUnprocessable();
        $this->verify($pending, $fresh[0])->assertOk();
        $this->assertSame(10, $user->recoveryCodes()->count());
    }

    public function test_codes_survive_removing_one_factor_and_are_deleted_with_the_last()
    {
        [$user, $token, , $codes] = $this->enroll();
        $second = $this->addTotp($token);
        $this->postJson('/api/2fa/disable', [
            'factor_id' => $second['factor_id'], 'code' => $codes[0],
        ], $this->bearer($token))->assertOk();
        $this->assertSame(10, $user->recoveryCodes()->count());
        $pending = $this->passwordLogin($user)->assertOk()->json('data.two_factor_token');
        $token = $this->verify($pending, $codes[1])->assertOk()->json('data.token');
        $this->postJson('/api/2fa/disable', [
            'factor_id' => $user->factors()->value('id'), 'code' => $codes[2],
        ], $this->bearer($token))->assertOk();
        $this->assertSame(0, $user->recoveryCodes()->count());
        $this->assertFalse($user->fresh()->hasTwoFactorEnabled());
    }

    public function test_adding_an_unconfirmed_factor_preserves_pending_login()
    {
        [$user, $token, , $codes] = $this->enroll();
        $pending = $this->passwordLogin($user)->assertOk()->json('data.two_factor_token');
        $this->postJson('/api/2fa/setup', [], $this->bearer($token))->assertOk();
        $this->verify($pending, $codes[0])->assertOk();
        $this->assertSame(1, $user->recoveryCodes()->whereNotNull('used_at')->count());
    }

    public function test_pending_login_can_select_another_confirmed_factor()
    {
        [$user, $token] = $this->enroll();
        $email = $this->addEmail($token);
        $pending = $this->passwordLogin($user)->assertOk()->json('data.two_factor_token');
        $selected = $this->postJson('/api/2fa/resend', [
            'two_factor_token' => $pending, 'factor_id' => $email['factor_id'],
        ])->assertOk()->assertJsonPath('data.method', 'email')->json('data.two_factor_token');
        $event = Event::dispatched(VerificationCodeGeneratedEvent::class)->last()[0];
        $this->verify($pending, $event->code)->assertUnauthorized();
        $this->verify($selected, $event->code)->assertOk();
    }

    public function test_successful_login_updates_last_used_at()
    {
        [$user, , , $codes] = $this->enroll();
        $before = $user->factors()->first()->last_used_at;
        $this->travel(1)->minutes();
        $pending = $this->passwordLogin($user)->assertOk()->json('data.two_factor_token');
        $this->verify($pending, $codes[0])->assertOk();
        $this->assertTrue($user->factors()->first()->last_used_at->greaterThan($before));
    }

    public function test_confirming_and_removing_another_factor_invalidates_pending_login()
    {
        [$user, $token, , $codes] = $this->enroll();
        $setup = $this->postJson('/api/2fa/setup', [], $this->bearer($token))->assertOk()->json('data');
        $pending = $this->passwordLogin($user)->assertOk()->json('data.two_factor_token');
        $this->postJson('/api/2fa/confirm', [
            'factor_id' => $setup['factor_id'],
            'code' => app('pragmarx.google2fa')->getCurrentOtp($setup['secret']),
        ], $this->bearer($token))->assertOk()->assertJsonCount(0, 'data.recovery_codes');
        $this->verify($pending, $codes[0])->assertUnprocessable();
        $pending = $this->passwordLogin($user)->assertOk()->json('data.two_factor_token');
        $this->postJson('/api/2fa/disable', [
            'factor_id' => $setup['factor_id'], 'code' => $codes[0],
        ], $this->bearer($token))->assertOk();
        $this->verify($pending, $codes[1])->assertUnprocessable();
    }

    public function test_factor_ids_are_scoped_to_the_owner()
    {
        [$owner, , , $codes] = $this->enroll();
        [$other, $token] = $this->enroll();
        $id = $owner->factors()->value('id');
        $this->postJson('/api/2fa/confirm', [
            'factor_id' => $id, 'code' => '123456',
        ], $this->bearer($token))->assertStatus(400);
        $this->postJson('/api/2fa/disable', [
            'factor_id' => $id, 'code' => $codes[0],
        ], $this->bearer($token))->assertNotFound();
        $pending = $this->passwordLogin($other)->assertOk()->json('data.two_factor_token');
        $this->postJson('/api/2fa/resend', [
            'factor_id' => $id, 'two_factor_token' => $pending,
        ])->assertUnprocessable();
        $this->getJson('/api/2fa/factors', $this->bearer($token))
            ->assertOk()->assertJsonCount(1, 'data.factors')
            ->assertJsonPath('data.factors.0.id', $other->factors()->value('id'));
        $this->assertSame(0, $owner->recoveryCodes()->whereNotNull('used_at')->count());
    }

    public function test_model_prune_retains_recently_expired_challenges()
    {
        $user = $this->emailUser();
        $this->sentChallenge($user);
        $this->travel(25)->hours();
        $this->sentChallenge($user);
        $this->travel(6)->minutes();
        $this->artisan('model:prune', ['--model' => [AuthChallenge::class]])->assertExitCode(0);
        $this->assertDatabaseCount('auth_challenges', 1);
        $this->assertTrue(AuthChallenge::first()->expires_at->isPast());
    }
}
