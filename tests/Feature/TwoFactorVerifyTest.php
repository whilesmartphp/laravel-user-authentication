<?php

namespace Whilesmart\UserAuthentication\Tests\Feature;

use PragmaRX\Google2FALaravel\Facade as Google2FA;
use Whilesmart\UserAuthentication\Tests\TestCase;

class TwoFactorVerifyTest extends TestCase
{
    protected function setUp(): void
    {
        parent::setUp();
    }

    /** @test */
    public function test_it_can_verify_a_valid_totp_code()
    {
        $secret = 'KVKFKRJTMR2G6KBV';

        $user = $this->createUser([
            'two_factor_secret' => encrypt($secret),
            'two_factor_enabled' => true,
            'two_factor_type' => 'totp',
        ]);

        $this->withSession([
            '2fa:user_id' => $user->id,
            '2fa:type' => 'totp',

        ]);

        // Generate a real valid code using the secret
        $validCode = Google2FA::getCurrentOtp($secret);

        $response = $this->postJson('/api/2fa/verify', [
            'code' => $validCode,
        ]);

        $response->assertStatus(200);
        // $this->assertEquals($user->id, auth()->id());
        $this->assertAuthenticatedAs($user);
    }
}
