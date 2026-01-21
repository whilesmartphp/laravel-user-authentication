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

        dump('Test app key:'.config('app.key'));

        $user = $this->createUser([
            'two_factor_secret' => encrypt($secret),
            'two_factor_enabled' => true,
            'two_factor_type' => 'totp',
        ]);

        dump('secret stored for user (encrypted): '.$user->two_factor_secret);
        $this->withSession([
            '2fa:user_id' => $user->id,
            '2fa:type' => 'totp',

        ]);

        // Generate a real valid code using the secret
        $validCode = Google2FA::getCurrentOtp($secret);
        dump('Generated valid TOTP code: '.$validCode);

        $response = $this->postJson('/api/2fa/verify', [
            'code' => $validCode,
        ]);

        // If it's not successful, this will dump the error message to your terminal
        if ($response->status() !== 200) {
            dump('ERROR: Decryption failed. Key in config is: '.config('app.key'));
            dump($response->json());
        }
        $response->assertStatus(200);
        // $this->assertEquals($user->id, auth()->id());
        $this->assertAuthenticatedAs($user);
    }
}
