<?php

namespace Whilesmart\UserAuthentication\Tests\Feature;

use Whilesmart\UserAuthentication\Tests\TestCase;
use Whilesmart\UserAuthentication\Models\User;
use PragmaRX\Google2FALaravel\Facade as Google2FA;

class TwoFactorVerifyTest extends TestCase
{
    /** @test */
    public function it_can_verify_a_valid_totp_code()
    {
        $secret = 'ADUM6VREBTLU72UW'; // Example secret
        $user = User::factory()->create([
            'two_factor_secret' => encrypt($secret),
            'two_factor_enabled' => true,
            'two_factor_type' => 'totp'
        ]);

        // Put user ID in session as if they just came from the middleware
        session(['2fa:user_id' => $user->id]);

        // Generate a real valid code using the secret
        $validCode = Google2FA::getCurrentOtp($secret);

        $response = $this->postJson('/api/2fa/verify', [
            'code' => $validCode
        ]);

        $response->assertStatus(200);
        $this->assertEquals($user->id, auth()->id());
    }
}