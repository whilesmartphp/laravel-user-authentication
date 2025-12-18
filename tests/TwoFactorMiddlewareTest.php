<?php

namespace Whilesmart\UserAuthentication\Tests\Feature;

use Whilesmart\UserAuthentication\Tests\TestCase;
use Whilesmart\UserAuthentication\Models\User;
use Illuminate\Support\Facades\Auth;

class TwoFactorMiddlewareTest extends TestCase
{
    /** @test */
    public function users_with_2fa_enabled_are_intercepted()
    {
        // 1. Create a user with 2FA enabled
        $user = User::factory()->create([
            'two_factor_enabled' => true,
            'two_factor_type' => 'totp'
        ]);

        // 2. Act as the user (simulate password login success)
        Auth::login($user);

        // 3. Try to access a protected route
        $response = $this->getJson('/api/user-profile');

        // 4. Assert they get a 403 '2FA Required' response
        $response->assertStatus(403);
        $response->assertJsonStructure(['two_factor_required', 'method']);
        
        // Assert the user was logged out of the full session
        $this->assertFalse(Auth::check());
    }
}