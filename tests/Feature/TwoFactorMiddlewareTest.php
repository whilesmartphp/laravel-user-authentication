<?php

namespace Whilesmart\UserAuthentication\Tests\Feature;

use Illuminate\Support\Facades\Auth;
use Whilesmart\UserAuthentication\Models\User;
use Whilesmart\UserAuthentication\Tests\TestCase;

class TwoFactorMiddlewareTest extends TestCase
{
    /** @test */
    public function test_users_with_2fa_enabled_are_intercepted()
    {
        // 1. Create a user with 2FA enabled
        // $user = $this->createUser();
        $user = User::create([
            'first_name' => 'Mercy',
            'last_name' => 'Ma',
            'email' => 'mercy@gmail.com',
            'password' => bcrypt('password123'),
        ]);
        $user->twoFactorAuth()->create([
            'secret' => 'KVKFKRJTMR2G6KBV',
            'type' => 'totp',
            'is_enabled' => true,
        ]);

        // 2. Act as the user (simulate password login success)
        // Auth::login($user);

        // 3. Try to access a protected route
        // $response = $this->getJson('/api/user-profile');
        $response = $this->postJson('/api/login', [
            'email' => $user->email,
            'password' => 'password123',
        ]);

        $response->assertStatus(200);
        $response->assertJson([
            'success' => true,
            'message' => 'Two-factor authentication required.',
            'data' => [
                'two_factor_required' => true,
                'method' => 'totp',
            ],
        ]);
        // Ensure the user remains unauthenticated/not logged in
        $this->assertFalse(Auth::check());
    }

    /** @test */
    public function test_middleware_blocks_access_to_temporary_protected_route()
    {
        $this->app['router']->get('/api/test-protected', function () {
            return response()->json(['success' => true]);
        })->middleware(['web', \Whilesmart\UserAuthentication\Http\Middleware\RedirectIfTwoFactorEnabled::class]);

        $user = User::create([
            'first_name' => 'Middleware',
            'last_name' => 'Test',
            'email' => 'middleware@example.com',
            'password' => bcrypt('password123'),
        ]);

        $user->twoFactorAuth()->create([
            'secret' => 'KVKFKRJTMR2G6KBV',
            'type' => 'totp',
            'is_enabled' => true,
        ]);

        $response = $this->actingAs($user)->getJson('/api/test-protected');

        $response->assertStatus(403);
        $response->assertJsonFragment(['two_factor_required' => true]);
    }

    /** @test */
    public function test_users_without_2fa_pass_through_middleware()
    {
        $this->app['router']->get('/api/test-pass-protected', function () {
            return response()->json(['success' => true]);
        })->middleware(['web', \Whilesmart\UserAuthentication\Http\Middleware\RedirectIfTwoFactorEnabled::class]);

        $user = User::create([
            'first_name' => 'No2FA',
            'last_name' => 'User',
            'email' => 'no2fa@example.com',
            'password' => bcrypt('password123'),
        ]);

        // User has NO twoFactorAuth relation
        $response = $this->actingAs($user)->getJson('/api/test-pass-protected');

        $response->assertStatus(200);
        $response->assertJson(['success' => true]);
    }
}
