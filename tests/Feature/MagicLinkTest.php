<?php

namespace Whilesmart\UserAuthentication\Tests\Feature;

use Illuminate\Support\Facades\URL;
use Whilesmart\UserAuthentication\Tests\TestCase;

class MagicLinkTest extends TestCase
{
    /** @test */
    public function test_it_authenticates_user_via_persistent_magic_link()
    {
        $user = $this->createUser();
        $token = \Illuminate\Support\Str::random(64);

        // Create the record in our new magic_links table
        \Whilesmart\UserAuthentication\Models\MagicLink::create([
            'user_id' => $user->id,
            'token' => $token,
            'expires_at' => now()->addMinutes(15),
            'is_used' => false,
        ]);

        $url = URL::temporarySignedRoute(
            '2fa.verify.link',
            now()->addMinutes(15),
            ['user' => $user->id, 'token' => $token]
        );

        $response = $this->get($url);

        $response->assertRedirect();
        $this->assertAuthenticatedAs($user);
        $this->assertTrue(session('2fa:verified'));
    }

    /** @test */
    public function test_it_rejects_expired_magic_link()
    {
        $user = $this->createUser();
        $token = \Illuminate\Support\Str::random(64);

        \Whilesmart\UserAuthentication\Models\MagicLink::create([
            'user_id' => $user->id,
            'token' => $token,
            'expires_at' => now()->subMinute(),
            'is_used' => false,
        ]);

        $url = URL::temporarySignedRoute(
            '2fa.verify.link',
            now()->addMinutes(15),
            ['user' => $user->id, 'token' => $token]
        );

        $response = $this->get($url);

        $response->assertStatus(403);
    }

    /** @test */
    public function test_it_rejects_already_used_magic_link()
    {
        $user = $this->createUser();
        $token = \Illuminate\Support\Str::random(64);

        \Whilesmart\UserAuthentication\Models\MagicLink::create([
            'user_id' => $user->id,
            'token' => $token,
            'expires_at' => now()->addMinutes(15),
            'is_used' => true,
        ]);

        $url = URL::temporarySignedRoute(
            '2fa.verify.link',
            now()->addMinutes(15),
            ['user' => $user->id, 'token' => $token]
        );

        $response = $this->get($url);

        $response->assertStatus(403);
    }
}
