<?php

namespace Whilesmart\UserAuthentication\Tests\Feature;

use Illuminate\Support\Facades\URL;
use Whilesmart\UserAuthentication\Models\User;
use Whilesmart\UserAuthentication\Tests\TestCase;

class MagicLinkTest extends TestCase
{
    /** @test */
    public function test_it_authenticates_user_via_signed_magic_link()
    {
        // $user = User::factory()->create();
        $user = $this->createUser();

        // Generate a valid signed URL
        $url = URL::temporarySignedRoute(
            '2fa.verify.link',
            now()->addMinutes(15),
            ['user' => $user->id]
        );

        // Request the URL
        $response = $this->get($url);

        // Assert redirect to dashboard and user is logged in
        $response->assertRedirect('/dashboard');
        $this->assertAuthenticatedAs($user);
        $this->assertTrue(session('2fa:verified'));
    }
}
