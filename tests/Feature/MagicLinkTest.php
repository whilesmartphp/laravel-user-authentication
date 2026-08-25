<?php

namespace Whilesmart\UserAuthentication\Tests\Feature;

use Illuminate\Support\Facades\Config;
use Illuminate\Support\Facades\Event;
use Whilesmart\UserAuthentication\Events\VerificationCodeGeneratedEvent;
use Whilesmart\UserAuthentication\Services\TwoFactorService;
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
            'token' => hash('sha256', $token),
            'expires_at' => now()->addMinutes(15),
            'is_used' => false,
        ]);

        $response = $this->getJson("/api/2fa/verify?token={$token}&user={$user->id}");

        $response->assertStatus(200)
            ->assertJsonPath('token', fn (string $tokenValue) => ! empty($tokenValue));
    }

    /** @test */
    public function test_it_rejects_expired_magic_link()
    {
        $user = $this->createUser();
        $token = \Illuminate\Support\Str::random(64);

        \Whilesmart\UserAuthentication\Models\MagicLink::create([
            'user_id' => $user->id,
            'token' => hash('sha256', $token),
            'expires_at' => now()->subMinute(),
            'is_used' => false,
        ]);

        $response = $this->getJson("/api/2fa/verify?token={$token}&user={$user->id}");

        $response->assertStatus(403);
    }

    /** @test */
    public function test_it_rejects_already_used_magic_link()
    {
        $user = $this->createUser();
        $token = \Illuminate\Support\Str::random(64);

        \Whilesmart\UserAuthentication\Models\MagicLink::create([
            'user_id' => $user->id,
            'token' => hash('sha256', $token),
            'expires_at' => now()->addMinutes(15),
            'is_used' => true,
        ]);

        $response = $this->getJson("/api/2fa/verify?token={$token}&user={$user->id}");

        $response->assertStatus(403);
    }

    /** @test */
    public function test_magic_link_url_uses_configured_base_url()
    {
        $user = $this->createUser();
        Config::set('user-authentication.magic_link.url', 'https://auth.example.com/verify');

        Event::fake([VerificationCodeGeneratedEvent::class]);

        app(TwoFactorService::class)->handleChallenge($user, 'email', $user->email);

        Event::assertDispatched(VerificationCodeGeneratedEvent::class, function ($event) use ($user) {
            return str_starts_with($event->magicLink, 'https://auth.example.com/verify?token=')
                && str_contains($event->magicLink, "user={$user->id}");
        });
    }
}
