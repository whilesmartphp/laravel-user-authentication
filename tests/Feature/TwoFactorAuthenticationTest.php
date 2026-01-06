<?php

namespace Whilesmart\UserAuthentication\Tests\Feature;

use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\URL;
use PragmaRX\Google2FALaravel\Facade as Google2FA;
use Whilesmart\UserAuthentication\Events\VerificationCodeGeneratedEvent;
use Whilesmart\UserAuthentication\Tests\TestCase;

class TwoFactorAuthenticationTest extends TestCase
{
    /** @test */
    public function test_middleware_intercepts_login_when_2fa_is_enabled()
    {
        $user = $this->createUser([
            'two_factor_enabled' => true,
            'two_factor_type' => 'totp',
        ]);

        // Simulate a successful password login
        $response = $this->postJson('/api/login', [
            'email' => $user->email,
            'password' => 'password123',
        ]);

        // Assert: Instead of a token, we get a 403 2FA challenge
        $response->assertStatus(403)
            ->assertJson([
                'two_factor_required' => true,
                'method' => 'totp',
            ]);

        // Assert: User is logged out and ID is in session
        $this->assertFalse(Auth::check());
        $this->assertEquals($user->id, session('2fa:user_id'));
    }

    /** @test */
    public function test_it_can_verify_a_valid_totp_code()
    {
        $secret = 'KVKFKRJTMR2G6KBV';
        $user = $this->createUser([
            'two_factor_enabled' => true,
            'two_factor_secret' => encrypt($secret),
            'two_factor_type' => 'totp',
        ]);

        // Mock the session state from middleware
        session(['2fa:user_id' => $user->id]);

        // Generate a valid code using the secret
        $validCode = Google2FA::getCurrentOtp($secret);

        $response = $this->postJson('/api/2fa/verify', [
            'code' => $validCode,
        ]);

        $response->assertStatus(200)
            ->assertJson(['message' => 'Authenticated successfully.']);

        $this->assertAuthenticatedAs($user);
        $this->assertTrue(session('2fa:verified'));
    }

    /** @test */
    public function test_it_sends_magic_link_for_email_2fa()
    {
        Event::fake();

        $user = $this->createUser([
            'two_factor_enabled' => true,
            'two_factor_type' => 'email',
        ]);

        // Trigger middleware by attempting login
        $this->postJson('/api/login', [
            'email' => $user->email,
            'password' => 'password123',
        ]);

        // Assert: Event was dispatched with a link
        Event::assertDispatched(VerificationCodeGeneratedEvent::class, function ($event) {
            return ! empty($event->link) && str_contains($event->link, '2fa/verify-link');
        });
    }

    /** @test */
    public function test_it_authenticates_via_magic_link()
    {
        $user = $this->createUser();

        // Generate a signed URL manually
        $url = URL::temporarySignedRoute(
            '2fa.verify.link',
            now()->addMinutes(15),
            ['user' => $user->id]
        );

        $response = $this->get($url);

        // Check for redirect (the link handler uses redirect())
        $response->assertStatus(302);
        $this->assertAuthenticatedAs($user);
        $this->assertTrue(session('2fa:verified'));
    }

    /** @test */
    public function test_it_fails_verification_with_invalid_code()
    {
        $user = $this->createUser([
            'two_factor_enabled' => true,
            'two_factor_secret' => encrypt('KVKFKRJTMR2G6KBV'),
            'two_factor_type' => 'totp',
        ]);

        session(['2fa:user_id' => $user->id]);

        $response = $this->postJson('/api/2fa/verify', [
            'code' => '000000', // Incorrect code
        ]);

        $response->assertStatus(422);
        $this->assertFalse(Auth::check());
    }
}
