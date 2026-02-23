<?php

namespace Whilesmart\UserAuthentication\Tests\Feature;

use Illuminate\Support\Facades\Event;
use Whilesmart\UserAuthentication\Events\UserLoggedOutEvent;
use Whilesmart\UserAuthentication\Models\User;
use Whilesmart\UserAuthentication\Tests\TestCase;

class LogoutTest extends TestCase
{
    public function test_user_can_logout_successfully()
    {
        Event::fake();
        $user = User::create([
            'first_name' => 'Test',
            'last_name' => 'User',
            'email' => 'test@example.com',
            'password' => \Illuminate\Support\Facades\Hash::make('password'),
        ]);
        $token = $user->createToken('test-token')->plainTextToken;

        $response = $this->withHeader('Authorization', 'Bearer ' . $token)
            ->postJson('/api/logout');

        $response->assertStatus(200);
        $this->assertCount(0, $user->tokens);
        Event::assertDispatched(UserLoggedOutEvent::class);
    }
}
