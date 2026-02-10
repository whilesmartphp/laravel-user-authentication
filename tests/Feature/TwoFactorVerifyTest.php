<?php

namespace Whilesmart\UserAuthentication\Tests\Feature;

use Whilesmart\UserAuthentication\Tests\TestCase;

class TwoFactorVerifyTest extends TestCase
{
    protected function setUp(): void
    {
        parent::setUp();
    }

    /** @test */
    public function test_it_fails_with_expired_session()
    {
        // No session set
        $response = $this->postJson('/api/2fa/verify', ['code' => '123456']);
        $response->assertStatus(401);
    }
}
