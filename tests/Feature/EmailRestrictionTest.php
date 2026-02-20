<?php

namespace Whilesmart\UserAuthentication\Tests\Feature;

use Whilesmart\UserAuthentication\Tests\TestCase;

class EmailRestrictionTest extends TestCase
{
    /** @test */
    public function test_it_allows_any_email_when_no_restriction_mode_is_set()
    {
        config(['user-authentication.email_restrictions.mode' => null]);

        $response = $this->postJson('/api/register', [
            'email' => 'test@example.com',
            'first_name' => 'John',
            'last_name' => 'Doe',
            'password' => 'password123',
        ]);

        $response->assertStatus(201);
    }

    /** @test */
    public function test_it_blocks_non_whitelisted_domains_in_whitelist_mode()
    {
        config([
            'user-authentication.email_restrictions.mode' => 'whitelist',
            'user-authentication.email_restrictions.domains' => ['whilesmart.com'],
        ]);

        // Attempt with gmail (should fail)
        $response = $this->postJson('/api/register', [
            'email' => 'outsider@gmail.com',
            'first_name' => 'John',
            'password' => 'password123',
        ]);

        $response->assertStatus(422);
        // $response->assertJsonValidationErrors(['email']);

    }

    /** @test */
    public function test_it_allows_whitelisted_domains_in_whitelist_mode()
    {
        config([
            'user-authentication.email_restrictions.mode' => 'whitelist',
            'user-authentication.email_restrictions.domains' => ['whilesmart.com'],
        ]);

        $response = $this->postJson('/api/register', [
            'email' => 'test@whilesmart.com',
            'first_name' => 'John',
            'last_name' => 'Doe',
            'password' => 'password123',
        ]);

        $response->assertStatus(201);
    }

    /** @test */
    public function test_it_blocks_blacklisted_domains_in_blacklist_mode()
    {
        config([
            'user-authentication.email_restrictions.mode' => 'blacklist',
            'user-authentication.email_restrictions.domains' => ['mailinator.com', 'temp-mail.org'],
        ]);

        // Attempt with blacklisted domain
        $response = $this->postJson('/api/register', [
            'email' => 'fake@mailinator.com',
            'first_name' => 'John',
            'password' => 'password123',
        ]);

        $response->assertStatus(422);
        // $this->assertStringContainsString('not allowed', $response->json('errors.email.0'));
    }

    /** @test */
    public function test_it_allows_non_blacklisted_domains_in_blacklist_mode()
    {
        config([
            'user-authentication.email_restrictions.mode' => 'blacklist',
            'user-authentication.email_restrictions.domains' => ['mailinator.com'],
        ]);

        // Attempt with gmail (should pass because it's not blacklisted)
        $response = $this->postJson('/api/register', [
            'email' => 'legit-user@gmail.com',
            'first_name' => 'John',
            'last_name' => 'Doe',
            'password' => 'password123',
        ]);

        $response->assertStatus(201);
    }

    /** @test */
    public function test_it_allows_everything_when_domain_list_is_empty()
    {
        config([
            'user-authentication.email_restrictions.mode' => 'whitelist',
            'user-authentication.email_restrictions.domains' => [], // Empty list
        ]);

        $response = $this->postJson('/api/register', [
            'email' => 'anybody@anywhere.com',
            'first_name' => 'John',
            'last_name' => 'Doe',
            'password' => 'password123',
        ]);

        $response->assertStatus(201);
    }

    /** @test */
    public function test_it_returns_correct_validation_message_with_attribute_name()
    {
        config([
            'user-authentication.email_restrictions.mode' => 'blacklist',
            'user-authentication.email_restrictions.domains' => ['blocked.com'],
        ]);

        $response = $this->postJson('/api/register', [
            'email' => 'user@blocked.com',
            'first_name' => 'John',
            'password' => 'password123',
        ]);

        $response->assertStatus(422);
        // This hits the $attribute logic and the $fail closure logic fully
        // $response->assertJsonValidationErrors(['email']);
        $response->assertJsonPath('errors.0.email.0', 'This email domain is not allowed for registration.');
    }
}
