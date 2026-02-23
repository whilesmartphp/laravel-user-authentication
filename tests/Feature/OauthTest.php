<?php

namespace Whilesmart\UserAuthentication\Tests\Feature;

use Faker\Factory;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\Event;
use Laravel\Socialite\Contracts\User as SocialiteUser;
use Laravel\Socialite\Facades\Socialite;
use Laravel\Socialite\Two\AbstractProvider;
use Orchestra\Testbench\Attributes\WithMigration;
use Whilesmart\UserAuthentication\Events\OauthUserAuthenticatedEvent;
use Whilesmart\UserAuthentication\Events\UserLoggedInEvent;
use Whilesmart\UserAuthentication\Events\UserRegisteredEvent;
use Whilesmart\UserAuthentication\Models\OauthAccount;
use Whilesmart\UserAuthentication\Models\User;
use Whilesmart\UserAuthentication\Tests\TestCase;

use function Orchestra\Testbench\workbench_path;

#[WithMigration]
class OauthTest extends TestCase
{
    use RefreshDatabase;

    protected function defineDatabaseMigrations()
    {
        $this->loadMigrationsFrom(
            workbench_path('database/migrations')
        );
    }

    protected function getPackageProviders($app)
    {
        return [
            'Laravel\Socialite\SocialiteServiceProvider',
            'Whilesmart\UserAuthentication\UserAuthenticationServiceProvider',
        ];
    }

    protected function defineEnvironment($app)
    {
        $app['config']->set('services.github', [
            'client_id' => 'test-client-id',
            'client_secret' => 'test-client-secret',
            'redirect' => 'http://localhost/auth/github/callback',
        ]);
    }

    protected function mockSocialiteUser(array $overrides = []): SocialiteUser
    {
        $faker = Factory::create();

        $socialiteUser = $this->createMock(SocialiteUser::class);
        $socialiteUser->method('getId')->willReturn($overrides['id'] ?? $faker->randomNumber(8));
        $socialiteUser->method('getName')->willReturn($overrides['name'] ?? $faker->name);
        $socialiteUser->method('getEmail')->willReturn($overrides['email'] ?? $faker->unique()->safeEmail);
        $socialiteUser->method('getAvatar')->willReturn($overrides['avatar'] ?? 'https://avatars.example.com/123');
        $socialiteUser->token = $overrides['token'] ?? 'gho_fake_github_token_'.$faker->sha1;

        return $socialiteUser;
    }

    protected function mockSocialiteDriver(SocialiteUser $socialiteUser): void
    {
        $provider = $this->createMock(AbstractProvider::class);
        $provider->method('stateless')->willReturnSelf();
        $provider->method('user')->willReturn($socialiteUser);

        Socialite::shouldReceive('driver')
            ->with('github')
            ->andReturn($provider);
    }

    protected function mockSocialiteDriverWithException(\Exception $exception): void
    {
        $provider = $this->createMock(AbstractProvider::class);
        $provider->method('stateless')->willReturnSelf();
        $provider->method('user')->willThrowException($exception);

        Socialite::shouldReceive('driver')
            ->with('github')
            ->andReturn($provider);
    }

    public function test_oauth_callback_creates_new_user_and_oauth_account()
    {
        $this->withoutExceptionHandling();
        Event::fake();

        $socialiteUser = $this->mockSocialiteUser([
            'id' => 12345,
            'name' => 'Jane Doe',
            'email' => 'jane@example.com',
            'avatar' => 'https://avatars.example.com/jane',
            'token' => 'gho_test_token_abc',
        ]);
        $this->mockSocialiteDriver($socialiteUser);

        $response = $this->getJson('/api/oauth/github/callback?code=test_code');

        $response->assertStatus(201)
            ->assertJsonStructure([
                'success',
                'data' => [
                    'user',
                    'token',
                ],
                'message',
            ]);

        $this->assertDatabaseHas('users', ['email' => 'jane@example.com']);
        $this->assertDatabaseHas('oauth_accounts', [
            'provider' => 'github',
            'provider_id' => '12345',
            'avatar_url' => 'https://avatars.example.com/jane',
        ]);

        Event::assertDispatched(UserRegisteredEvent::class);
        Event::assertDispatched(OauthUserAuthenticatedEvent::class, function ($event) {
            return $event->driver === 'github'
                && $event->isNewUser === true
                && $event->user->email === 'jane@example.com';
        });
    }

    public function test_oauth_callback_logs_in_existing_user_and_updates_oauth_account()
    {
        Event::fake();

        $user = User::create([
            'email' => 'existing@example.com',
            'first_name' => 'Existing',
            'password' => 'password123',
        ]);

        OauthAccount::create([
            'user_id' => $user->id,
            'provider' => 'github',
            'provider_id' => '99999',
            'avatar_url' => 'https://old-avatar.example.com',
            'token' => 'old_token',
        ]);

        $socialiteUser = $this->mockSocialiteUser([
            'id' => 99999,
            'name' => 'Existing User',
            'email' => 'existing@example.com',
            'avatar' => 'https://new-avatar.example.com',
            'token' => 'gho_new_token',
        ]);
        $this->mockSocialiteDriver($socialiteUser);

        $response = $this->getJson('/api/oauth/github/callback?code=test_code');

        $response->assertStatus(201);

        $oauthAccount = OauthAccount::where('user_id', $user->id)->where('provider', 'github')->first();
        $this->assertEquals('https://new-avatar.example.com', $oauthAccount->avatar_url);
        $this->assertEquals('99999', $oauthAccount->provider_id);

        Event::assertDispatched(UserLoggedInEvent::class);
        Event::assertDispatched(OauthUserAuthenticatedEvent::class, function ($event) {
            return $event->isNewUser === false;
        });
        Event::assertNotDispatched(UserRegisteredEvent::class);
    }

    public function test_oauth_callback_returns_json_error_when_provider_fails()
    {
        $this->mockSocialiteDriverWithException(
            new \GuzzleHttp\Exception\ClientException(
                'Client error',
                new \GuzzleHttp\Psr7\Request('GET', 'https://api.github.com/user'),
                new \GuzzleHttp\Psr7\Response(401, [], '{"message":"Bad credentials"}')
            )
        );

        $response = $this->getJson('/api/oauth/github/callback?code=bad_code');

        $response->assertStatus(401)
            ->assertJson([
                'success' => false,
                'message' => 'OAuth authentication failed',
            ]);
    }

    public function test_oauth_callback_returns_error_when_name_or_email_missing()
    {
        $socialiteUser = $this->mockSocialiteUser([
            'name' => '',
            'email' => '',
        ]);
        $this->mockSocialiteDriver($socialiteUser);

        $response = $this->getJson('/api/oauth/github/callback?code=test_code');

        $response->assertStatus(400)
            ->assertJson([
                'success' => false,
                'message' => 'Your app must request the name and email of the user',
            ]);
    }

    public function test_oauth_login_uses_configured_scopes()
    {
        config(['user-authentication.oauth_scopes.github' => ['read:user', 'user:email', 'repo']]);

        $provider = $this->createMock(AbstractProvider::class);
        $provider->method('stateless')->willReturnSelf();
        $provider->expects($this->once())
            ->method('scopes')
            ->with(['read:user', 'user:email', 'repo'])
            ->willReturnSelf();

        $redirectResponse = new \Illuminate\Http\RedirectResponse('https://github.com/login/oauth/authorize?scope=read:user+user:email+repo');
        $provider->method('redirect')->willReturn($redirectResponse);

        Socialite::shouldReceive('driver')
            ->with('github')
            ->andReturn($provider);

        $response = $this->getJson('/api/oauth/github/login');

        $response->assertStatus(200)
            ->assertJsonStructure([
                'success',
                'data' => ['url'],
            ]);
    }

    public function test_oauth_login_works_without_configured_scopes()
    {
        config(['user-authentication.oauth_scopes' => []]);

        $provider = $this->createMock(AbstractProvider::class);
        $provider->method('stateless')->willReturnSelf();
        $provider->expects($this->never())->method('scopes');

        $redirectResponse = new \Illuminate\Http\RedirectResponse('https://github.com/login/oauth/authorize');
        $provider->method('redirect')->willReturn($redirectResponse);

        Socialite::shouldReceive('driver')
            ->with('github')
            ->andReturn($provider);

        $response = $this->getJson('/api/oauth/github/login');

        $response->assertStatus(200);
    }

    public function test_oauth_callback_stores_provider_data_on_oauth_account()
    {
        Event::fake();

        $socialiteUser = $this->mockSocialiteUser([
            'id' => 77777,
            'email' => 'provider-data@example.com',
            'name' => 'Test User',
            'avatar' => 'https://avatars.example.com/77777',
            'token' => 'gho_provider_token_xyz',
        ]);
        $this->mockSocialiteDriver($socialiteUser);

        $this->getJson('/api/oauth/github/callback?code=test_code');

        $user = User::where('email', 'provider-data@example.com')->first();
        $this->assertNotNull($user);

        $oauthAccount = OauthAccount::where('user_id', $user->id)->where('provider', 'github')->first();
        $this->assertNotNull($oauthAccount);
        $this->assertEquals('77777', $oauthAccount->provider_id);
        $this->assertEquals('https://avatars.example.com/77777', $oauthAccount->avatar_url);
        $this->assertEquals('gho_provider_token_xyz', $oauthAccount->token);
    }

    public function test_oauth_callback_does_not_create_duplicate_oauth_accounts()
    {
        Event::fake();

        $email = 'nodupe@example.com';
        $user = User::create([
            'email' => $email,
            'first_name' => 'No Dupe',
            'password' => 'password123',
        ]);
        OauthAccount::create([
            'user_id' => $user->id,
            'provider' => 'github',
            'provider_id' => '55555',
        ]);

        $socialiteUser = $this->mockSocialiteUser([
            'id' => 55555,
            'email' => $email,
            'name' => 'No Dupe',
        ]);
        $this->mockSocialiteDriver($socialiteUser);

        $this->getJson('/api/oauth/github/callback?code=test_code');

        $this->assertEquals(1, OauthAccount::where('user_id', $user->id)->where('provider', 'github')->count());
    }
}
