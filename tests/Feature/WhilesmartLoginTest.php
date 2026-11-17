<?php

namespace Whilesmart\UserAuthentication\Tests\Feature;

use Firebase\JWT\JWT;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Http;
use Whilesmart\UserAuthentication\Models\WhilesmartIdentity;
use Whilesmart\UserAuthentication\Tests\TestCase;

class WhilesmartLoginTest extends TestCase
{
    private array $contract;
    private string $privateKey = "";
    private array $query = [];
    private string $browser;
    private array $overrides = [];

    protected function getEnvironmentSetUp($app)
    {
        parent::getEnvironmentSetUp($app);
        $app['config']->set('database.connections.testing.database', ':memory:');
    }

    protected function setUp(): void
    {
        parent::setUp();
        Cache::flush();
        $this->contract = json_decode(file_get_contents(__DIR__.'/../Fixtures/whilesmart-oidc.json'), true);
        $key = openssl_pkey_new(['private_key_bits' => 2048, 'private_key_type' => OPENSSL_KEYTYPE_RSA]);
        openssl_pkey_export($key, $this->privateKey);
        $details = openssl_pkey_get_details($key);
        $this->contract['jwks']['keys'][0]['n'] = rtrim(strtr(base64_encode($details['rsa']['n']), '+/', '-_'), '=');
        config(['user-authentication.whilesmart' => [
            'issuer' => $this->contract['discovery']['issuer'],
            'client_id' => $this->contract['id_claims']['aud'],
            'client_secret' => 'test-client-secret',
            'redirect_uri' => 'https://client.example.test/api/oauth/whilesmart/callback',
            'scopes' => ['openid', 'profile', 'email'],
        ]]);
        Http::preventStrayRequests();
        Http::fake(function ($request) {
            $metadata = $this->contract['discovery'];
            if ($request->url() === $metadata['issuer'].'/.well-known/openid-configuration') {
                return Http::response($metadata);
            }
            if ($request->url() === $metadata['jwks_uri']) {
                return Http::response($this->contract['jwks']);
            }
            if ($request->url() === $metadata['token_endpoint']) {
                $this->assertSame('authorization_code', $request['grant_type']);
                $this->assertSame($this->query['code_challenge'], rtrim(strtr(base64_encode(hash('sha256', $request['code_verifier'], true)), '+/', '-_'), '='));
                $claims = array_replace($this->contract['id_claims'], ['nonce' => $this->query['nonce'], 'iat' => time(), 'exp' => time() + 900], $this->overrides);

                return Http::response(array_replace($this->contract['tokens'], ['access_token' => 'test-access-token', 'id_token' => JWT::encode($claims, $this->privateKey, 'RS256', $this->contract['jwks']['keys'][0]['kid'])]));
            }
            if ($request->url() === $metadata['userinfo_endpoint']) {
                return Http::response($this->contract['userinfo']);
            }

            throw new \RuntimeException('Unexpected issuer request.');
        });
    }

    private function begin(?string $token = null): void
    {
        $response = $token === null ? $this->getJson('/api/oauth/whilesmart/login') : $this->withToken($token)->postJson('/api/oauth/whilesmart/link');
        $response->assertOk();
        parse_str(parse_url($response->json('data.url'), PHP_URL_QUERY), $this->query);
        $this->browser = $response->getCookie('user_auth_whilesmart', false)->getValue();
    }

    private function complete(?string $browser = null)
    {
        return $this->withCredentials()->withUnencryptedCookie('user_auth_whilesmart', $browser ?? $this->browser)->getJson('/api/oauth/whilesmart/callback?'.http_build_query(['state' => $this->query['state'], 'code' => 'captured-code-placeholder']));
    }

    public function test_verified_identity_creates_account_and_replay_is_rejected(): void
    {
        \Illuminate\Support\Facades\Event::fake([\Whilesmart\UserAuthentication\Events\UserRegisteredEvent::class]);
        $this->begin();
        $this->complete()->assertOk()->assertJsonStructure(['data' => ['token', 'user']]);
        $this->assertDatabaseHas('whilesmart_identities', ['subject' => $this->contract['userinfo']['sub']]);
        $this->assertNull(WhilesmartIdentity::first()->credentials);
        \Illuminate\Support\Facades\Event::assertDispatchedTimes(\Whilesmart\UserAuthentication\Events\UserRegisteredEvent::class, 1);
        $this->complete()->assertStatus(400);
    }

    public function test_browser_binding_rejects_another_browser_without_consuming_state(): void
    {
        $this->begin();
        $this->complete(str_repeat('0', 64))->assertStatus(400);
        $this->complete()->assertOk();
    }

    public function test_identity_nonce_and_audience_are_checked(): void
    {
        foreach (['nonce' => 'other-nonce', 'aud' => 'other-client', 'iss' => 'https://other.example.test', 'exp' => time() - 1] as $claim => $value) {
            $this->overrides = [$claim => $value];
            $this->begin();
            $this->complete()->assertStatus(400);
        }
        $this->assertDatabaseCount('whilesmart_identities', 0);
    }

    public function test_matching_email_requires_explicit_authenticated_link(): void
    {
        $user = $this->createUser(['email' => $this->contract['userinfo']['email']]);
        $this->begin();
        $this->complete()->assertStatus(409);
        $token = $user->createToken('link')->plainTextToken;
        $this->begin($token);
        $this->complete()->assertOk()->assertJsonMissingPath('data.token');
        $this->assertSame((string) $user->id, WhilesmartIdentity::first()->user_id);
    }

    public function test_link_authorization_is_rechecked_after_local_logout(): void
    {
        $user = $this->createUser();
        $this->begin($user->createToken('link')->plainTextToken);
        $user->tokens()->delete();
        $this->complete()->assertStatus(400);
        $this->assertDatabaseCount('whilesmart_identities', 0);
    }

    public function test_domain_restrictions_apply_to_new_accounts(): void
    {
        config(['user-authentication.email_restrictions.mode' => 'whitelist', 'user-authentication.email_restrictions.domains' => ['allowed.example.test']]);
        $this->begin();
        $this->complete()->assertStatus(422);
        $this->assertDatabaseCount('whilesmart_identities', 0);
    }

    public function test_linked_login_keeps_local_two_factor_requirement(): void
    {
        $user = $this->createUser();
        WhilesmartIdentity::create(['identity_key' => hash('sha256', $this->contract['discovery']['issuer']."\0".$this->contract['userinfo']['sub']), 'issuer' => $this->contract['discovery']['issuer'], 'subject' => $this->contract['userinfo']['sub'], 'user_type' => get_class($user), 'user_id' => (string) $user->id]);
        $user->factors()->create(['type' => 'totp', 'confirmed_at' => now(), 'secret' => app('pragmarx.google2fa')->generateSecretKey()]);
        $this->begin();
        $this->complete()->assertOk()->assertJsonPath('data.two_factor_required', true)->assertJsonMissingPath('data.token');
        $this->assertSame(0, $user->tokens()->count());
    }
    public function test_retained_provider_credentials_are_encrypted_and_hidden(): void
    {
        config(['user-authentication.whilesmart.retain_tokens' => true, 'app.key' => 'base64:'.base64_encode(random_bytes(32))]);
        $this->app->forgetInstance('encrypter');
        $this->begin();
        $this->complete()->assertOk();
        $identity = WhilesmartIdentity::first();
        $this->assertSame('test-access-token', $identity->credentials['access_token']);
        $this->assertStringNotContainsString('test-access-token', $identity->getRawOriginal('credentials'));
        $this->assertArrayNotHasKey('credentials', $identity->toArray());
    }

    public function test_user_info_subject_must_match_the_signed_identity(): void
    {
        $this->begin();
        $this->contract['userinfo']['sub'] = 'different-subject';
        $this->complete()->assertStatus(400);
        $this->assertDatabaseCount('whilesmart_identities', 0);
    }

}
