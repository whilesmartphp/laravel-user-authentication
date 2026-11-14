<?php

namespace Whilesmart\UserAuthentication\Tests\Feature;

use Illuminate\Support\Facades\Cache;
use Symfony\Component\Uid\Uuid;
use Webauthn\CredentialRecord;
use Webauthn\TrustPath\EmptyTrustPath;
use Whilesmart\UserAuthentication\Models\Passkey;
use Whilesmart\UserAuthentication\Services\PasskeyService;
use Whilesmart\UserAuthentication\Tests\TestCase;

class PasskeyTest extends TestCase
{
    protected function setUp(): void
    {
        parent::setUp();

        config()->set('app.key', 'passkey-test-application-key');
        config()->set('user-authentication.passkey.domain', 'https://localhost');
        config()->set('user-authentication.passkey.allowed_origins', ['https://localhost']);
        config()->set('user-authentication.passkey.resident_keys', true);
    }

    public function test_authenticated_user_can_get_passkey_registration_options()
    {
        $user = $this->createUser();
        $token = $user->createToken('test')->plainTextToken;

        $response = $this->postJson('/api/passkeys/register/options', [
            'name' => 'Test Passkey',
        ], ['Authorization' => 'Bearer ' . $token]);

        $response->assertStatus(200)
            ->assertJsonStructure([
                'success',
                'data' => ['options', 'session_id'],
            ]);

        $options = json_decode($response->json('data.options'), true);
        $this->assertArrayHasKey('challenge', $options);
        $this->assertSame('localhost', $options['rp']['id']);
        $this->assertSame('John Doe', $options['user']['displayName']);
        $this->assertSame('required', $options['authenticatorSelection']['userVerification']);
        $this->assertSame(32, strlen(base64_decode(strtr($options['challenge'], '-_', '+/'))));
    }

    public function test_passkey_registration_fails_without_name()
    {
        $user = $this->createUser();
        $token = $user->createToken('test')->plainTextToken;

        $response = $this->postJson('/api/passkeys/register/options', [], [
            'Authorization' => 'Bearer ' . $token,
        ]);

        $response->assertStatus(422)
            ->assertJsonPath('success', false)
            ->assertJsonPath('errors.0.name', ['The name field is required.']);
    }

    public function test_authenticated_user_can_register_a_passkey()
    {
        $user = $this->createUser();
        $token = $user->createToken('test')->plainTextToken;

        $this->app->instance(PasskeyService::class, new class () extends PasskeyService {
            public function getPublicKeyCredentialSource(array $passkey, string $options): CredentialRecord
            {
                return new CredentialRecord(
                    publicKeyCredentialId: base64_decode('MTIzNA=='),
                    type: 'public-key',
                    transports: ['internal'],
                    attestationType: 'none',
                    trustPath: new EmptyTrustPath(),
                    aaguid: Uuid::fromString('00000000-0000-0000-0000-000000000000'),
                    credentialPublicKey: 'public-key',
                    userHandle: Passkey::webAuthnSerializer()->deserialize(
                        $options,
                        \Webauthn\PublicKeyCredentialCreationOptions::class,
                        'json'
                    )->user->id,
                    counter: 0,
                );
            }
        });

        $sessionId = $this->postJson(
            '/api/passkeys/register/options',
            ['name' => 'Test Passkey'],
            ['Authorization' => 'Bearer ' . $token]
        )->json('data.session_id');

        $response = $this->postJson('/api/passkeys/register', [
            'name' => 'Test Passkey',
            'session_id' => $sessionId,
            'passkey' => ['id' => 'stubbed'],
        ], ['Authorization' => 'Bearer ' . $token]);

        $response->assertStatus(200)
            ->assertJsonPath('success', true);

        $this->postJson('/api/passkeys/register', [
            'name' => 'Replay', 'session_id' => $sessionId, 'passkey' => ['id' => 'stubbed'],
        ], ['Authorization' => 'Bearer ' . $token])->assertStatus(400);

        $this->assertDatabaseHas('passkeys', [
            'keyable_id' => $user->id,
            'keyable_type' => get_class($user),
            'name' => 'Test Passkey',
        ]);
    }

    public function test_passkey_registration_rejects_invalid_session()
    {
        $user = $this->createUser();
        $token = $user->createToken('test')->plainTextToken;

        $response = $this->postJson('/api/passkeys/register', [
            'name' => 'Test Passkey',
            'session_id' => 'reg_invalid',
            'passkey' => ['id' => 'x'],
        ], ['Authorization' => 'Bearer ' . $token]);

        $response->assertStatus(422)
            ->assertJsonPath('success', false);
    }

    public function test_user_can_get_email_based_login_options()
    {
        $user = $this->createUser();
        $this->createPasskey($user);

        $response = $this->postJson('/api/passkeys/login/options', [
            'email' => $user->email,
        ]);

        $response->assertStatus(200)
            ->assertJsonStructure(['success', 'data' => ['options', 'session_id']]);

        $options = json_decode($response->json('data.options'), true);
        $this->assertCount(10, $options['allowCredentials']);
        $this->assertSame('required', $options['userVerification']);
    }

    public function test_unknown_email_returns_padded_allow_credentials()
    {
        $response = $this->postJson('/api/passkeys/login/options', [
            'email' => 'missing@example.com',
        ]);

        $response->assertStatus(200)
            ->assertJsonStructure(['success', 'data' => ['options', 'session_id']]);

        $options = json_decode($response->json('data.options'), true);
        $this->assertCount(10, $options['allowCredentials']);
    }

    public function test_passwordless_login_options_return_empty_allow_credentials()
    {
        $response = $this->postJson('/api/passkeys/login/options', []);

        $response->assertStatus(200)
            ->assertJsonStructure(['success', 'data' => ['options', 'session_id']]);

        $options = json_decode($response->json('data.options'), true);
        $this->assertSame([], $options['allowCredentials']);
    }

    public function test_user_can_login_with_passkey()
    {
        $user = $this->createUser();
        $passkey = $this->createPasskey($user);

        $service = new class () extends PasskeyService {
            public Passkey $passkey;

            public function verifyPasskey(array $passkey, string $options, ?string $userHandle = null): Passkey
            {
                return $this->passkey;
            }
        };
        $service->passkey = $passkey;

        $this->app->instance(PasskeyService::class, $service);

        $sessionId = $this->postJson('/api/passkeys/login/options', ['email' => $user->email])
            ->json('data.session_id');

        $response = $this->postJson('/api/passkeys/login', [
            'session_id' => $sessionId,
            'passkey' => ['id' => 'stubbed'],
        ]);

        $response->assertStatus(200)
            ->assertJsonStructure(['success', 'data' => ['token', 'user']]);

        $this->postJson('/api/passkeys/login', [
            'session_id' => $sessionId, 'passkey' => ['id' => 'stubbed'],
        ])->assertStatus(400);
    }

    public function test_passkey_login_rejects_invalid_session()
    {
        $response = $this->postJson('/api/passkeys/login', [
            'session_id' => 'log_invalid',
            'passkey' => ['id' => 'x'],
        ]);

        $response->assertStatus(422)
            ->assertJsonPath('success', false);
    }

    public function test_authenticated_user_can_list_passkeys()
    {
        $user = $this->createUser();
        $this->createPasskey($user);
        $token = $user->createToken('test')->plainTextToken;

        $response = $this->getJson('/api/passkeys', [
            'Authorization' => 'Bearer ' . $token,
        ]);

        $response->assertStatus(200)
            ->assertJsonCount(1, 'data.passkeys')
            ->assertJsonPath('data.passkeys.0.data', null)
            ->assertJsonPath('data.passkeys.0.keyable_type', null);
    }

    public function test_authenticated_user_can_delete_passkey()
    {
        $user = $this->createUser();
        $passkey = $this->createPasskey($user);
        $token = $user->createToken('test')->plainTextToken;

        $response = $this->deleteJson('/api/passkeys/' . $passkey->id, [], [
            'Authorization' => 'Bearer ' . $token,
        ]);

        $response->assertStatus(204);
        $this->assertDatabaseMissing('passkeys', ['id' => $passkey->id]);
    }

    public function test_deleting_unknown_passkey_returns_404()
    {
        $user = $this->createUser();
        $token = $user->createToken('test')->plainTextToken;

        $response = $this->deleteJson('/api/passkeys/99999', [], [
            'Authorization' => 'Bearer ' . $token,
        ]);

        $response->assertStatus(404);
    }

    public function test_expired_ceremonies_fail()
    {
        $user = $this->createUser();
        $this->actingAs($user, 'sanctum');
        $registration = $this->postJson('/api/passkeys/register/options', ['name' => 'Key'])
            ->json('data.session_id');
        $login = $this->postJson('/api/passkeys/login/options')->json('data.session_id');
        $this->travel(6)->minutes();
        $this->postJson('/api/passkeys/register', [
            'name' => 'Key', 'session_id' => $registration, 'passkey' => ['id' => 'unused'],
        ])->assertStatus(400);
        $this->postJson('/api/passkeys/login', [
            'session_id' => $login, 'passkey' => ['id' => 'unused'],
        ])->assertStatus(400);
    }

    public function test_registration_is_bound_to_the_user_who_requested_it()
    {
        $owner = $this->createUser();
        $other = $this->createUser();
        $this->actingAs($owner, 'sanctum');
        $session = $this->postJson('/api/passkeys/register/options', ['name' => 'Key'])
            ->json('data.session_id');
        $this->actingAs($other, 'sanctum');
        $this->postJson('/api/passkeys/register', [
            'name' => 'Key', 'session_id' => $session, 'passkey' => ['id' => 'unused'],
        ])->assertStatus(400)->assertJsonPath('success', false);
        $this->assertDatabaseCount('passkeys', 0);
    }

    public function test_ceremony_purposes_cannot_be_interchanged()
    {
        $this->actingAs($this->createUser(), 'sanctum');
        $registration = $this->postJson('/api/passkeys/register/options', ['name' => 'Key'])
            ->json('data.session_id');
        $login = $this->postJson('/api/passkeys/login/options')->json('data.session_id');
        $this->postJson('/api/passkeys/login', [
            'session_id' => $registration, 'passkey' => ['id' => 'unused'],
        ])->assertStatus(400);
        $this->postJson('/api/passkeys/register', [
            'name' => 'Key', 'session_id' => $login, 'passkey' => ['id' => 'unused'],
        ])->assertStatus(400);
        $this->assertTrue(Cache::has('passkey:register:' . $registration));
        $this->assertTrue(Cache::has('passkey:login:' . $login));
    }

    public function test_malformed_sessions_do_not_touch_unrelated_cache_entries()
    {
        Cache::put('unrelated', 'keep', 60);
        $this->actingAs($this->createUser(), 'sanctum');
        foreach (['register', 'login'] as $purpose) {
            $this->postJson('/api/passkeys/' . $purpose, [
                'name' => 'Key', 'session_id' => 'unrelated', 'passkey' => ['id' => 'unused'],
            ])->assertStatus(422);
        }
        $this->assertSame('keep', Cache::get('unrelated'));
    }

    public function test_email_options_hide_account_existence_and_credential_count()
    {
        config()->set('user-authentication.passkey.max_credentials', 3);
        $owner = $this->createUser();
        $empty = $this->createUser();
        $this->createPasskey($owner);
        $this->createPasskey($owner);
        $responses = [];
        foreach ([$owner->email, $empty->email, 'missing@example.com', 'missing@example.com'] as $email) {
            $response = $this->postJson('/api/passkeys/login/options', ['email' => $email]);
            $response->assertOk()->assertJsonStructure(['success', 'data' => ['options', 'session_id']]);
            $responses[] = json_decode($response->json('data.options'), true);
        }
        foreach ($responses as $options) {
            $this->assertSame(array_keys($responses[0]), array_keys($options));
            $this->assertCount(3, $options['allowCredentials']);
            foreach ($options['allowCredentials'] as $credential) {
                $this->assertSame(array_keys($responses[2]['allowCredentials'][0]), array_keys($credential));
            }
        }
        $this->assertSame($responses[2]['allowCredentials'], $responses[3]['allowCredentials']);
    }

    public function test_each_ceremony_endpoint_is_rate_limited_by_ip()
    {
        config()->set('user-authentication.passkey.rate_limits.ip', 2);
        config()->set('user-authentication.passkey.rate_limits.email', 100);
        $this->actingAs($this->createUser(), 'sanctum');
        foreach (['login/options', 'login', 'register/options', 'register'] as $path) {
            $this->postJson('/api/passkeys/' . $path);
            $this->postJson('/api/passkeys/' . $path);
            $this->postJson('/api/passkeys/' . $path)->assertStatus(429);
        }
    }

    public function test_email_rate_limit_applies_across_ips()
    {
        config()->set('user-authentication.passkey.rate_limits.ip', 100);
        config()->set('user-authentication.passkey.rate_limits.email', 2);
        foreach (['192.0.2.1', '192.0.2.2'] as $ip) {
            $this->withServerVariables(['REMOTE_ADDR' => $ip])->postJson(
                '/api/passkeys/login/options',
                ['email' => 'missing@example.com']
            )->assertOk();
        }
        $this->withServerVariables(['REMOTE_ADDR' => '192.0.2.3'])->postJson(
            '/api/passkeys/login/options',
            ['email' => 'missing@example.com']
        )->assertStatus(429);
    }

    public function test_duplicate_credential_for_another_user_returns_conflict()
    {
        $owner = $this->createUser();
        $existing = $this->createPasskey($owner);
        $user = $this->createUser();
        $this->actingAs($user, 'sanctum');
        $record = $existing->getCredential();
        $record->userHandle = (string) $user->id;
        $existing->update(['credential_id' => (new PasskeyService())->getCredentialId($record)]);
        $service = new class () extends PasskeyService {
            public CredentialRecord $record;

            public function getPublicKeyCredentialSource(array $passkey, string $options): CredentialRecord
            {
                return $this->record;
            }
        };
        $service->record = $record;
        $this->app->instance(PasskeyService::class, $service);
        $session = $this->postJson('/api/passkeys/register/options', ['name' => 'Key'])->json('data.session_id');
        $this->postJson('/api/passkeys/register', [
            'name' => 'Key', 'session_id' => $session, 'passkey' => ['id' => 'stubbed'],
        ])->assertStatus(409)->assertJsonPath('success', false);
        $this->assertDatabaseCount('passkeys', 1);
    }

    public function test_registration_respects_configured_credential_cap()
    {
        config()->set('user-authentication.passkey.max_credentials', 1);
        $user = $this->createUser();
        $existing = $this->createPasskey($user);
        $this->actingAs($user, 'sanctum');
        $record = $existing->getCredential();
        $record->userHandle = (string) $user->id;
        $existing->update(['credential_id' => (new PasskeyService())->getCredentialId($record)]);
        $service = new class () extends PasskeyService {
            public CredentialRecord $record;

            public function getPublicKeyCredentialSource(array $passkey, string $options): CredentialRecord
            {
                return $this->record;
            }
        };
        $service->record = $record;
        $this->app->instance(PasskeyService::class, $service);
        $session = $this->postJson('/api/passkeys/register/options', ['name' => 'Key'])->json('data.session_id');
        $this->postJson('/api/passkeys/register', [
            'name' => 'Key', 'session_id' => $session, 'passkey' => ['id' => 'stubbed'],
        ])->assertStatus(409)->assertJsonPath('message', 'Passkey limit reached');
        $this->assertDatabaseCount('passkeys', 1);
    }

    public function test_users_cannot_list_or_delete_other_users_passkeys()
    {
        $owner = $this->createUser();
        $passkey = $this->createPasskey($owner);
        $this->actingAs($this->createUser(), 'sanctum');
        $this->getJson('/api/passkeys')->assertOk()->assertJsonCount(0, 'data.passkeys');
        $this->deleteJson('/api/passkeys/' . $passkey->id)->assertStatus(404);
        $this->assertDatabaseHas('passkeys', ['id' => $passkey->id]);
    }

    public function test_busy_ceremony_lock_rejects_a_competing_request_without_consuming()
    {
        $session = $this->postJson('/api/passkeys/login/options')->json('data.session_id');
        $lock = Cache::lock('passkey:login:' . $session . ':lock', 10);
        $this->assertTrue($lock->get());
        try {
            $this->postJson('/api/passkeys/login', [
                'session_id' => $session, 'passkey' => ['id' => 'unused'],
            ])->assertStatus(400);
            $this->assertTrue(Cache::has('passkey:login:' . $session));
        } finally {
            $lock->release();
        }
    }

    public function test_user_verification_policy_is_configurable_for_both_ceremonies()
    {
        config()->set('user-authentication.passkey.user_verification', 'preferred');
        config()->set('user-authentication.passkey.domain', 'localhost');
        $this->actingAs($this->createUser(), 'sanctum');
        $registration = $this->postJson('/api/passkeys/register/options', ['name' => 'Key']);
        $registration->assertOk();
        $creation = json_decode($registration->json('data.options'), true);
        $this->assertSame('preferred', $creation['authenticatorSelection']['userVerification']);
        $this->assertSame('localhost', $creation['rp']['id']);
        $login = $this->postJson('/api/passkeys/login/options');
        $login->assertOk();
        $request = json_decode($login->json('data.options'), true);
        $this->assertSame('preferred', $request['userVerification']);
        $this->assertSame('localhost', $request['rpId']);
        $this->assertSame(32, strlen(base64_decode(strtr($request['challenge'], '-_', '+/'))));
    }

    public function test_registration_rejects_a_credential_with_another_user_handle()
    {
        $owner = $this->createUser();
        $existing = $this->createPasskey($owner);
        $this->actingAs($this->createUser(), 'sanctum');
        $service = new class () extends PasskeyService {
            public CredentialRecord $record;

            public function getPublicKeyCredentialSource(array $passkey, string $options): CredentialRecord
            {
                return $this->record;
            }
        };
        $service->record = $existing->getCredential();
        $this->app->instance(PasskeyService::class, $service);
        $session = $this->postJson('/api/passkeys/register/options', ['name' => 'Key'])->json('data.session_id');
        $this->postJson('/api/passkeys/register', [
            'name' => 'Key', 'session_id' => $session, 'passkey' => ['id' => 'stubbed'],
        ])->assertStatus(400);
        $this->assertDatabaseCount('passkeys', 1);
    }

}
