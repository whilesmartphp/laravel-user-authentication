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

        $service = $this->app->instance(PasskeyService::class, new class () extends PasskeyService {
            public function getPublicKeyCredentialSource(array $passkey, string $options, $host): CredentialRecord
            {
                return new CredentialRecord(
                    publicKeyCredentialId: base64_decode('MTIzNA=='),
                    type: 'public-key',
                    transports: ['internal'],
                    attestationType: 'none',
                    trustPath: new EmptyTrustPath(),
                    aaguid: Uuid::fromString('00000000-0000-0000-0000-000000000000'),
                    credentialPublicKey: 'public-key',
                    userHandle: (string) 1,
                    counter: 0,
                );
            }
        });

        $sessionId = 'reg_' . uniqid();
        Cache::put($sessionId, json_encode(['challenge' => 'test']), now()->addMinutes(5));

        $response = $this->postJson('/api/passkeys/register', [
            'name' => 'Test Passkey',
            'session_id' => $sessionId,
            'passkey' => [
                'id' => 'dGVzdA',
                'rawId' => 'dGVzdA',
                'type' => 'public-key',
                'response' => [
                    'clientDataJSON' => 'eyJ0ZXN0IjogdHJ1ZX0',
                    'attestationObject' => 'o2NmbXRkbm9uZQ',
                    'transports' => ['internal'],
                ],
            ],
        ], ['Authorization' => 'Bearer ' . $token]);

        $response->assertStatus(200)
            ->assertJsonPath('success', true);

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

        $response->assertStatus(400)
            ->assertJsonPath('success', false);
    }

    public function test_user_can_get_email_based_login_options()
    {
        $user = $this->createUser();
        $passkey = $this->createPasskey($user);

        $response = $this->postJson('/api/passkeys/login/options', [
            'email' => $user->email,
        ]);

        $response->assertStatus(200)
            ->assertJsonStructure(['success', 'data' => ['options', 'session_id']]);

        $options = json_decode($response->json('data.options'), true);
        $this->assertCount(1, $options['allowCredentials']);
    }

    public function test_unknown_email_returns_user_not_found()
    {
        $response = $this->postJson('/api/passkeys/login/options', [
            'email' => 'missing@example.com',
        ]);

        $response->assertStatus(400)
            ->assertJsonPath('success', false);
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

        $this->app->instance(PasskeyService::class, new class ($passkey) extends PasskeyService {
            public function __construct(private Passkey $passkey)
            {
            }

            public function verifyPasskey(array $passkey, string $options, string $host): Passkey
            {
                return $this->passkey;
            }
        });

        $sessionId = 'log_' . uniqid();
        Cache::put($sessionId, json_encode(['challenge' => 'test']), now()->addMinutes(5));

        $response = $this->postJson('/api/passkeys/login', [
            'session_id' => $sessionId,
            'passkey' => [
                'id' => 'dGVzdA',
                'rawId' => 'dGVzdA',
                'type' => 'public-key',
                'response' => [
                    'clientDataJSON' => 'eyJ0ZXN0IjogdHJ1ZX0',
                    'authenticatorData' => 'eyJ0ZXN0IjogdHJ1ZX0',
                    'signature' => 'c2ln',
                    'userHandle' => 'MQ==',
                ],
            ],
        ]);

        $response->assertStatus(200)
            ->assertJsonStructure(['success', 'data' => ['token', 'user']]);
    }

    public function test_passkey_login_rejects_invalid_session()
    {
        $response = $this->postJson('/api/passkeys/login', [
            'session_id' => 'log_invalid',
            'passkey' => ['id' => 'x'],
        ]);

        $response->assertStatus(400)
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
            ->assertJsonCount(1, 'data.passkeys');
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

    private function createPasskey($user): Passkey
    {
        $record = new CredentialRecord(
            publicKeyCredentialId: 'test-id',
            type: 'public-key',
            transports: ['internal'],
            attestationType: 'none',
            trustPath: new EmptyTrustPath(),
            aaguid: Uuid::fromString('00000000-0000-0000-0000-000000000000'),
            credentialPublicKey: 'key',
            userHandle: (string) $user->id,
            counter: 0,
        );

        $data = Passkey::webAuthnSerializer()->serialize($record, 'json');

        return $user->passkeys()->create([
            'name' => 'Test Passkey',
            'credential_id' => 'dGVzdA',
            'data' => $data,
        ]);
    }
}
