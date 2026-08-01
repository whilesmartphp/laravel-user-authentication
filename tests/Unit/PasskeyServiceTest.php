<?php

namespace Whilesmart\UserAuthentication\Tests\Unit;

use Symfony\Component\Uid\Uuid;
use Webauthn\CredentialRecord;
use Webauthn\TrustPath\EmptyTrustPath;
use Whilesmart\UserAuthentication\Models\Passkey;
use Whilesmart\UserAuthentication\Models\User;
use Whilesmart\UserAuthentication\Services\PasskeyService;
use Whilesmart\UserAuthentication\Tests\TestCase;

class PasskeyServiceTest extends TestCase
{
    public function test_get_registration_options_includes_resident_key_when_enabled()
    {
        config()->set('user-authentication.passkey.domain', 'https://app.example.com');
        config()->set('user-authentication.passkey.resident_keys', true);

        $service = new PasskeyService();
        $options = $service->getRegistrationOptions('1', 'user@example.com', 'User');

        $this->assertSame('app.example.com', $options->rp->id);
        $this->assertSame('required', $options->authenticatorSelection->residentKey);
    }

    public function test_get_registration_options_uses_no_preference_when_resident_keys_disabled()
    {
        config()->set('user-authentication.passkey.domain', 'https://app.example.com');
        config()->set('user-authentication.passkey.resident_keys', false);

        $service = new PasskeyService();
        $options = $service->getRegistrationOptions('1', 'user@example.com', 'User');

        $this->assertNull($options->authenticatorSelection->residentKey);
    }

    public function test_get_rp_id_handles_bare_hostname()
    {
        config()->set('user-authentication.passkey.domain', 'app.example.com');

        $service = new PasskeyService();
        $options = $service->getRegistrationOptions('1', 'user@example.com', 'User');

        $this->assertSame('app.example.com', $options->rp->id);
    }

    public function test_get_login_options_with_user_returns_credentials()
    {
        $user = $this->createUser();
        $this->createPasskey($user);

        config()->set('user-authentication.passkey.domain', 'https://app.example.com');

        $service = new PasskeyService();
        $options = $service->getLoginOptions($user->id);

        $this->assertSame('app.example.com', $options->rpId);
        $this->assertCount(1, $options->allowCredentials);
    }

    public function test_get_login_options_without_user_returns_empty_allow_credentials()
    {
        config()->set('user-authentication.passkey.domain', 'https://app.example.com');

        $service = new PasskeyService();
        $options = $service->getLoginOptions();

        $this->assertSame([], $options->allowCredentials);
    }

    public function test_get_credential_id_returns_base64url_encoded_id()
    {
        $service = new PasskeyService();
        $record = new CredentialRecord(
            publicKeyCredentialId: 'test-id',
            type: 'public-key',
            transports: [],
            attestationType: 'none',
            trustPath: new EmptyTrustPath(),
            aaguid: Uuid::fromString('00000000-0000-0000-0000-000000000000'),
            credentialPublicKey: 'key',
            userHandle: '1',
            counter: 0,
        );

        $this->assertSame('dGVzdC1pZA', $service->getCredentialId($record));
    }

    private function createPasskey(User $user): Passkey
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
            'credential_id' => 'dGVzdA-' . uniqid(),
            'data' => $data,
        ]);
    }
}
