<?php

namespace Whilesmart\UserAuthentication\Services;

use Exception;
use Illuminate\Support\Str;
use Symfony\Component\Serializer\Exception\ExceptionInterface;
use Webauthn\AuthenticatorAssertionResponse;
use Webauthn\AuthenticatorAssertionResponseValidator;
use Webauthn\AuthenticatorAttestationResponse;
use Webauthn\AuthenticatorAttestationResponseValidator;
use Webauthn\CeremonyStep\CeremonyStepManagerFactory;
use Webauthn\CredentialRecord;
use Webauthn\Exception\InvalidDataException;
use Webauthn\PublicKeyCredential;
use Webauthn\PublicKeyCredentialCreationOptions;
use Webauthn\PublicKeyCredentialRequestOptions;
use Webauthn\PublicKeyCredentialRpEntity;
use Webauthn\PublicKeyCredentialUserEntity;
use Whilesmart\UserAuthentication\Models\Passkey;
use Whilesmart\UserAuthentication\Traits\Loggable;

class PasskeyService
{
    use Loggable;

    /**
     * @throws InvalidDataException
     */
    public function getLoginOptions(int $userId): PublicKeyCredentialRequestOptions
    {
        $allowedCredentials = Passkey::where('user_id', $userId)
            ->get()
            ->map(fn(Passkey $passkey) => $passkey->getCredential())
            ->map(fn(CredentialRecord $publicKeyCredentialSource) => $publicKeyCredentialSource->getPublicKeyCredentialDescriptor())
            ->all();

        return new PublicKeyCredentialRequestOptions(
            challenge: Str::random(),
            rpId: parse_url(config('app.url'), PHP_URL_HOST),
            allowCredentials: $allowedCredentials,
        );
    }

    /**
     * @throws InvalidDataException
     */
    public function getRegistrationOptions(string $userId, string $userEmail, string $displayName): PublicKeyCredentialCreationOptions
    {
        return new PublicKeyCredentialCreationOptions(
            rp: new PublicKeyCredentialRpEntity(
                name: config('app.name'),
                id: parse_url(config('user-authentication.passkey.domain'), PHP_URL_HOST),
            ),
            user: new PublicKeyCredentialUserEntity(
                name: $userEmail,
                id: $userId,
                displayName: $displayName,
            ),
            challenge: Str::random(),
        );
    }

    /**
     * @throws ExceptionInterface
     */
    public function verifyPasskey(array $passkey, string $options, string $host): Passkey
    {
        $publicKeyCredential = Passkey::webAuthnSerializer()->deserialize(
            json_encode($passkey),
            PublicKeyCredential::class,
            'json'
        );

        $publicKeyCredentialOptions = Passkey::webAuthnSerializer()->deserialize(
            $options,
            PublicKeyCredentialRequestOptions::class,
            'json'
        );
        if (!$publicKeyCredential->response instanceof AuthenticatorAssertionResponse) {
            throw new Exception(__('This passkey is not valid 2'), 400);
        }

        $validatedPasskey = Passkey::firstWhere('credential_id', $this->base64urlEncode($publicKeyCredential->rawId));

        if (!$validatedPasskey) {
            throw new Exception(__('This passkey is not valid'), 400);
        }

        try {
            $csmFactory = new CeremonyStepManagerFactory();
            $csmFactory->setAllowedOrigins(config('user-authentication.passkey.allowed_origins'));
            $publicKeyCredentialSource = AuthenticatorAssertionResponseValidator::create(
                $csmFactory->requestCeremony()
            )->check(
                credentialRecord: $validatedPasskey->getCredential(),
                authenticatorAssertionResponse: $publicKeyCredential->response,
                publicKeyCredentialRequestOptions: $publicKeyCredentialOptions,
                host: $host,
                userHandle: null,
            );
        } catch (\Throwable $e) {
            $this->error($e->getMessage());
            throw new Exception(__('This passkey is not valid'), 400);
        }

        $validatedPasskey->update(['data' => Passkey::webAuthnSerializer()
            ->serialize($publicKeyCredentialSource, 'json')]);
        return $validatedPasskey;
    }

    private function base64urlEncode(string $data): string
    {
        // 1. Run standard base64
        $b64 = base64_encode($data);

        // 2. Replace + with -, / with _, and remove = padding
        return rtrim(strtr($b64, '+/', '-_'), '=');
    }

    /**
     * @throws ExceptionInterface
     * @throws \Throwable
     * @throws Exception
     */
    public function getPublicKeyCredentialSource(array $passkey, string $options, $host): CredentialRecord
    {

        $publicKeyCredential = Passkey::webAuthnSerializer()->deserialize(
            json_encode($passkey),
            PublicKeyCredential::class,
            'json'
        );

        $publicKeyCredentialOptions = Passkey::webAuthnSerializer()->deserialize(
            $options,
            PublicKeyCredentialCreationOptions::class,
            'json'
        );


        if (!$publicKeyCredential->response instanceof AuthenticatorAttestationResponse) {
            throw new Exception(__('This passkey is not valid 2'), 400);
        }


        $csmFactory = new CeremonyStepManagerFactory();
        $csmFactory->setAllowedOrigins(config('user-authentication.passkey.allowed_origins'));
        $publicKeyCredentialSource = AuthenticatorAttestationResponseValidator::create(
            $csmFactory->creationCeremony(),
        )->check(
            authenticatorAttestationResponse: $publicKeyCredential->response,
            publicKeyCredentialCreationOptions: $publicKeyCredentialOptions,
            host: $host,
        );

        return $publicKeyCredentialSource;
    }

    public function getCredentialId(CredentialRecord $publicKeyCredentialSource): string
    {
        return $this->base64urlEncode($publicKeyCredentialSource->publicKeyCredentialId);
    }
}
