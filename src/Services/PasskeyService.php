<?php

namespace Whilesmart\UserAuthentication\Services;

use Exception;
use Illuminate\Support\Str;
use Symfony\Component\Serializer\Exception\ExceptionInterface;
use Webauthn\AuthenticatorAssertionResponse;
use Webauthn\AuthenticatorAssertionResponseValidator;
use Webauthn\AuthenticatorAttestationResponse;
use Webauthn\AuthenticatorAttestationResponseValidator;
use Webauthn\AuthenticatorSelectionCriteria;
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

    private function getRpId(): ?string
    {
        $domain = config('user-authentication.passkey.domain');
        $host = parse_url($domain, PHP_URL_HOST);
        if ($host !== null) {
            return $host;
        }
        // If no scheme was provided, PHP's parse_url treats the value as a path.
        // Prepend a scheme so it can be parsed as a host.
        $host = parse_url('https://' . $domain, PHP_URL_HOST);
        return $host;
    }

    /**
     * @throws InvalidDataException
     */
    public function getLoginOptions(?int $userId = null): PublicKeyCredentialRequestOptions
    {
        if ($userId !== null) {
            $User = config('user-authentication.user_model');
            $allowedCredentials = Passkey::where('keyable_id', $userId)
                ->where('keyable_type', $User)
                ->get()
                ->map(fn (Passkey $passkey) => $passkey->getCredential())
                ->map(fn (CredentialRecord $source) => $source->getPublicKeyCredentialDescriptor())
                ->all();
        }

        return new PublicKeyCredentialRequestOptions(
            challenge: Str::random(),
            rpId: $this->getRpId(),
            allowCredentials: $allowedCredentials ?? [],
        );
    }

    /**
     * @throws InvalidDataException
     */
    public function getRegistrationOptions(
        string $userId,
        string $userEmail,
        string $displayName
    ): PublicKeyCredentialCreationOptions {
        return new PublicKeyCredentialCreationOptions(
            rp: new PublicKeyCredentialRpEntity(
                name: config('app.name'),
                id: $this->getRpId(),
            ),
            user: new PublicKeyCredentialUserEntity(
                name: $userEmail,
                id: $userId,
                displayName: $displayName,
            ),
            challenge: Str::random(),
            authenticatorSelection: new AuthenticatorSelectionCriteria(
                residentKey: config('user-authentication.passkey.resident_keys')
                    ? AuthenticatorSelectionCriteria::RESIDENT_KEY_REQUIREMENT_REQUIRED
                    : AuthenticatorSelectionCriteria::RESIDENT_KEY_REQUIREMENT_NO_PREFERENCE,
                userVerification: AuthenticatorSelectionCriteria::USER_VERIFICATION_REQUIREMENT_PREFERRED,
            ),
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
            throw new Exception($e->getMessage(), 400);
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


        try {
            $csmFactory = new CeremonyStepManagerFactory();
            $csmFactory->setAllowedOrigins(config('user-authentication.passkey.allowed_origins'));
            $publicKeyCredentialSource = AuthenticatorAttestationResponseValidator::create(
                $csmFactory->creationCeremony(),
            )->check(
                authenticatorAttestationResponse: $publicKeyCredential->response,
                publicKeyCredentialCreationOptions: $publicKeyCredentialOptions,
                host: $host,
            );
        } catch (\Throwable $e) {
            $this->error($e->getMessage());
            throw new Exception($e->getMessage(), 400);
        }

        return $publicKeyCredentialSource;
    }

    public function getCredentialId(CredentialRecord $publicKeyCredentialSource): string
    {
        return $this->base64urlEncode($publicKeyCredentialSource->publicKeyCredentialId);
    }
}
