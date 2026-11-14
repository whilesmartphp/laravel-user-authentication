<?php

namespace Whilesmart\UserAuthentication\Services;

use Exception;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;
use InvalidArgumentException;
use LogicException;
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
use Webauthn\PublicKeyCredentialDescriptor;
use Webauthn\PublicKeyCredentialRequestOptions;
use Webauthn\PublicKeyCredentialRpEntity;
use Webauthn\PublicKeyCredentialUserEntity;
use Webauthn\SimpleFakeCredentialGenerator;
use Whilesmart\UserAuthentication\Models\Passkey;
use Whilesmart\UserAuthentication\Traits\Loggable;

class PasskeyService
{
    use Loggable;

    public function getRpId(): string
    {
        $domain = config('user-authentication.passkey.domain');
        if (!is_string($domain) || $domain === '') {
            throw new InvalidArgumentException('Passkey domain must be configured');
        }
        $host = parse_url($domain, PHP_URL_HOST);
        if (is_string($host) && $host !== '') {
            return $host;
        }
        $host = parse_url('https://' . $domain, PHP_URL_HOST);
        if (!is_string($host) || $host === '') {
            throw new InvalidArgumentException('Invalid passkey domain');
        }
        return $host;
    }

    private function userVerification(): string
    {
        $policy = config('user-authentication.passkey.user_verification');
        if (!in_array($policy, ['required', 'preferred', 'discouraged'], true)) {
            throw new InvalidArgumentException('Invalid passkey user verification policy');
        }
        return $policy;
    }

    /**
     * @throws InvalidDataException
     */
    public function getLoginOptions(
        int|string|null $userId = null,
        ?string $email = null,
        ?Request $request = null
    ): PublicKeyCredentialRequestOptions {
        $user = null;
        if ($userId !== null) {
            $User = config('user-authentication.user_model');
            $user = $User::find($userId);
            $allowedCredentials = $user
                ? $user->passkeys
                    ->map(fn (Passkey $passkey) => $passkey->getCredential())
                    ->map(fn (CredentialRecord $source) => $source->getPublicKeyCredentialDescriptor())
                    ->all()
                : [];
        }

        if ($email !== null) {
            $key = config('app.key');
            if (!is_string($key) || $key === '') {
                throw new LogicException('An application key is required for passkey login');
            }
            $generator = new SimpleFakeCredentialGenerator(secret: hash_hmac('sha256', 'passkey-options', $key));
            $allowedCredentials = array_map(
                fn ($credential) => new PublicKeyCredentialDescriptor('public-key', $credential->id),
                $allowedCredentials ?? []
            );
            $credentialCount = count($allowedCredentials);
            for ($index = 0; $index < config('user-authentication.passkey.max_credentials', 10); $index++) {
                $fake = $generator->generate($request ?? new Request(), $email . ':' . $index)[0];
                if ($index >= $credentialCount) {
                    $allowedCredentials[] = new PublicKeyCredentialDescriptor('public-key', $fake->id);
                }
            }
        }

        return new PublicKeyCredentialRequestOptions(
            challenge: random_bytes(32),
            rpId: $this->getRpId(),
            allowCredentials: $allowedCredentials ?? [],
            userVerification: $this->userVerification(),
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
            challenge: random_bytes(32),
            authenticatorSelection: new AuthenticatorSelectionCriteria(
                residentKey: config('user-authentication.passkey.resident_keys')
                    ? AuthenticatorSelectionCriteria::RESIDENT_KEY_REQUIREMENT_REQUIRED
                    : AuthenticatorSelectionCriteria::RESIDENT_KEY_REQUIREMENT_NO_PREFERENCE,
                userVerification: $this->userVerification(),
            ),
        );
    }

    /**
     * @throws ExceptionInterface
     */
    public function verifyPasskey(array $passkey, string $options, ?string $userHandle = null): Passkey
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
            throw new Exception(__('This passkey is not valid'), 400);
        }

        return DB::transaction(function () use ($publicKeyCredential, $publicKeyCredentialOptions, $userHandle) {
            $validatedPasskey = Passkey::where('credential_id', $this->base64urlEncode($publicKeyCredential->rawId))
                ->lockForUpdate()->first();

            if (!$validatedPasskey) {
                throw new Exception(__('This passkey is not valid'), 400);
            }

            try {
                $csmFactory = new CeremonyStepManagerFactory();
                $csmFactory->setAllowedOrigins(config('user-authentication.passkey.allowed_origins'));
                $csmFactory->setAttestationStatementSupportManager(Passkey::attestationStatementSupportManager());
                $publicKeyCredentialSource = AuthenticatorAssertionResponseValidator::create(
                    $csmFactory->requestCeremony()
                )->check(
                    credentialRecord: $validatedPasskey->getCredential(),
                    authenticatorAssertionResponse: $publicKeyCredential->response,
                    publicKeyCredentialRequestOptions: $publicKeyCredentialOptions,
                    host: $this->getRpId(),
                    userHandle: $userHandle,
                );
            } catch (\Throwable $e) {
                $this->error($e->getMessage());
                throw new Exception($e->getMessage(), 400);
            }

            $validatedPasskey->update(['data' => Passkey::webAuthnSerializer()
                ->serialize($publicKeyCredentialSource, 'json')]);
            return $validatedPasskey;
        });
    }

    private function base64urlEncode(string $data): string
    {
        $b64 = base64_encode($data);

        return rtrim(strtr($b64, '+/', '-_'), '=');
    }

    /**
     * @throws ExceptionInterface
     * @throws \Throwable
     * @throws Exception
     */
    public function getPublicKeyCredentialSource(array $passkey, string $options): CredentialRecord
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
            throw new Exception(__('This passkey is not valid'), 400);
        }


        try {
            $csmFactory = new CeremonyStepManagerFactory();
            $csmFactory->setAllowedOrigins(config('user-authentication.passkey.allowed_origins'));
            $csmFactory->setAttestationStatementSupportManager(Passkey::attestationStatementSupportManager());
            $publicKeyCredentialSource = AuthenticatorAttestationResponseValidator::create(
                $csmFactory->creationCeremony(),
            )->check(
                authenticatorAttestationResponse: $publicKeyCredential->response,
                publicKeyCredentialCreationOptions: $publicKeyCredentialOptions,
                host: $this->getRpId(),
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
