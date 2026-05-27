<?php

namespace Whilesmart\UserAuthentication\Http\Controllers\Auth;

use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Validator;
use Illuminate\Support\Str;
use Illuminate\Validation\ValidationException;
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
use Whilesmart\UserAuthentication\Enums\HookAction;
use Whilesmart\UserAuthentication\Events\UserLoggedInEvent;
use Whilesmart\UserAuthentication\Http\Controllers\Controller;
use Whilesmart\UserAuthentication\Models\Passkey;
use Whilesmart\UserAuthentication\Rules\EmailDomainRestriction;
use Whilesmart\UserAuthentication\Traits\ApiResponse;
use Whilesmart\UserAuthentication\Traits\HasMiddlewareHooks;
use Whilesmart\UserAuthentication\Traits\Loggable;

class PasskeyController extends Controller
{
    use ApiResponse;
    use HasMiddlewareHooks;
    use Loggable;


    /**
     * @throws ExceptionInterface
     * @throws InvalidDataException
     */
    public function registerOptions(Request $request): JsonResponse
    {
        $request = $this->runBeforeHooks($request, HookAction::PASSKEY_LOGIN_OPTIONS);

        $validationRules = [
            'name' => ['required', 'string', 'max:255']
        ];
        $validator = Validator::make($request->all(), $validationRules);

        if ($validator->fails()) {
            $response = $this->failure('Validation failed.', 422, [$validator->errors()]);
            return $this->runAfterHooks($request, $response, HookAction::PASSKEY_REGISTER_OPTIONS);
        }
        $options = new PublicKeyCredentialCreationOptions(
            rp: new PublicKeyCredentialRpEntity(
                name: config('app.name'),
                id: parse_url(config('user-authentication.passkey.domain'), PHP_URL_HOST),
            ),
            user: new PublicKeyCredentialUserEntity(
                name: $request->user()->email,
                id: $request->user()->id,
                displayName: $request->user()->name,
            ),
            challenge: Str::random(),
        );

        $response = $this->success(['options' => $options]);
        return $this->runAfterHooks($request, $response, HookAction::PASSKEY_REGISTER_OPTIONS);
    }

    /**
     * @throws InvalidDataException
     * @throws ExceptionInterface
     */
    public function loginOptions(Request $request): JsonResponse
    {
        $request = $this->runBeforeHooks($request, HookAction::PASSKEY_LOGIN_OPTIONS);

        $validationRules = [
            'email' => [
                'required',
                'string',
                'email',
                'max:255',
                new EmailDomainRestriction(),
            ],
        ];
        $validator = Validator::make($request->all(), $validationRules);

        if ($validator->fails()) {
            $response = $this->failure('Validation failed.', 422, [$validator->errors()]);
            return $this->runAfterHooks($request, $response, HookAction::PASSKEY_LOGIN_OPTIONS);
        }

        $User = config('user-authentication.user_model');
        $user = $User::where('email', $request->email)->first();
        if (!$user) {
            $response = $this->failure(__('User not found'));
            return $this->runAfterHooks($request, $response, HookAction::PASSKEY_LOGIN_OPTIONS);
        }

        $allowedCredentials = $user->passkeys()
            ->get()
            ->map(fn(Passkey $passkey) => $passkey->getCredential())
            ->map(fn(CredentialRecord $publicKeyCredentialSource) => $publicKeyCredentialSource->getPublicKeyCredentialDescriptor())
            ->all();

        $options = new PublicKeyCredentialRequestOptions(
            challenge: Str::random(),
            rpId: parse_url(config('user-authentication.passkey.domain'), PHP_URL_HOST),
            allowCredentials: $allowedCredentials,
        );

        $response = $this->success(['options' => Passkey::webAuthnSerializer()->serialize($options, 'json')]);
        return $this->runAfterHooks($request, $response, HookAction::PASSKEY_LOGIN_OPTIONS);
    }


    /**
     * @throws ValidationException
     * @throws ExceptionInterface
     */
    public function login(Request $request): JsonResponse
    {
        $request = $this->runBeforeHooks($request, HookAction::PASSKEY_LOGIN);

        $validationRules = [
            'passkey' => ['required', 'array'],
            'options' => ['required', 'array']
        ];

        $validator = Validator::make($request->all(), $validationRules);

        if ($validator->fails()) {
            $response = $this->failure('Validation failed.', 422, [$validator->errors()]);

            return $this->runAfterHooks($request, $response, HookAction::PASSKEY_LOGIN);
        }

        $data = $request->only(['passkey', 'options']);

        $publicKeyCredential = Passkey::webAuthnSerializer()->deserialize(
            json_encode($data['passkey']),
            PublicKeyCredential::class,
            'json'
        );

        $publicKeyCredentialOptions = Passkey::webAuthnSerializer()->deserialize(
            json_encode($data['options']),
            PublicKeyCredentialRequestOptions::class,
            'json'
        );
        if (!$publicKeyCredential->response instanceof AuthenticatorAssertionResponse) {
            // todo: unable to reproduce this particular case. Might not necessarily be an error
            $response = $this->failure(__('This passkey is not valid'));
            return $this->runAfterHooks($request, $response, HookAction::PASSKEY_LOGIN);

        }

        $passkey = Passkey::firstWhere('credential_id', $this->base64urlEncode($publicKeyCredential->rawId));

        if (!$passkey) {
            $response = $this->failure(__('This passkey is not valid'));
            return $this->runAfterHooks($request, $response, HookAction::PASSKEY_LOGIN);
        }

        try {
            $csmFactory = new CeremonyStepManagerFactory();
            $csmFactory->setAllowedOrigins(config('user-authentication.passkey.allowed_origins'));
            $publicKeyCredentialSource = AuthenticatorAssertionResponseValidator::create(
                $csmFactory->requestCeremony()
            )->check(
                credentialRecord: $passkey->getCredential(),
                authenticatorAssertionResponse: $publicKeyCredential->response,
                publicKeyCredentialRequestOptions: $publicKeyCredentialOptions,
                host: $request->getHost(),
                userHandle: null,
            );
        } catch (\Throwable $e) {
            $this->error($e->getMessage());
            $response = $this->failure(__('This passkey is not valid'));
            return $this->runAfterHooks($request, $response, HookAction::PASSKEY_LOGIN);
        }

        $passkey->update(['data' => Passkey::webAuthnSerializer()->serialize($publicKeyCredentialSource, 'json')]);

        $user = $passkey->keyable;

        if (!$user) {
            $response = $this->failure('Invalid credentials', 401);

            return $this->runAfterHooks($request, $response, HookAction::PASSKEY_LOGIN);
        }
        UserLoggedInEvent::dispatch($user);

        $response = $this->success([
            'token' => $user->createToken('auth-token')->plainTextToken,
            'token_type' => 'Bearer',
            'user' => auth()->user(),
        ], 'User successfully logged in', 200);

        return $this->runAfterHooks($request, $response, HookAction::PASSKEY_LOGIN);
    }

    private function base64urlEncode(string $data): string
    {
        // 1. Run standard base64
        $b64 = base64_encode($data);

        // 2. Replace + with -, / with _, and remove = padding
        return rtrim(strtr($b64, '+/', '-_'), '=');
    }

    /**
     * Store a newly created resource in storage.
     * @throws ExceptionInterface
     */
    public function register(Request $request): JsonResponse
    {
        $request = $this->runBeforeHooks($request, HookAction::PASSKEY_REGISTER);

        $validationRules = [
            'name' => ['required', 'string', 'max:255'],
            'options' => ['required', 'array'],
            'passkey' => ['required', 'array'],
        ];

        $validator = Validator::make($request->all(), $validationRules);

        if ($validator->fails()) {
            $response = $this->failure('Validation failed.', 422, [$validator->errors()]);

            return $this->runAfterHooks($request, $response, HookAction::PASSKEY_REGISTER);
        }
        $data = $request->all();

        $publicKeyCredential = Passkey::webAuthnSerializer()->deserialize(
            json_encode($data['passkey']),
            PublicKeyCredential::class,
            'json'
        );

        $publicKeyCredentialOptions = Passkey::webAuthnSerializer()->deserialize(
            json_encode($data['options']),
            PublicKeyCredentialCreationOptions::class,
            'json'
        );


        if (!$publicKeyCredential->response instanceof AuthenticatorAttestationResponse) {
            // todo: unable to reproduce this particular case. Might not necessarily be an error
            $response = $this->failure(__('This passkey is not valid'));
            return $this->runAfterHooks($request, $response, HookAction::PASSKEY_REGISTER);
        }

        try {
            $csmFactory = new CeremonyStepManagerFactory();
            $csmFactory->setAllowedOrigins(config('user-authentication.passkey.allowed_origins'));
            $publicKeyCredentialSource = AuthenticatorAttestationResponseValidator::create(
                $csmFactory->creationCeremony(),
            )->check(
                authenticatorAttestationResponse: $publicKeyCredential->response,
                publicKeyCredentialCreationOptions: $publicKeyCredentialOptions,
                host: $request->getHost(),
            );
        } catch (\Throwable $e) {
            $this->error($e->getMessage());
            $response = $this->failure(__('This passkey is not valid'));
            return $this->runAfterHooks($request, $response, HookAction::PASSKEY_REGISTER);
        }

        $user = $request->user();
        $exists = Passkey::where('credential_id', $this->base64urlEncode($publicKeyCredentialSource->publicKeyCredentialId))
            ->where('keyable_id', $user->id)
            ->where('keyable_type', config('user-authentication.user_model'))
            ->exists();
        if ($exists) {
            $response = $this->failure(__('This passkey already exists'));
            return $this->runAfterHooks($request, $response, HookAction::PASSKEY_REGISTER);
        }

        $request->user()->passkeys()->create([
            'name' => $data['name'],
            'credential_id' => $this->base64urlEncode($publicKeyCredentialSource->publicKeyCredentialId),
            'data' => Passkey::webAuthnSerializer()->serialize($publicKeyCredentialSource, 'json'),
        ]);
        $response = $this->success(message: __('Passkey created'));
        return $this->runAfterHooks($request, $response, HookAction::PASSKEY_REGISTER);

    }

    public function index(Request $request): JsonResponse
    {
        $passkeys = $request->user()->passkeys;
        $response = $this->success(data: ['passkeys' => $passkeys], message: __('Passkey created'));
        return $this->runAfterHooks($request, $response, HookAction::PASSKEY_INDEX);

    }

    /**
     * Remove the specified resource from storage.
     */
    public function destroy(Request $request, $passkeyId): JsonResponse
    {
        $passkey = $request->user()->passkeys()->find($passkeyId);
        if (!$passkey) {
            $response = $this->failure(__('Passkey not found'), 404);
            return $this->runAfterHooks($request, $response, HookAction::PASSKEY_DELETE);
        }
        $passkey->delete();
        $response = $this->success(statusCode: 204);
        return $this->runAfterHooks($request, $response, HookAction::PASSKEY_DELETE);
    }
}
