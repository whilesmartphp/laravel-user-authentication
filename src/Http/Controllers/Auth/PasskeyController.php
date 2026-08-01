<?php

namespace Whilesmart\UserAuthentication\Http\Controllers\Auth;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Validator;
use Illuminate\Support\Str;
use Illuminate\Validation\ValidationException;
use Symfony\Component\Serializer\Exception\ExceptionInterface;
use Webauthn\Exception\InvalidDataException;
use Whilesmart\UserAuthentication\Enums\HookAction;
use Whilesmart\UserAuthentication\Events\UserLoggedInEvent;
use Whilesmart\UserAuthentication\Http\Controllers\Controller;
use Whilesmart\UserAuthentication\Models\Passkey;
use Whilesmart\UserAuthentication\Rules\EmailDomainRestriction;
use Whilesmart\UserAuthentication\Services\PasskeyService;
use Whilesmart\UserAuthentication\Traits\ApiResponse;
use Whilesmart\UserAuthentication\Traits\HasMiddlewareHooks;
use Whilesmart\UserAuthentication\Traits\Loggable;

class PasskeyController extends Controller
{
    use ApiResponse;
    use HasMiddlewareHooks;
    use Loggable;


    private PasskeyService $passkeyService;

    public function __construct(PasskeyService $passkeyService)
    {
        $this->passkeyService = $passkeyService;
    }

    /**
     * @throws ExceptionInterface
     * @throws InvalidDataException
     */
    public function registerOptions(Request $request): JsonResponse
    {
        $request = $this->runBeforeHooks($request, HookAction::PASSKEY_REGISTER_OPTIONS);

        $validationRules = [
            'name' => ['required', 'string', 'max:255']
        ];
        $validator = Validator::make($request->all(), $validationRules);

        if ($validator->fails()) {
            $response = $this->failure('Validation failed.', 422, [$validator->errors()]);
            return $this->runAfterHooks($request, $response, HookAction::PASSKEY_REGISTER_OPTIONS);
        }

        $user = $request->user();
        $name = trim(($user->first_name ?? '') . ' ' . ($user->last_name ?? ''));
        $displayName = $name ?: $user->email;
        $options = $this->passkeyService->getRegistrationOptions((string) $user->id, $user->email, $displayName);

        $options = Passkey::webAuthnSerializer()->serialize($options, 'json');
        $sessionId = "reg_" . Str::uuid()->toString();
        Cache::add($sessionId, $options, now()->addMinutes(config('user-authentication.passkey.session_lifetime')));

        $response = $this->success(['options' => $options, 'session_id' => $sessionId]);
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
                'sometimes',
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

        $userId = null;
        if ($request->has('email')) {
            $User = config('user-authentication.user_model');
            $user = $User::where('email', $request->email)->first();
            if (!$user) {
                $response = $this->failure(__('Invalid credentials'));
                return $this->runAfterHooks($request, $response, HookAction::PASSKEY_LOGIN_OPTIONS);
            }
            $userId = $user->id;
        }

        $options = $this->passkeyService->getLoginOptions($userId);
        $options = Passkey::webAuthnSerializer()->serialize($options, 'json');

        $sessionId = "log_" . Str::uuid()->toString();
        Cache::add(
            $sessionId,
            json_encode([
                'options' => $options,
                'userHandle' => $userId !== null ? (string) $userId : null,
            ]),
            now()->addMinutes(config('user-authentication.passkey.session_lifetime'))
        );

        $response = $this->success(['options' => $options, 'session_id' => $sessionId]);
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
            'session_id' => ['required', 'string']
        ];

        $validator = Validator::make($request->all(), $validationRules);

        if ($validator->fails()) {
            $response = $this->failure('Validation failed.', 422, [$validator->errors()]);

            return $this->runAfterHooks($request, $response, HookAction::PASSKEY_LOGIN);
        }

        $data = $request->only(['passkey', 'session_id']);

        $cached = Cache::pull($data['session_id']);
        if (is_null($cached)) {
            $response = $this->failure(__('Invalid session id'));
            return $this->runAfterHooks($request, $response, HookAction::PASSKEY_LOGIN);
        }
        $cached = json_decode($cached, true);
        $options = $cached['options'] ?? $cached;
        $userHandle = $cached['userHandle'] ?? null;

        try {
            $passkey = $this->passkeyService->verifyPasskey(
                $data['passkey'],
                $options,
                $request->getHost(),
                $userHandle
            );
        } catch (\Exception $e) {
            $response = $this->failure($e->getMessage(), 400);
            return $this->runAfterHooks($request, $response, HookAction::PASSKEY_LOGIN);
        }

        $user = $passkey->keyable;

        if (!$user instanceof Authenticatable) {
            $response = $this->failure('Invalid credentials', 401);

            return $this->runAfterHooks($request, $response, HookAction::PASSKEY_LOGIN);
        }
        UserLoggedInEvent::dispatch($user);

        $response = $this->success([
            'token' => $user->createToken('auth-token')->plainTextToken,
            'token_type' => 'Bearer',
            'user' => $user,
        ], 'User successfully logged in', 200);

        return $this->runAfterHooks($request, $response, HookAction::PASSKEY_LOGIN);
    }

    /**
     * Store a newly created resource in storage.
     * @throws ExceptionInterface
     * @throws \Throwable
     */
    public function register(Request $request): JsonResponse
    {
        $request = $this->runBeforeHooks($request, HookAction::PASSKEY_REGISTER);

        $validationRules = [
            'name' => ['required', 'string', 'max:255'],
            'session_id' => ['required', 'string'],
            'passkey' => ['required', 'array'],
        ];

        $validator = Validator::make($request->all(), $validationRules);

        if ($validator->fails()) {
            $response = $this->failure('Validation failed.', 422, [$validator->errors()]);

            return $this->runAfterHooks($request, $response, HookAction::PASSKEY_REGISTER);
        }
        $data = $request->all();

        $options = Cache::pull($data['session_id']);
        if (is_null($options)) {
            $response = $this->failure(__('Invalid session id'));
            return $this->runAfterHooks($request, $response, HookAction::PASSKEY_REGISTER);
        }

        try {
            $publicKeyCredentialSource = $this->passkeyService->getPublicKeyCredentialSource(
                $data['passkey'],
                $options,
                $request->getHost()
            );
        } catch (\Exception $e) {
            $response = $this->failure($e->getMessage(), 400);
            return $this->runAfterHooks($request, $response, HookAction::PASSKEY_REGISTER);
        }

        $user = $request->user();
        $exists = $user->passkeys()
            ->where('credential_id', $this->passkeyService->getCredentialId($publicKeyCredentialSource))
            ->exists();
        if ($exists) {
            $response = $this->failure(__('This passkey already exists'));
            return $this->runAfterHooks($request, $response, HookAction::PASSKEY_REGISTER);
        }

        $request->user()->passkeys()->create([
            'name' => $data['name'],
            'credential_id' => $this->passkeyService->getCredentialId($publicKeyCredentialSource),
            'data' => Passkey::webAuthnSerializer()->serialize($publicKeyCredentialSource, 'json'),
        ]);
        $response = $this->success(message: __('Passkey created'));
        return $this->runAfterHooks($request, $response, HookAction::PASSKEY_REGISTER);
    }

    public function index(Request $request): JsonResponse
    {
        $request = $this->runBeforeHooks($request, HookAction::PASSKEY_INDEX);

        $passkeys = $request->user()->passkeys
            ->makeHidden(['data', 'keyable_type', 'keyable_id']);
        $response = $this->success(data: ['passkeys' => $passkeys], message: __('Passkeys retrieved'));
        return $this->runAfterHooks($request, $response, HookAction::PASSKEY_INDEX);
    }

    /**
     * Remove the specified resource from storage.
     */
    public function destroy(Request $request, $passkeyId): JsonResponse
    {
        $request = $this->runBeforeHooks($request, HookAction::PASSKEY_DELETE);

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
