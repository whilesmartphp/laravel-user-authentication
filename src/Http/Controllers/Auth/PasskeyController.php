<?php

namespace Whilesmart\UserAuthentication\Http\Controllers\Auth;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Database\UniqueConstraintViolationException;
use Illuminate\Support\Facades\DB;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Validator;
use Illuminate\Support\Str;
use Illuminate\Validation\ValidationException;
use Symfony\Component\Serializer\Exception\ExceptionInterface;
use Webauthn\Exception\InvalidDataException;
use Whilesmart\UserAuthentication\Enums\HookAction;
use Whilesmart\UserAuthentication\Http\Controllers\Controller;
use Whilesmart\UserAuthentication\Models\Passkey;
use Whilesmart\UserAuthentication\Rules\EmailDomainRestriction;
use Whilesmart\UserAuthentication\Services\PasskeyService;
use Whilesmart\UserAuthentication\Traits\ApiResponse;
use Whilesmart\UserAuthentication\Traits\HasMiddlewareHooks;
use Whilesmart\UserAuthentication\Traits\Loggable;
use Whilesmart\UserAuthentication\Traits\SignsInUsers;

class PasskeyController extends Controller
{
    use ApiResponse;
    use HasMiddlewareHooks;
    use Loggable;
    use SignsInUsers;


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
        $sessionId = $this->storeCeremony('register', $options, (string) $user->id);

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
            if ($user) {
                $userId = $user->id;
            }
        }

        $options = $this->passkeyService->getLoginOptions($userId, $request->input('email'), $request);
        $options = Passkey::webAuthnSerializer()->serialize($options, 'json');

        $sessionId = $this->storeCeremony('login', $options, $userId !== null ? (string) $userId : null);

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
            'session_id' => ['required', 'string', 'uuid']
        ];

        $validator = Validator::make($request->all(), $validationRules);

        if ($validator->fails()) {
            $response = $this->failure('Validation failed.', 422, [$validator->errors()]);

            return $this->runAfterHooks($request, $response, HookAction::PASSKEY_LOGIN);
        }

        $data = $request->only(['passkey', 'session_id']);

        $cached = $this->consumeCeremony('login', $data['session_id']);
        if ($cached === null) {
            $response = $this->failure(__('Invalid session id'));
            return $this->runAfterHooks($request, $response, HookAction::PASSKEY_LOGIN);
        }
        $options = $cached['options'];
        $userHandle = $cached['userHandle'];

        try {
            $passkey = $this->passkeyService->verifyPasskey(
                $data['passkey'],
                $options,
                $userHandle
            );
        } catch (\Exception $e) {
            report($e);
            $response = $this->failure(__('This passkey is not valid'), 400);
            return $this->runAfterHooks($request, $response, HookAction::PASSKEY_LOGIN);
        }

        $user = $passkey->keyable;

        if (!$user instanceof Authenticatable) {
            $response = $this->failure('Invalid credentials', 401);

            return $this->runAfterHooks($request, $response, HookAction::PASSKEY_LOGIN);
        }
        return $this->signIn($request, $user, HookAction::PASSKEY_LOGIN);
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
            'session_id' => ['required', 'string', 'uuid'],
            'passkey' => ['required', 'array'],
        ];

        $validator = Validator::make($request->all(), $validationRules);

        if ($validator->fails()) {
            $response = $this->failure('Validation failed.', 422, [$validator->errors()]);

            return $this->runAfterHooks($request, $response, HookAction::PASSKEY_REGISTER);
        }
        $data = $request->all();

        $cached = $this->consumeCeremony('register', $data['session_id']);
        if ($cached === null || $cached['owner'] !== (string) $request->user()->id) {
            $response = $this->failure(__('Invalid session id'));
            return $this->runAfterHooks($request, $response, HookAction::PASSKEY_REGISTER);
        }

        try {
            $publicKeyCredentialSource = $this->passkeyService->getPublicKeyCredentialSource(
                $data['passkey'],
                $cached['options']
            );
        } catch (\Exception $e) {
            report($e);
            $response = $this->failure(__('This passkey is not valid'), 400);
            return $this->runAfterHooks($request, $response, HookAction::PASSKEY_REGISTER);
        }

        $user = $request->user();
        if ($publicKeyCredentialSource->userHandle !== (string) $user->id) {
            $response = $this->failure(__('This passkey is not valid'), 400);
            return $this->runAfterHooks($request, $response, HookAction::PASSKEY_REGISTER);
        }

        try {
            $created = DB::transaction(function () use ($user, $data, $publicKeyCredentialSource) {
                $user->newQuery()->whereKey($user->id)->lockForUpdate()->firstOrFail();
                if ($user->passkeys()->count() >= config('user-authentication.passkey.max_credentials', 10)) {
                    return false;
                }
                $user->passkeys()->create([
                    'name' => $data['name'],
                    'credential_id' => $this->passkeyService->getCredentialId($publicKeyCredentialSource),
                    'data' => Passkey::webAuthnSerializer()->serialize($publicKeyCredentialSource, 'json'),
                ]);
                return true;
            });
        } catch (UniqueConstraintViolationException $e) {
            $response = $this->failure(__('This passkey already exists'), 409);
            return $this->runAfterHooks($request, $response, HookAction::PASSKEY_REGISTER);
        }
        if (!$created) {
            $response = $this->failure(__('Passkey limit reached'), 409);
            return $this->runAfterHooks($request, $response, HookAction::PASSKEY_REGISTER);
        }
        $response = $this->success(message: __('Passkey created'));
        return $this->runAfterHooks($request, $response, HookAction::PASSKEY_REGISTER);
    }

    private function storeCeremony(string $purpose, string $options, ?string $userId): string
    {
        $sessionId = Str::uuid()->toString();
        Cache::put('passkey:' . $purpose . ':' . $sessionId, [
            'purpose' => $purpose,
            'owner' => $purpose === 'register' ? $userId : null,
            'options' => $options,
            'userHandle' => $purpose === 'login' ? $userId : null,
        ], now()->addMinutes(config('user-authentication.passkey.session_lifetime')));
        return $sessionId;
    }

    private function consumeCeremony(string $purpose, string $sessionId): ?array
    {
        $key = 'passkey:' . $purpose . ':' . $sessionId;
        $cached = Cache::lock($key . ':lock', 10)->get(function () use ($key, $purpose) {
            $ceremony = Cache::get($key);
            if (!is_array($ceremony) || ($ceremony['purpose'] ?? null) !== $purpose) {
                return null;
            }
            return Cache::forget($key) ? $ceremony : null;
        });
        return is_array($cached) ? $cached : null;
    }

    public function index(Request $request): JsonResponse
    {
        $request = $this->runBeforeHooks($request, HookAction::PASSKEY_INDEX);

        $passkeys = $request->user()->passkeys()->get()
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
