<?php

namespace Whilesmart\UserAuthentication\Http\Controllers\Auth;

use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Routing\Controller;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\RateLimiter;
use Illuminate\Support\Facades\Validator;
use Illuminate\Support\Str;
use Kreait\Firebase\Exception\Auth\FailedToVerifyToken;
use Kreait\Firebase\Exception\AuthException;
use Kreait\Firebase\Exception\FirebaseException;
use Kreait\Laravel\Firebase\Facades\Firebase;
use Laravel\Socialite\Facades\Socialite;
use Whilesmart\UserAuthentication\Enums\HookAction;
use Whilesmart\UserAuthentication\Events\UserLoggedInEvent;
use Whilesmart\UserAuthentication\Events\UserLoggedOutEvent;
use Whilesmart\UserAuthentication\Events\UserRegisteredEvent;
use Whilesmart\UserAuthentication\Events\VerificationCodeGeneratedEvent;
use Whilesmart\UserAuthentication\Models\OauthAccount;
use Whilesmart\UserAuthentication\Models\User;
use Whilesmart\UserAuthentication\Models\VerificationCode;
use Whilesmart\UserAuthentication\Services\SmartPingsVerificationService;
use Whilesmart\UserAuthentication\Traits\ApiResponse;
use Whilesmart\UserAuthentication\Traits\HasMiddlewareHooks;
use Whilesmart\UserAuthentication\Traits\Loggable;

class AuthController extends Controller
{
    use ApiResponse, HasMiddlewareHooks, Loggable;

    public function register(Request $request): JsonResponse
    {
        $request = $this->runBeforeHooks($request, HookAction::REGISTER);

        try {
            $validationRules = [
                'email' => 'required|string|email|max:255|unique:users',
                'first_name' => 'required|string|max:255',
                'last_name' => 'string|max:255',
                'username' => 'string|max:255|unique:users',
                'phone' => 'string|max:255|unique:users',
                'password' => 'required|string|min:8',
            ];

            $requireEmailVerification = config('user-authentication.verification.require_email_verification', false);
            $requirePhoneVerification = config('user-authentication.verification.require_phone_verification', false);

            $validator = Validator::make($request->all(), $validationRules);

            if ($validator->fails()) {
                $response = $this->failure('Validation failed.', 422, [$validator->errors()]);

                return $this->runAfterHooks($request, $response, HookAction::REGISTER);
            }

            // Check if verification codes have been verified when required
            $smartPingsService = app(SmartPingsVerificationService::class);

            if ($requireEmailVerification) {
                if ($response = $this->checkVerificationStatus($request, $smartPingsService, $request->email, 'email', HookAction::REGISTER)) {
                    return $response;
                }
            }

            if ($requirePhoneVerification && $request->has('phone')) {
                if ($response = $this->checkVerificationStatus($request, $smartPingsService, $request->phone, 'phone', HookAction::REGISTER)) {
                    return $response;
                }
            }

            $user_data = $request->only(['first_name', 'last_name', 'email', 'password', 'phone', 'username']);
            $user_data['password'] = Hash::make($request->password);

            $User = config('user-authentication.user_model', User::class);
            $user = $User::create($user_data);
            UserRegisteredEvent::dispatch($user);
            $this->info("New user with email $request->email just registered ");

            $response = [
                'user' => $user,
                'token' => $user->createToken('auth-token')->plainTextToken,
            ];

            $response = $this->success($response, 'User registered successfully', 201);

            return $this->runAfterHooks($request, $response, HookAction::REGISTER);
        } catch (\Exception $e) {
            $this->error($e);

            $response = $this->failure('An error occurred', 500);

            return $this->runAfterHooks($request, $response, HookAction::REGISTER);
        }
    }

    public function login(Request $request): JsonResponse
    {
        $request = $this->runBeforeHooks($request, HookAction::LOGIN);
        $validator = Validator::make($request->all(), [
            'email' => 'required_without_all:phone,username|email',
            'phone' => 'required_without_all:email,username|string',
            'username' => 'required_without_all:email,phone|string',
            'password' => 'required|string|min:8',
        ]);

        if ($validator->fails()) {
            $response = $this->failure('Validation failed.', 422, [$validator->errors()]);

            return $this->runAfterHooks($request, $response, HookAction::LOGIN);
        }

        $identifier_field = $request->has('email') ? 'email'
            : ($request->has('phone') ? 'phone' : 'username');

        $credentials = [
            $identifier_field => $request->$identifier_field,
            'password' => $request->password,
        ];

        try {
            /* @var $User \Illuminate\Auth\Authenticatable */
            $User = config('user-authentication.user_model', User::class);

            $user = $User::where($identifier_field, $credentials[$identifier_field])->first();

            if (! $user || ! auth()->attempt($credentials)) {
                $response = $this->failure('Invalid credentials', 401);

                return $this->runAfterHooks($request, $response, HookAction::LOGIN);
            }

            UserLoggedInEvent::dispatch($user);

            $response = $this->success([
                'token' => $user->createToken('auth-token')->plainTextToken,
                'token_type' => 'Bearer',
                'user' => auth()->user(),
            ], 'User successfully logged in', 200);

            return $this->runAfterHooks($request, $response, HookAction::LOGIN);
        } catch (\Exception $e) {
            $this->error('An error occurred during login: '.$e->getMessage(), ['exception' => $e]);

            $response = $this->failure('An error occurred during login', 500);

            return $this->runAfterHooks($request, $response, HookAction::LOGIN);
        }
    }

    public function logout(Request $request): JsonResponse
    {
        $request = $this->runBeforeHooks($request, HookAction::LOGOUT);

        $user = $request->user();
        $user->currentAccessToken()->delete();
        UserLoggedOutEvent::dispatch($user);

        $response = $this->success([], 'User has been logged out successfully');

        return $this->runAfterHooks($request, $response, HookAction::LOGOUT);
    }

    public function oauthLogin(Request $request, $driver): JsonResponse
    {
        $request = $this->runBeforeHooks($request, HookAction::OAUTH_LOGIN);

        $url = Socialite::driver($driver)->stateless()->redirect()->getTargetUrl();

        $response = $this->success([
            'url' => $url,
            'message' => 'oauth login redirection url',
        ]);

        return $this->runAfterHooks($request, $response, HookAction::OAUTH_LOGIN);
    }

    public function oauthCallback(Request $request, $driver): JsonResponse
    {
        $request = $this->runBeforeHooks($request, HookAction::OAUTH_CALLBACK);

        $social_user = Socialite::driver($driver)->stateless()->user();
        $email = $social_user->getEmail();
        $name = $social_user->getName();

        if (empty($name) || empty($email)) {
            $response = $this->failure('Your app must request the name and email of the user', 400);

            return $this->runAfterHooks($request, $response, HookAction::OAUTH_CALLBACK);
        }


        $existing_user = $this->handleUserAuthentication($email, $name, $driver);


        $response = [
            'user' => $existing_user,
            'token' => $existing_user->createToken('auth-token')->plainTextToken,
        ];

        $response = $this->success($response, 'User authenticated successfully', 200);

        return $this->runAfterHooks($request, $response, HookAction::OAUTH_CALLBACK);

    }

    public function sendVerificationCode(Request $request): JsonResponse
    {
        $request = $this->runBeforeHooks($request, HookAction::SEND_VERIFICATION_CODE);

        // Validate request first to get contact for rate limiting
        $validator = Validator::make($request->all(), [
            'contact' => 'required|string',
            'type' => 'required|string|in:email,phone',
            'purpose' => 'string|in:registration,login',
        ]);

        if ($validator->fails()) {
            return $this->failure('Validation failed.', 422, [$validator->errors()]);
        }

        // Enhanced rate limiting with IP + contact
        $contact = $request->contact;
        $rateLimitKeyIp = 'verification-code:ip:'.$request->ip();
        $rateLimitKeyContact = 'verification-code:contact:'.hash('sha256', $contact);
        $attempts = config('user-authentication.verification.rate_limit_attempts');
        $minutes = config('user-authentication.verification.rate_limit_minutes', 5);

        if (RateLimiter::tooManyAttempts($rateLimitKeyIp, $attempts) ||
            RateLimiter::tooManyAttempts($rateLimitKeyContact, $attempts)) {
            $response = $this->failure('Too many attempts, please try again later.', 429);

            return $this->runAfterHooks($request, $response, HookAction::SEND_VERIFICATION_CODE);
        }

        RateLimiter::hit($rateLimitKeyIp, $minutes * 60);
        RateLimiter::hit($rateLimitKeyContact, $minutes * 60);
        $type = $request->type;
        $purpose = $request->purpose ?? 'registration';

        // Validate contact format based on type
        if ($type === 'email' && ! filter_var($contact, FILTER_VALIDATE_EMAIL)) {
            return $this->failure('Invalid email address.', 422);
        }

        // For registration, check if email/phone already exists
        if ($purpose === 'registration') {
            $User = config('user-authentication.user_model', User::class);
            $field = $type === 'email' ? 'email' : 'phone';
            $existingUser = $User::where($field, $contact)->first();

            if ($existingUser) {
                return $this->failure("This {$type} is already registered.", 422);
            }
        }

        // Check if SmartPings is enabled and not self-managed
        $smartPingsService = app(SmartPingsVerificationService::class);

        if ($smartPingsService->isEnabled()) {
            // Use SmartPings for verification
            $result = $smartPingsService->sendVerification($contact, $type);

            if ($result['success']) {
                $response = $this->success([], $result['message']);
            } else {
                $response = $this->failure($result['message'], 500);
            }
        } else {
            // Use default verification system
            $codeLength = config('user-authentication.verification.code_length', 6);
            $verificationCode = str_pad(random_int(0, pow(10, $codeLength) - 1), $codeLength, '0', STR_PAD_LEFT);
            $expiryMinutes = config('user-authentication.verification.code_expiry_minutes');
            $expiresAt = now()->addMinutes($expiryMinutes);

            // Clean up expired codes before storing new one
            VerificationCode::cleanupExpired();

            // Store the verification code
            VerificationCode::updateOrCreate(
                ['contact' => $contact, 'purpose' => "{$purpose}_{$type}"],
                ['code' => Hash::make($verificationCode), 'expires_at' => $expiresAt]
            );

            // Dispatch event for sending the code
            VerificationCodeGeneratedEvent::dispatch($contact, $verificationCode, "{$purpose}_{$type}", $type);

            $response = $this->success([], "Verification code sent to your {$type}.");
        }

        return $this->runAfterHooks($request, $response, HookAction::SEND_VERIFICATION_CODE);
    }

    public function verifyCode(Request $request): JsonResponse
    {
        $request = $this->runBeforeHooks($request, HookAction::VERIFY_CODE);

        $validator = Validator::make($request->all(), [
            'contact' => 'required|string',
            'code' => 'required|string',
            'type' => 'required|string|in:email,phone',
            'purpose' => 'string|in:registration,login',
        ]);

        if ($validator->fails()) {
            return $this->failure('Validation failed.', 422, [$validator->errors()]);
        }

        $contact = $request->contact;
        $code = $request->code;
        $type = $request->type;
        $purpose = $request->purpose ?? 'registration';

        // Check if SmartPings is enabled and not self-managed
        $smartPingsService = app(SmartPingsVerificationService::class);

        if ($smartPingsService->isEnabled()) {
            // Use SmartPings for verification
            $verified = $smartPingsService->verify($contact, $code, $type);

            if ($verified) {
                $response = $this->success([], 'Code verified successfully.');
            } else {
                $response = $this->failure('Invalid or expired code.', 400);
            }
        } else {
            // Use default verification system
            $codeEntry = VerificationCode::where('contact', $contact)
                ->where('purpose', "{$purpose}_{$type}")
                ->first();

            if (! $codeEntry) {
                return $this->failure('Invalid or expired code.', 400);
            }

            if (! Hash::check($code, $codeEntry->code) || $codeEntry->isExpired()) {
                return $this->failure('Invalid or expired code.', 400);
            }

            // Mark the code as verified
            $codeEntry->update(['verified_at' => now()]);

            $response = $this->success([], 'Code verified successfully.');
        }

        return $this->runAfterHooks($request, $response, HookAction::VERIFY_CODE);
    }

    private function checkVerificationStatus(
        Request $request,
        SmartPingsVerificationService $smartPingsService,
        string $contact,
        string $type,
        HookAction $hookAction
    ): ?JsonResponse {
        $purpose = 'registration_'.$type;
        $errorMessage = ucfirst($type).' verification required. Please verify your '.$type.' first.';

        if ($smartPingsService->isEnabled()) {
            if (! $smartPingsService->isVerified($contact, $type)) {
                $response = $this->failure($errorMessage, 422);

                return $this->runAfterHooks($request, $response, $hookAction);
            }
        } else {
            $verifiedCode = VerificationCode::where('contact', $contact)
                ->where('purpose', $purpose)
                ->where('verified_at', '!=', null)
                ->where('expires_at', '>', now())
                ->first();

            if (! $verifiedCode) {
                $response = $this->failure($errorMessage, 422);

                return $this->runAfterHooks($request, $response, $hookAction);
            }
        }

        return null;
    }

    public function firebaseAuthCallback(Request $request, string $driver)
    {
        $driver = strtolower($driver);
        $rules = ['token' => 'required|string'];

        $validator = Validator::make($request->all(), $rules);

        if ($validator->fails()) {
            $errors = $validator->errors();
            $response = $this->failure('Server failed to validate request.', 422, $errors->toArray());

            return $this->runAfterHooks($request, $response, HookAction::OAUTH_CALLBACK);
        }

        $auth = Firebase::auth();
        try {
            $verifiedIdToken = $auth->verifyIdToken($request->token);
            $uid = $verifiedIdToken->claims()->get('sub');
            $user = $auth->getUser($uid);

            $email = $user->email;
            $name = $user->displayName;

            if (empty($name) || empty($email)) {
                $response = $this->failure('Your app must request the name and email of the user', 400);

                return $this->runAfterHooks($request, $response, HookAction::OAUTH_CALLBACK);
            }
            if ($driver == 'apple' && ! config('user-authentication.allow_ios_private_emails', true)) {
                if (str_contains($email, '@privaterelay.appleid.com')) {
                    $response = $this->failure('Please enable Share My Email on your IOS device', 400);

                    return $this->runAfterHooks($request, $response, HookAction::OAUTH_CALLBACK);
                }
            }

            $existing_user = $this->handleUserAuthentication($email, $name, $driver);

            $response = [
                'user' => $existing_user,
                'token' => $existing_user->createToken('auth-token')->plainTextToken,
            ];

            $response = $this->success($response, 'User authenticated successfully', 200);

            return $this->runAfterHooks($request, $response, HookAction::OAUTH_CALLBACK);
        } catch (FailedToVerifyToken $e) {
            $this->error($e->getMessage());
            $response = $this->failure('Invalid token', 400);

            return $this->runAfterHooks($request, $response, HookAction::OAUTH_CALLBACK);
        } catch (AuthException|FirebaseException $e) {
            $this->error($e->getMessage());
            $response = $this->failure('Invalid token', 400);

            return $this->runAfterHooks($request, $response, HookAction::OAUTH_CALLBACK);
        }
    }

     /**
     * Private helper method to handle user authentication (login/create) and OAuth account creation.
     *
     * @param string $email
     * @param string $name
     * @param string $driver
     * @return mixed The authenticated user instance.
     */
    private function handleUserAuthentication(string $email, string $name, string $driver){
        $User = config('user-authentication.user_model', User::class);
        $existing_user = $User::where('email', $email)->first();
        if ($existing_user){
            UserLoggedInEvent::dispatch($existing_user);
            $this->info("User with email $email  just logged in via social auth ");
        } else {
            $user_data = [
                'first_name' => $name,
                'email' => $email,
                'password' => Hash::make(Str::random(10))
            ];
            $existing_user = $User::create($user_data);
            UserRegisteredEvent::dispatch($existing_user);
            $this->info("New user with email $email just registered via social auth" );
        }
        OauthAccount::firstOrCreate([
            'user_id' => $existing_user->id,
            'provider' => $driver
        ]);
        return $existing_user;
    }

}
