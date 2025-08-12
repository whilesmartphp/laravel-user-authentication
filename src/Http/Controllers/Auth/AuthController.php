<?php

namespace Whilesmart\UserAuthentication\Http\Controllers\Auth;

use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Routing\Controller;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Validator;
use Illuminate\Support\Str;
use Laravel\Socialite\Facades\Socialite;
use OpenApi\Attributes as OA;
use Whilesmart\UserAuthentication\Enums\HookAction;
use Whilesmart\UserAuthentication\Events\UserLoggedInEvent;
use Whilesmart\UserAuthentication\Events\UserLoggedOutEvent;
use Whilesmart\UserAuthentication\Events\UserRegisteredEvent;
use Whilesmart\UserAuthentication\Models\OauthAccount;
use Whilesmart\UserAuthentication\Models\User;
use Whilesmart\UserAuthentication\Traits\ApiResponse;
use Whilesmart\UserAuthentication\Traits\HasMiddlewareHooks;
use Whilesmart\UserAuthentication\Traits\Loggable;

#[OA\Tag(name: 'Authentication', description: 'Endpoints for user authentication')]
class AuthController extends Controller
{
    use ApiResponse, HasMiddlewareHooks, Loggable;

    #[OA\Post(
        path: '/register',
        summary: 'Register a new user',
        security: [],
        requestBody: new OA\RequestBody(
            required: true,
            content: new OA\JsonContent(
                required: ['email', 'first_name', 'password'],
                properties: [
                    new OA\Property(property: 'email', type: 'string', format: 'email'),
                    new OA\Property(property: 'first_name', type: 'string'),
                    new OA\Property(property: 'last_name', type: 'string'),
                    new OA\Property(property: 'username', type: 'string'),
                    new OA\Property(property: 'phone', type: 'string'),
                    new OA\Property(property: 'password', type: 'string', format: 'password'),
                ]
            )
        ),
        tags: ['Authentication'],
        responses: [
            new OA\Response(response: 201, description: 'User registered successfully'),
            new OA\Response(response: 422, description: 'Validation error'),
        ]
    )]
    public function register(Request $request): JsonResponse
    {
        $request = $this->runBeforeHooks($request, HookAction::REGISTER);

        try {
            $validator = Validator::make($request->all(), [
                'email' => 'required|string|email|max:255|unique:users',
                'first_name' => 'required|string|max:255',
                'last_name' => 'string|max:255',
                'username' => 'string|max:255',
                'phone' => 'string|max:255',
                'password' => 'required|string|min:8',
            ]);

            if ($validator->fails()) {
                return $this->failure('Validation failed.', 422, [$validator->errors()]);
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

            return $this->success($response, 'User registered successfully', 201);
        } catch (\Exception $e) {
            $this->error($e);

            return $this->failure('An error occurred', 500);
        }
    }

    #[OA\Post(
        path: '/login',
        summary: 'User login',
        security: [],
        requestBody: new OA\RequestBody(
            required: true,
            content: new OA\JsonContent(
                required: ['password'],
                properties: [
                    new OA\Property(property: 'email', type: 'string', format: 'email'),
                    new OA\Property(property: 'phone', type: 'string'),
                    new OA\Property(property: 'username', type: 'string'),
                    new OA\Property(property: 'password', type: 'string', format: 'password'),
                ]
            )
        ),
        tags: ['Authentication'],
        responses: [
            new OA\Response(response: 200, description: 'User successfully logged in'),
            new OA\Response(response: 401, description: 'Invalid credentials'),
            new OA\Response(response: 500, description: 'Server error'),
        ]
    )]
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
            return $this->failure('Validation failed.', 422, [$validator->errors()]);
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
                return $this->failure('Invalid credentials', 401);
            }

            UserLoggedInEvent::dispatch($user);

            return $this->success([
                'token' => $user->createToken('auth-token')->plainTextToken,
                'token_type' => 'Bearer',
                'user' => auth()->user(),
            ], 'User successfully logged in', 200);
        } catch (\Exception $e) {
            $this->error('An error occurred during login: '.$e->getMessage(), ['exception' => $e]);

            return $this->failure('An error occurred during login', 500);
        }
    }

    #[OA\Post(
        path: '/logout',
        summary: 'User logout',
        security: [
            ['sanctum' => []],
        ],
        tags: ['Authentication'],
        responses: [
            new OA\Response(response: 200, description: 'User successfully logged out'),
            new OA\Response(response: 401, description: 'Invalid credentials'),
            new OA\Response(response: 500, description: 'Server error'),
        ]
    )]
    public function logout(Request $request): JsonResponse
    {
        $request = $this->runBeforeHooks($request, HookAction::LOGOUT);

        $user = $request->user();
        $user->currentAccessToken()->delete();
        UserLoggedOutEvent::dispatch($user);

        return $this->success([], 'User has been logged out successfully');
    }

    #[OA\Get(
        path: '/oauth/{driver}/login',
        summary: 'Get Oauth redirect URI',
        tags: ['Authentication'],
        responses: [
            new OA\Response(response: 200, description: 'URL generated'),
            new OA\Response(response: 500, description: 'Server error'),
        ]
    )]
    public function oauthLogin(Request $request, $driver): JsonResponse
    {
        $request = $this->runBeforeHooks($request, HookAction::OAUTH_LOGIN);

        $url = Socialite::driver($driver)->stateless()->redirect()->getTargetUrl();

        return $this->success([
            'url' => $url,
            'message' => 'oauth login redirection url',
        ]);
    }

    #[OA\Get(
        path: '/oauth/{driver}/callback',
        summary: 'Handles Oauth login callback',
        tags: ['Authentication'],
        responses: [
            new OA\Response(response: 200, description: ' '),
            new OA\Response(response: 500, description: 'Server error'),
        ]
    )]
    public function oauthCallback(Request $request, $driver): JsonResponse
    {
        $request = $this->runBeforeHooks($request, HookAction::OAUTH_CALLBACK);

        $social_user = Socialite::driver($driver)->stateless()->user();
        $email = $social_user->getEmail();
        $name = $social_user->getName();

        if (empty($name) || empty($email)) {
            return $this->failure('Your app must request the name and email of the user', 400);
        }

        $User = config('user-authentication.user_model', User::class);
        $existing_user = $User::where('email', $email)->first();
        if ($existing_user) {
            UserLoggedInEvent::dispatch($existing_user);
            $this->info("User with email $email just logged in via social auth ");
        } else {
            $user_data = ['first_name' => $name, 'email' => $email, 'password' => Hash::make(Str::random(10))];
            $existing_user = $User::create($user_data);
            UserRegisteredEvent::dispatch($existing_user);
            $this->info("New user with email $email just registered via social auth ");
        }

        OauthAccount::firstOrCreate([
            'user_id' => $existing_user->id,
            'provider' => $driver,
        ]);

        $response = [
            'user' => $existing_user,
            'token' => $existing_user->createToken('auth-token')->plainTextToken,
        ];

        return $this->success($response, 'User authenticated successfully', 200);

    }
}
