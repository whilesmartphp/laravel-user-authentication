<?php

namespace Whilesmart\UserAuthentication\Http\Controllers\Auth;

use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Routing\Controller;
use Illuminate\Support\Facades\Cookie;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Str;
use Illuminate\Support\Facades\Validator;
use Illuminate\Database\QueryException;
use Laravel\Socialite\Two\User as SocialiteUser;
use Whilesmart\UserAuthentication\Rules\EmailDomainRestriction;
use Whilesmart\UserAuthentication\Enums\HookAction;
use Whilesmart\UserAuthentication\Events\OauthUserAuthenticatedEvent;
use Whilesmart\UserAuthentication\Events\UserRegisteredEvent;
use Whilesmart\UserAuthentication\Models\User;
use Whilesmart\UserAuthentication\Models\WhilesmartIdentity;
use Whilesmart\UserAuthentication\Services\WhilesmartLogin;
use Whilesmart\UserAuthentication\Traits\ApiResponse;
use Whilesmart\UserAuthentication\Traits\HasMiddlewareHooks;
use Whilesmart\UserAuthentication\Traits\SignsInUsers;

class WhilesmartController extends Controller
{
    use ApiResponse;
    use HasMiddlewareHooks;
    use SignsInUsers;

    public function __construct()
    {
        $this->middleware(function ($request, $next) {
            return $next($request)->header('Cache-Control', 'no-store');
        });
    }

    public function login(Request $request, WhilesmartLogin $login): JsonResponse
    {
        $request = $this->runBeforeHooks($request, HookAction::OAUTH_LOGIN);
        try {
            $transaction = $login->begin($request);
        } catch (\Throwable) {
            return $this->failure('Whilesmart sign-in is unavailable.', 503);
        }
        $response = $this->success(['url' => $transaction['url']], 'Open Whilesmart to sign in.');
        $response->headers->setCookie(Cookie::make(
            'user_auth_whilesmart',
            $transaction['browser'],
            10,
            '/',
            null,
            $request->isSecure(),
            true,
            false,
            'lax'
        ));

        return $this->runAfterHooks($request, $response, HookAction::OAUTH_LOGIN);
    }


    public function link(Request $request, WhilesmartLogin $login): JsonResponse
    {
        try {
            $transaction = $login->begin($request, true);
        } catch (\Throwable) {
            return $this->failure('Account linking could not be started.', 400);
        }
        $response = $this->success(['url' => $transaction['url']], 'Authorize Whilesmart to link your account.');
        $response->headers->setCookie(Cookie::make(
            'user_auth_whilesmart',
            $transaction['browser'],
            10,
            '/',
            null,
            $request->isSecure(),
            true,
            false,
            'lax'
        ));

        return $response;
    }

    public function callback(Request $request, WhilesmartLogin $login): JsonResponse
    {
        $request = $this->runBeforeHooks($request, HookAction::OAUTH_CALLBACK);
        try {
            $remote = $login->complete($request);
        } catch (\Throwable) {
            return $this->failure('Whilesmart authorization failed. Start sign-in again.', 400);
        }
        $User = config('user-authentication.user_model', User::class);
        $key = hash('sha256', implode("\0", [$remote['issuer'], $remote['subject']]));
        $identity = WhilesmartIdentity::find($key);
        $new = false;
        if ($remote['link'] !== null) {
            return $this->finishLink($remote, $User, $key, $identity);
        }

        if ($identity) {
            if ($identity->getAttribute('user_type') !== $User) {
                return $this->failure('This identity belongs to another account type.', 409);
            }
            $user = $User::find($identity->getAttribute('user_id'));
            if (! $user) {
                return $this->failure('The linked account is unavailable.', 403);
            }
        } else {
            $registered = $this->registerAccount($remote, $User, $key);
            if ($registered instanceof JsonResponse) {
                return $registered;
            }
            [$user, $identity] = $registered;
            $new = true;
        }

        if (config('user-authentication.whilesmart.retain_tokens', false)) {
            $identity->setAttribute('credentials', $remote['credentials']);
            $identity->save();
        }
        $social = (new SocialiteUser())->setRaw($remote['identity'])->map(['id' => $remote['subject'],
             'name' => $remote['identity']['name'] ?? '',
             'email' => $remote['identity']['email'] ?? null,
             'avatar' => null]);
        if ($new) {
            UserRegisteredEvent::dispatch($user);
        }
        OauthUserAuthenticatedEvent::dispatch($user, $social, 'whilesmart', $new);

        return $this->signIn($request, $user, HookAction::OAUTH_CALLBACK);
    }

    private function finishLink(array $remote, string $User, string $key, ?WhilesmartIdentity $identity): JsonResponse
    {
        $link = $remote['link'];
        if (
            $link['type'] !== $User
            || ($identity
            && ($identity->getAttribute('user_type') !== $User
            || (string) $identity->getAttribute('user_id') !== $link['id']))
        ) {
            return $this->failure('This Whilesmart identity is already linked to another account.', 409);
        }
        $user = $User::find($link['id']);
        if (! $user) {
            return $this->failure('The local account is unavailable.', 403);
        }
        try {
            $identity ??= WhilesmartIdentity::create(['identity_key' => $key,
                 'issuer' => $remote['issuer'],
                 'subject' => $remote['subject'],
                 'user_type' => $User,
                 'user_id' => $link['id']]);
        } catch (QueryException) {
            return $this->failure('The account changed during linking. Start again.', 409);
        }
        if (config('user-authentication.whilesmart.retain_tokens', false)) {
            $identity->setAttribute('credentials', $remote['credentials']);
            $identity->save();
        }

        return $this->success([], 'Whilesmart account linked.');
    }

    private function registerAccount(array $remote, string $User, string $key): array|JsonResponse
    {
        $profile = $remote['identity'];
        $email = $profile['email'] ?? null;
        if (
            ! is_string($email)
            || ! filter_var($email, FILTER_VALIDATE_EMAIL)
            || ($profile['email_verified'] ?? false) !== true
        ) {
            return $this->failure('Request a verified email to create an account.', 422);
        }
        if (Validator::make(['email' => $email], ['email' => [new EmailDomainRestriction()]])->fails()) {
            return $this->failure('This email domain cannot register an account.', 422);
        }
        if ($User::where('email', $email)->exists()) {
            return $this->failure('Sign in to your existing account and explicitly link Whilesmart.', 409);
        }
        try {
            [$user, $identity] = DB::transaction(function () use ($User, $remote, $profile, $email, $key): array {
                $user = (new $User())->newQuery()->create(['email' => $email,
                     'password' => Hash::make(Str::random(64)),
                     'first_name' => $profile['given_name'] ?? '',
                     'last_name' => $profile['family_name'] ?? '',
                     'email_verified_at' => now()]);
                $identity = WhilesmartIdentity::create(['identity_key' => $key,
                     'issuer' => $remote['issuer'],
                     'subject' => $remote['subject'],
                     'user_type' => $User,
                     'user_id' => (string) $user->getKey()]);

                return [$user, $identity];
            });
            return [$user, $identity];
        } catch (QueryException) {
            return $this->failure('The account changed during sign-in. Try again.', 409);
        }
    }
}
