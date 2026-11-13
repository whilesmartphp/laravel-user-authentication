<?php

namespace Whilesmart\UserAuthentication\Http\Controllers\Auth;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Http\Request;
use Illuminate\Routing\Controller;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Str;
use Whilesmart\UserAuthentication\Enums\HookAction;
use Whilesmart\UserAuthentication\Events\UserRegisteredEvent;
use Whilesmart\UserAuthentication\Events\VerificationCodeGeneratedEvent;
use Whilesmart\UserAuthentication\Models\User;
use Whilesmart\UserAuthentication\Rules\EmailDomainRestriction;
use Whilesmart\UserAuthentication\Services\ContactLoginService;
use Whilesmart\UserAuthentication\Traits\ApiResponse;
use Whilesmart\UserAuthentication\Traits\HasMiddlewareHooks;
use Whilesmart\UserAuthentication\Traits\SignsInUsers;

class EmailLoginController extends Controller
{
    use ApiResponse;
    use HasMiddlewareHooks;
    use SignsInUsers;

    public function issue(Request $request)
    {
        abort_unless(config('user-authentication.email_login.enabled'), 404);
        $request = $this->runBeforeHooks($request, HookAction::EMAIL_LOGIN_REQUEST);
        $request->validate(['email' => ['required', 'string', 'email', 'max:255', new EmailDomainRestriction()]]);
        $email = strtolower(trim($request->email));
        $model = config('user-authentication.user_model', User::class);
        $user = $model::whereRaw('LOWER(email) = ?', [$email])->first();
        $service = app(ContactLoginService::class);
        $delivery = $service->prepare(
            'email',
            $email,
            $this->policy($user),
            config('user-authentication.email_login')
        );
        $service->store(array_merge($delivery['attributes'], [
            'authenticatable_type' => $user?->getMorphClass(),
            'authenticatable_id' => $user?->getKey(),
            'ip_address' => $request->ip(),
            'user_agent' => $request->userAgent(),
        ]));
        if ($user || config('user-authentication.email_login.create_users')) {
            $url = config('user-authentication.email_login.url');
            $link = $url ? $url . (str_contains($url, '?') ? '&' : '?')
                . http_build_query(['token' => $delivery['token']]) : null;
            $code = $delivery['code'];
            $sent = false;
            // Delivery runs after the response is sent so its latency cannot reveal whether the address exists.
            // Terminating callbacks persist on a reused application, so the flag keeps delivery to one send.
            app()->terminating(function () use ($email, $code, $link, &$sent) {
                if ($sent) {
                    return;
                }
                $sent = true;
                try {
                    VerificationCodeGeneratedEvent::dispatch($email, $code, 'contact_login', 'email', $link);
                } catch (\Throwable $exception) {
                    report($exception);
                }
            });
        }

        return $this->runAfterHooks(
            $request,
            $this->success([], 'If this email can sign in, a code has been sent.', 202),
            HookAction::EMAIL_LOGIN_REQUEST
        );
    }

    public function verify(Request $request)
    {
        abort_unless(config('user-authentication.email_login.enabled'), 404);
        $request = $this->runBeforeHooks($request, HookAction::EMAIL_LOGIN_VERIFY);
        $request->validate([
            'email' => 'required_without:token|prohibits:token|string|email|max:255',
            'code' => ['required_without:token', 'prohibits:token', 'string', 'regex:/\A[0-9]{6}\z/'],
            'token' => ['required_without_all:email,code', 'prohibits:email,code', 'string',
                'regex:/\A[a-zA-Z0-9]{64}\z/'],
        ]);
        $service = app(ContactLoginService::class);
        $link = $request->filled('token');
        $email = $link ? $service->contactForToken($request->token) : strtolower(trim($request->email));
        if (! $email) {
            return $this->failure('Invalid or expired code.', 422);
        }

        return DB::transaction(function () use ($request, $service, $link, $email) {
            $proof = $service->consume(
                'email',
                $email,
                $link ? $request->token : $request->code,
                $link,
                (int) config('user-authentication.email_login.attempts', 5)
            );
            if (! $proof) {
                return $this->failure('Invalid or expired code.', 422);
            }
            $model = config('user-authentication.user_model', User::class);
            $user = $model::whereRaw('LOWER(email) = ?', [$email])->lockForUpdate()->first();
            if (! hash_equals($proof['policy'], $this->policy($user))) {
                return $this->failure('Invalid or expired code.', 422);
            }
            if (! $user) {
                if (! config('user-authentication.email_login.create_users')) {
                    return $this->failure('Invalid or expired code.', 422);
                }
                $user = new $model();
                $user->forceFill([
                    'email' => $email, 'email_verified_at' => now(),
                    'first_name' => '', 'password' => Hash::make(Str::random(64)),
                ])->save();
                UserRegisteredEvent::dispatch($user);
            } else {
                $user->forceFill(['email_verified_at' => now()])->save();
            }

            return $this->runAfterHooks(
                $request,
                $this->signIn($request, $user, HookAction::LOGIN),
                HookAction::EMAIL_LOGIN_VERIFY
            );
        });
    }

    private function policy(?Model $user): string
    {
        return hash('sha256', $user ? $user->getMorphClass() . ':' . $user->getKey() : 'signup');
    }
}
