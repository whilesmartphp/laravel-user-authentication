<?php

namespace Whilesmart\UserAuthentication\Http\Controllers\Auth;

use Illuminate\Http\Request;
use Illuminate\Routing\Controller;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Str;
use Laravel\Sanctum\Contracts\HasAbilities;
use Laravel\Sanctum\PersonalAccessToken;
use Whilesmart\UserAuthentication\Enums\HookAction;
use Whilesmart\UserAuthentication\Events\UserLoggedInEvent;
use Whilesmart\UserAuthentication\Models\TwoFactorAuth;
use Whilesmart\UserAuthentication\Models\User;
use Whilesmart\UserAuthentication\Services\TwoFactorService;
use Whilesmart\UserAuthentication\Traits\ApiResponse;
use Whilesmart\UserAuthentication\Traits\HasMiddlewareHooks;

class TwoFactorController extends Controller
{
    use ApiResponse;
    use HasMiddlewareHooks;

    private function rules(bool $required = true): array
    {
        return [
            'two_factor_token' => ($required ? 'required' : 'nullable')
                . '|string|min:100|max:2048|regex:/\A[a-zA-Z0-9+\/=]+\z/',
            'code' => [$required ? 'required' : 'nullable', 'string', 'regex:/\A(?:[0-9]{4,8}|[a-zA-Z0-9]{10})\z/'],
        ];
    }

    public function setup(Request $request)
    {
        /** @var User $user */
        $user = $request->user();
        /** @var HasAbilities|null $current */
        $current = $user->currentAccessToken();
        if (! $current instanceof PersonalAccessToken) {
            return $this->failure('A bearer token is required.', 401);
        }

        return DB::transaction(function () use ($request) {
            /** @var User $user */
            $user = $request->user();
            $user->newQuery()->whereKey($user->id)->lockForUpdate()->firstOrFail();
            $factor = $user->twoFactorAuth()->lockForUpdate()->first();
            if ($factor?->is_enabled) {
                return $this->failure('Two-factor authentication is already enabled.', 400);
            }
            $google2fa = app('pragmarx.google2fa');
            $secret = $google2fa->generateSecretKey();
            $user->twoFactorAuth()->updateOrCreate([], [
                'secret' => $secret, 'type' => 'totp', 'is_enabled' => false,
                'last_used_step' => null, 'setup_attempts' => 0,
            ]);

            return $this->success([
                'secret' => $secret,
                'qr_code_url' => $google2fa->getQRCodeUrl(config('app.name'), $user->email, $secret),
            ], 'Two-factor authentication setup initiated. Please confirm with your authenticator app.');
        });
    }

    public function confirm(Request $request)
    {
        /** @var User $user */
        $user = $request->user();
        /** @var HasAbilities|null $current */
        $current = $user->currentAccessToken();
        if (! $current instanceof PersonalAccessToken) {
            return $this->failure('A bearer token is required.', 401);
        }

        $request->validate(['code' => ['required', 'string', 'regex:/\A[0-9]{6}\z/']]);

        return DB::transaction(function () use ($request, $current) {
            /** @var User $user */
            $user = $request->user();
            $user->newQuery()->whereKey($user->id)->lockForUpdate()->firstOrFail();
            $factor = $user->twoFactorAuth()->lockForUpdate()->first();
            if ($factor?->is_enabled) {
                return $this->failure('Two-factor authentication is already enabled.', 400);
            }
            if (! $factor || ! $factor->secret) {
                return $this->failure('2FA setup has not been initiated.', 400);
            }
            $factor->increment('setup_attempts');
            $valid = app(TwoFactorService::class)->verifyFactor($factor, $request->code);
            if (! $valid) {
                if ($factor->setup_attempts >= max(1, (int) config('user-authentication.two_factor.attempts', 5))) {
                    $factor->delete();
                }

                return $this->failure('Invalid code. Please try again.', 422);
            }
            $codes = collect(range(1, 8))->map(fn () => Str::random(10))->all();
            $factor->update(['is_enabled' => true, 'confirmed_at' => now(), 'recovery_codes' => $codes]);
            $user->tokens()->where('id', '!=', $current->getKey())->delete();
            $current->forceFill([
                'abilities' => array_values(array_unique([...$current->getAttribute('abilities'), '2fa-verified'])),
            ])->save();

            return $this->success(
                ['recovery_codes' => $codes],
                'Two-factor authentication has been enabled successfully.'
            );
        });
    }

    public function disable(Request $request)
    {
        $request->validate($this->rules(false));

        return DB::transaction(function () use ($request) {
            /** @var User $user */
            $user = $request->user();
            $user->newQuery()->whereKey($user->id)->lockForUpdate()->firstOrFail();
            $factor = $user->twoFactorAuth()->lockForUpdate()->first();
            if (! $factor?->is_enabled) {
                return $this->failure('Two-factor authentication is not enabled.', 400);
            }
            $service = app(TwoFactorService::class);
            if ($factor->type === 'totp') {
                if (! $request->code || ! $service->verifyFactor($factor, $request->code)) {
                    return $this->failure('Invalid code. Could not disable 2FA.', 422);
                }
                $factor->delete();
                $user->tokens()->delete();

                return $this->success([], 'Two-factor authentication has been disabled.');
            }
            if (! $request->code && ! $request->two_factor_token) {
                $pending = $service->issue($user, 'disable_2fa');
                if ($pending === null) {
                    return $this->failure('Two-factor policy changed.', 409);
                }

                return $this->success($pending, 'A verification code has been sent to complete 2FA disable.');
            }
            if (
                ! $request->code || ! $request->two_factor_token
                || ! $service->consume($user, $request->two_factor_token, $request->code, 'disable_2fa')
            ) {
                return $this->failure('Invalid or expired code.', 422);
            }

            return $this->success([], 'Two-factor authentication has been disabled.');
        });
    }

    public function verify(Request $request)
    {
        $request->validate($this->rules());

        return $this->complete($request, $request->code);
    }

    public function verifyLink(Request $request)
    {
        $request->validate([
            'two_factor_token' => 'required|string|min:100|max:2048|regex:/\A[a-zA-Z0-9+\/=]+\z/',
            'token' => ['required', 'string', 'regex:/\A[a-zA-Z0-9]{64}\z/'],
        ]);

        return $this->complete($request, $request->token, true);
    }

    private function complete(Request $request, string $code, bool $link = false)
    {
        $request = $this->runBeforeHooks($request, HookAction::VERIFY_TWO_FACTOR);
        $service = app(TwoFactorService::class);
        $challenge = $service->challenge($request->two_factor_token);
        if (! $challenge || $challenge->purpose !== 'login') {
            return $this->failure('Invalid or expired two-factor token.', 401);
        }
        $factor = TwoFactorAuth::whereKey($challenge->factor_id)->first();
        $user = $factor?->authenticatable;
        if (! $user) {
            return $this->failure('Invalid or expired two-factor token.', 401);
        }

        return DB::transaction(function () use ($request, $service, $user, $code, $link) {
            $user->newQuery()->whereKey($user->id)->lockForUpdate()->firstOrFail();
            $action = $service->consume($user, $request->two_factor_token, $code, 'login', $link);
            if (! $action) {
                return $this->failure('Invalid or expired code.', 422);
            }
            $response = $this->success([
                'token' => $user->createToken('auth-token', ['2fa-verified'])->plainTextToken,
                'token_type' => 'Bearer',
                'user' => $service->userData($user),
            ], 'Authenticated successfully.');
            UserLoggedInEvent::dispatch($user);

            return $this->runAfterHooks($request, $response, HookAction::from($action));
        });
    }

    public function resend(Request $request)
    {
        $request->validate(['two_factor_token' => 'required|string|min:100|max:2048|regex:/\A[a-zA-Z0-9+\/=]+\z/']);
        $service = app(TwoFactorService::class);
        $challenge = $service->challenge($request->two_factor_token);
        if (! $challenge || $challenge->purpose !== 'login') {
            return $this->failure('Invalid or expired two-factor token.', 401);
        }
        if ($challenge->method === 'totp') {
            return $this->failure('TOTP codes are generated by your authenticator app.', 400);
        }
        $factor = TwoFactorAuth::whereKey($challenge->factor_id)->first();
        $user = $factor?->authenticatable;
        if (! $factor || ! $user || ! $service->current($user, $factor, $challenge)) {
            return $this->failure('Invalid or expired two-factor token.', 401);
        }

        return DB::transaction(function () use ($user, $request, $service) {
            $user = $user->newQuery()->whereKey($user->id)->lockForUpdate()->firstOrFail();
            $factor = $user->twoFactorAuth()->lockForUpdate()->first();
            $challenge = $service->challenge($request->two_factor_token);
            if (! $factor || ! $challenge || ! $service->current($user, $factor, $challenge)) {
                return $this->failure('Invalid or expired two-factor token.', 401);
            }

            $pending = $service->issue($user, 'login', HookAction::from($challenge->action));
            if ($pending === null) {
                return $this->failure('Two-factor policy changed.', 409);
            }

            return $this->success(
                $pending,
                'A new verification code has been sent.'
            );
        });
    }
}
