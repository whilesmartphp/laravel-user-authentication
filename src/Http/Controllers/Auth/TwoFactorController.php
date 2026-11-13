<?php

namespace Whilesmart\UserAuthentication\Http\Controllers\Auth;

use Illuminate\Http\Request;
use Illuminate\Routing\Controller;
use Illuminate\Support\Facades\DB;
use Laravel\Sanctum\Contracts\HasAbilities;
use Laravel\Sanctum\PersonalAccessToken;
use Whilesmart\UserAuthentication\Enums\HookAction;
use Whilesmart\UserAuthentication\Events\UserLoggedInEvent;
use Whilesmart\UserAuthentication\Models\AuthFactor;
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

    private function requiresBearer(Request $request): bool
    {
        /** @var HasAbilities|null $token */
        $token = $request->user()->currentAccessToken();

        return ! $token instanceof PersonalAccessToken;
    }

    public function setup(Request $request)
    {
        if ($this->requiresBearer($request)) {
            return $this->failure('Two-factor setup requires a bearer token.', 403);
        }
        $request->validate(['type' => 'sometimes|string|max:16', 'label' => 'nullable|string|max:255']);
        $user = $request->user();
        $data = app(TwoFactorService::class)->setup($user, $request->input('type', 'totp'), $request->input('label'));

        return $this->success($data, 'Two-factor authentication setup initiated.');
    }

    public function confirm(Request $request)
    {
        $request->validate([
            'factor_id' => 'required|integer',
            ...$this->rules(false),
            'code' => ['required', 'string', 'regex:/\A[0-9]{4,8}\z/'],
        ]);
        if ($this->requiresBearer($request)) {
            return $this->failure('Two-factor setup requires a bearer token.', 403);
        }
        $user = $request->user();
        /** @var PersonalAccessToken $current */
        $current = $user->currentAccessToken();

        return DB::transaction(function () use ($request, $user, $current) {
            $service = app(TwoFactorService::class);
            $factor = $service->lockFactors($user)->find($request->integer('factor_id'));
            if (! $factor || $factor->confirmed_at) {
                return $this->failure('Setup missing or already confirmed.', 400);
            }
            $factor->increment('setup_attempts');
            if ($service->type($factor->type)->needsSecret()) {
                $valid = $service->verifyFactor($factor, $request->code);
            } else {
                $pending = $service->challenge($request->input('two_factor_token', ''));
                $valid = $pending && $pending->factor_id === $factor->id
                    && $service->consume($user, $request->two_factor_token, $request->code, 'setup_2fa');
            }
            if (! $valid) {
                if ($factor->setup_attempts >= max(1, (int) config('user-authentication.two_factor.attempts', 5))) {
                    $factor->delete();
                }

                return $this->failure('Invalid code. Please try again.', 422);
            }
            $first = ! $user->hasTwoFactorEnabled();
            $factor->update(['confirmed_at' => now(), 'last_used_at' => now()]);
            $codes = $first ? $service->regenerateRecoveryCodes($user) : [];
            $user->tokens()->where('id', '!=', $current->getKey())->delete();
            $current->forceFill([
                'abilities' => array_values(array_unique([...$current->getAttribute('abilities'), '2fa-verified'])),
            ])->save();

            return $this->success(['recovery_codes' => $codes], 'Two-factor authentication has been enabled.');
        });
    }

    public function disable(Request $request)
    {
        $request->validate(['factor_id' => 'required|integer', ...$this->rules(false)]);

        return DB::transaction(function () use ($request) {
            $user = $request->user();
            $service = app(TwoFactorService::class);
            $factor = $service->lockFactors($user)->find($request->integer('factor_id'));
            if (! $factor) {
                return $this->failure('Factor not found.', 404);
            }
            if (! $factor->confirmed_at) {
                $factor->delete();

                return $this->success([], 'Pending factor removed.');
            }
            if ($service->type($factor->type)->needsSecret()) {
                $valid = $request->code && ($service->verifyFactor($factor, $request->code)
                    || $service->verifyRecoveryCode($user, $request->code));
                if (! $valid) {
                    return $this->failure('Invalid code. Could not disable 2FA.', 422);
                }
                $service->remove($user, $factor);

                return $this->success([], 'Factor removed.');
            }

            return $this->disableWithChallenge($request, $service, $factor);
        });
    }

    private function disableWithChallenge(Request $request, TwoFactorService $service, AuthFactor $factor)
    {
        $user = $request->user();
        if (! $request->code && ! $request->two_factor_token) {
            return $this->success(
                $service->issue($user, 'disable_2fa', HookAction::LOGIN, $factor->id),
                'A verification code has been sent.'
            );
        }
        $pending = $service->challenge($request->input('two_factor_token', ''));
        if (
            ! $pending || $pending->factor_id !== $factor->id || ! $request->code
            || ! $service->consume($user, $request->two_factor_token, $request->code, 'disable_2fa')
        ) {
            return $this->failure('Invalid or expired code.', 422);
        }

        return $this->success([], 'Factor removed.');
    }

    public function index(Request $request)
    {
        return $this->success(['factors' => $request->user()->factors()->orderBy('id')->get([
            'id', 'type', 'label', 'confirmed_at', 'last_used_at',
        ])]);
    }

    public function regenerateRecoveryCodes(Request $request)
    {
        return DB::transaction(function () use ($request) {
            $service = app(TwoFactorService::class);
            $user = $request->user();
            $service->lockFactors($user);
            if (! $user->hasTwoFactorEnabled()) {
                return $this->failure('Two-factor authentication is not enabled.', 400);
            }

            return $this->success(['recovery_codes' => $service->regenerateRecoveryCodes($user)]);
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
        $factor = AuthFactor::whereKey($challenge->factor_id)->first();
        /** @var (\Illuminate\Database\Eloquent\Model&\Illuminate\Contracts\Auth\Authenticatable)|null $user */
        $user = $factor?->authenticatable;
        if (! $user) {
            return $this->failure('Invalid or expired two-factor token.', 401);
        }

        return DB::transaction(function () use ($request, $service, $user, $code, $link) {
            $user->newQuery()->whereKey($user->getKey())->lockForUpdate()->firstOrFail();
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
        $request->validate([
            'two_factor_token' => 'required|string|min:100|max:2048|regex:/\A[a-zA-Z0-9+\/=]+\z/',
            'factor_id' => 'required|integer',
        ]);
        $service = app(TwoFactorService::class);
        $challenge = $service->challenge($request->two_factor_token);
        $factor = $challenge ? AuthFactor::find($challenge->factor_id) : null;
        $user = $factor?->authenticatable;
        if (! $user || $challenge->purpose !== 'login') {
            return $this->failure('Invalid or expired two-factor token.', 401);
        }

        return DB::transaction(function () use ($user, $request, $service, $factor) {
            $factors = $service->lockFactors($user);
            $currentFactor = $factors->find($factor->id);
            $challenge = $service->challenge($request->two_factor_token);
            if (! $challenge || ! $currentFactor || ! $service->current($user, $currentFactor, $challenge)) {
                return $this->failure('Invalid or expired two-factor token.', 401);
            }
            $pending = $service->issue(
                $user,
                'login',
                HookAction::from($challenge->action),
                $request->integer('factor_id')
            );
            if ($pending === null) {
                return $this->failure('Confirmed factor not found.', 422);
            }

            return $this->success($pending, 'Challenge issued.');
        });
    }
}
