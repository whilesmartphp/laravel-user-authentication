<?php

namespace Whilesmart\UserAuthentication\Traits;

use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;
use Whilesmart\UserAuthentication\Enums\HookAction;
use Whilesmart\UserAuthentication\Events\UserLoggedInEvent;
use Whilesmart\UserAuthentication\Models\User;
use Whilesmart\UserAuthentication\Services\TwoFactorService;

trait SignsInUsers
{
    /**
     * @param User $user
     */
    private function signIn(Request $request, $user, HookAction $action, int $status = 200): JsonResponse
    {
        return DB::transaction(function () use ($request, $user, $action, $status) {
            $user = $user->newQuery()->whereKey($user->id)->lockForUpdate()->firstOrFail();
            $service = app(TwoFactorService::class);
            if ($user->hasTwoFactorEnabled()) {
                $pending = $service->issue($user, 'login', $action);
                if ($pending === null) {
                    return $this->failure('Two-factor policy changed.', 409);
                }

                return $this->success($pending, 'Two-factor authentication required.');
            }
            UserLoggedInEvent::dispatch($user);
            $response = $this->success([
                'token' => $user->createToken('auth-token')->plainTextToken,
                'token_type' => 'Bearer',
                'user' => $service->userData($user),
            ], 'User successfully logged in', $status);

            return $this->runAfterHooks($request, $response, $action);
        });
    }
}
