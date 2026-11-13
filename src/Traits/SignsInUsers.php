<?php

namespace Whilesmart\UserAuthentication\Traits;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;
use Whilesmart\UserAuthentication\Enums\HookAction;
use Whilesmart\UserAuthentication\Events\UserLoggedInEvent;
use Whilesmart\UserAuthentication\Services\TwoFactorService;

trait SignsInUsers
{
    private function signIn(
        Request $request,
        Model&Authenticatable $user,
        HookAction $action,
        int $status = 200
    ): JsonResponse {
        return DB::transaction(function () use ($request, $user, $action, $status) {
            $user->newQuery()->whereKey($user->getKey())->lockForUpdate()->firstOrFail();
            $user->refresh();
            $service = app(TwoFactorService::class);
            $pending = $service->issue($user, 'login', $action);
            if ($pending !== null) {
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
