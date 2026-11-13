<?php

namespace Whilesmart\UserAuthentication\Http\Middleware;

use Closure;
use Illuminate\Http\Request;
use Laravel\Sanctum\Contracts\HasAbilities;
use Whilesmart\UserAuthentication\Models\User;

class RedirectIfTwoFactorEnabled
{
    public function handle(Request $request, Closure $next)
    {
        /** @var User|null $user */
        $user = $request->user();
        if ($user && $user->hasTwoFactorEnabled()) {
            /** @var HasAbilities|null $token */
            $token = $user->currentAccessToken();
            if (! $token || ! in_array('2fa-verified', $token->abilities ?? [], true)) {
                return response()->json([
                    'message' => 'Two-factor authentication required. Please sign in again.',
                    'two_factor_required' => true,
                ], 403);
            }
        }

        return $next($request);
    }
}
