<?php

namespace Whilesmart\UserAuthentication\Http\Middleware;

use Closure;
use Illuminate\Http\Request;
use Whilesmart\UserAuthentication\Services\TwoFactorService;

class RedirectIfTwoFactorEnabled
{
    /**
     * Handle an incoming request.
     */
    public function handle(Request $request, Closure $next)
    {
        /** @var \Whilesmart\UserAuthentication\Models\User|null $user */
        $user = $request->user();

        if ($user && $user->hasTwoFactorEnabled() && ! $user->tokenCan('2fa-verified')) {
            $type = $user->twoFactorAuth->type;
            $contact = ($type === 'phone') ? $user->phone : $user->email;
            $service = app(TwoFactorService::class);

            $service->handleChallenge($user, $type, $contact);

            return response()->json([
                'message' => 'Two-factor authentication required.',
                'two_factor_required' => true,
                'method' => $type,
                'two_factor_token' => $service->generatePendingToken($user, $contact, $type),
            ], 403);
        }

        return $next($request);
    }
}
