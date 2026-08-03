<?php

namespace Whilesmart\UserAuthentication\Http\Middleware;

use Closure;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
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

        if ($user && $user->hasTwoFactorEnabled() && ! $request->session()->has('2fa:verified')) {
            $userId = $user->id;
            $type = $user->twoFactorAuth->type;
            $contact = ($type === 'phone') ? $user->phone : $user->email;

            // use service
            app(TwoFactorService::class)->handleChallenge($user, $type, $contact);

            Auth::logout();
            $request->session()->put('2fa:user_id', $userId);
            $request->session()->put('2fa:contact', $contact); // Remember contact for verification
            $request->session()->put('2fa:type', $type);

            return response()->json([
                'message' => 'Two-factor authentication required.',
                'two_factor_required' => true,
                'method' => $type,
            ], 403);
        }

        return $next($request);
    }
}
