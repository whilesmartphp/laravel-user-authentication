<?php

namespace Whilesmart\UserAuthentication\Http\Middleware;

use Closure;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;

class RedirectIfTwoFactorEnabled
{
    /**
     * Handle an incoming request.
     */
    public function handle(Request $request, Closure $next)
    {
        $user = Auth::user();

        if ($user && $user->two_factor_enabled && ! $request->session()->has('2fa:verified')) {
            $userId = $user->id;
            $type = ($user->two_factor_type === 'phone') ? 'phone' : 'email';
            $contact = ($type === 'phone') ? $user->phone : $user->email;

            // 1. Send the code using the existing Service logic
            $service = app(\Whilesmart\UserAuthentication\Services\SmartPingsVerificationService::class);

            if ($service->isEnabled()) {
                // Use SmartPings
                $service->sendVerification($contact, $type);
            } else {
                // Self-Managed fallback (Logic from your AuthController)
                $this->sendSelfManagedCode($contact, $type, $userId);
            }

            Auth::logout();
            $request->session()->put('2fa:user_id', $userId);
            $request->session()->put('2fa:contact', $contact); // Remember contact for verification
            $request->session()->put('2fa:type', $type);

            return response()->json([
                'message' => 'Two-factor authentication required.',
                'two_factor_required' => true,
                'method' => $user->two_factor_type,
            ], 403);
        }

        return $next($request);
    }

    /**
     * Replicating the "Self-Managed" logic from AuthController
     */
    protected function sendSelfManagedCode($contact, $type, $userId)
    {
        $codeLength = config('user-authentication.verification.code_length', 6);
        $code = str_pad(random_int(0, pow(10, $codeLength) - 1), $codeLength, '0', STR_PAD_LEFT);

        \Whilesmart\UserAuthentication\Models\VerificationCode::updateOrCreate(
            ['contact' => $contact, 'purpose' => "login_{$type}"],
            [
                'code' => \Illuminate\Support\Facades\Hash::make($code),
                'expires_at' => now()->addMinutes(config('user-authentication.verification.code_expiry_minutes', 5)),
            ]
        );

        $magicLink = \Illuminate\Support\Facades\URL::temporarySignedRoute(
            '2fa.verify.link',
            now()->addMinutes(15),
            ['user' => $userId]
        );

        \Whilesmart\UserAuthentication\Events\VerificationCodeGeneratedEvent::dispatch($contact, $code, "login_{$type}", $type, $magicLink);

    }
}
