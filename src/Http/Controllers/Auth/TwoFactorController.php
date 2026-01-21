<?php

namespace Whilesmart\UserAuthentication\Http\Controllers\Auth;

use Illuminate\Http\Request;
use Illuminate\Routing\Controller;
use Illuminate\Support\Facades\Auth;

class TwoFactorController extends Controller
{
    /**
     * Verify the 2FA code (TOTP or Email/SMS)
     */
    public function verify(Request $request)
    {
        $userId = session('2fa:user_id');
        $contact = session('2fa:contact');
        $type = session('2fa:type');

        if (! $userId) {
            return response()->json(['message' => 'Session expired.'], 401);
        }

        $user = \Whilesmart\UserAuthentication\Models\User::find($userId);
        $smartPingsService = app(\Whilesmart\UserAuthentication\Services\SmartPingsVerificationService::class);

        // CASE 1: TOTP
        if ($user->two_factor_type === 'totp') {

            try {
                
                $valid = \PragmaRX\Google2FALaravel\Facade::verifyKey(
                    decrypt($user->two_factor_secret),
                    $request->code
                );
                // Check if valid
                if (! $valid) {
                    return response()->json(['message' => 'Invalid code.'], 422);
                }
            } catch (\Illuminate\Contracts\Encryption\DecryptException $e) {
                return response()->json([
                    'message' => 'The provided security token is invalid or the encryption key has changed.',
                ], 422);
            }
        }
        // CASE 2: SmartPings
        elseif ($smartPingsService->isEnabled()) {
            if (! $smartPingsService->verify($contact, $request->code, $type)) {
                return response()->json(['message' => 'Invalid SmartPings code.'], 422);
            }
        }
        // CASE 3: Self-Managed (Local DB)
        else {
            $codeEntry = \Whilesmart\UserAuthentication\Models\VerificationCode::where('contact', $contact)
                ->where('purpose', "login_{$type}")
                ->first();

            if (! $codeEntry || ! \Illuminate\Support\Facades\Hash::check($request->code, $codeEntry->code) || $codeEntry->isExpired()) {
                return response()->json(['message' => 'Invalid or expired code.'], 422);
            }
        }

        // AUTH SUCCESS
        Auth::login($user);  // Uncomment this to log in the user (required for test assertions)
        $token = $user->createToken('auth-token')->plainTextToken;
        session()->forget(['2fa:user_id', '2fa:contact', '2fa:type']);
        session(['2fa:verified' => true]);

        return response()->json(['message' => 'Authenticated successfully.', 'token' => $token]);

    }

    public function verifyLink(Request $request)
    {
        // 1. Check if the URL signature is valid
        if (! $request->hasValidSignature()) {
            return response()->json(['message' => 'The link has expired or is invalid.'], 403);
        }

        // 2. Find the user from the URL parameter
        $user = \Whilesmart\UserAuthentication\Models\User::findOrFail($request->user);

        // 3. Log them in and set the 2FA flag
        Auth::login($user);
        session(['2fa:verified' => true]);

        // 4. Redirect them or send a success JSON
        // Since this is likely an API package, you might redirect to your frontend dashboard
        $dashboardUrl = config('user-authentication.dashboard_url', '/dashboard');

        return redirect()->away($dashboardUrl);
    }
}
