<?php

namespace Whilesmart\UserAuthentication\Http\Controllers\Auth;

use Illuminate\Http\Request;
use Illuminate\Routing\Controller;
use Illuminate\Support\Facades\Auth;
use Whilesmart\UserAuthentication\Services\TwoFactorService;
use Whilesmart\UserAuthentication\Traits\ApiResponse;

/**
 * @uses \Whilesmart\UserAuthentication\Models\User
 */

class TwoFactorController extends Controller
{
    use ApiResponse;

    /**
     * setup,qr code and confirmation
     */
    public function setup(Request $request)
    {
        /** @var \Whilesmart\UserAuthentication\Models\User $user */
        $user = $request->user();

        // generate fresh secret
        $google2fa = app('pragmarx.google2fa');
        $secret = $google2fa->generateSecretKey();

        // store it via the polymorphic relationship
        // 'is_enabled' stays FALSE till user confirms the code from their app
        $user->twoFactorAuth()->updateOrCreate(
            ['authenticatable_id' => $user->id, 'authenticatable_type' => get_class($user)],
            ['secret' => $secret, 'type' => 'totp', 'is_enabled' => false]
        );

        // provide the otpauth URI for QR code generation on the frontend
        $qrCodeUrl = $google2fa->getQRCodeUrl(
            config('app.name'),
            $user->email,
            $secret
        );

        return $this->success([
            'secret' => $secret,
            'qr_code_url' => $qrCodeUrl,
            'help_text' => 'Scan the QR code with your authenticator app & enter the generated code to confirm setup.',
        ], 'Two-factor authentication setup initiated. Please confirm with your authenticator app.');
    }

    /**
     * Confirm the TOTP code during setup
     * prevents users from accidentally locking themselves out.
     * is_enabled only turns true if user can prove they have the correct code from their app.
     */
    public function confirm(Request $request)
    {
        $request->validate(['code' => 'required|string']);

        /** @var \Whilesmart\UserAuthentication\Models\User $user */
        $user = $request->user();

        // check if they actually started setup
        $twoFactor = $user->twoFactorAuth;
        if (! $twoFactor || ! $twoFactor->secret) {
            return $this->failure('2FA setup has not been initiated.', 400);
        }
        $google2fa = app('pragmarx.google2fa');

        // verify the code provided by the user's app
        if ($google2fa->verifyKey($twoFactor->secret, $request->code)) {
            // Generate recovery codes
            $recoveryCodes = collect(range(1, 8))->map(fn () => \Illuminate\Support\Str::random(10))->toArray();

            $twoFactor->update([
                'is_enabled' => true,
                'confirmed_at' => now(),
                'recovery_codes' => $recoveryCodes,
            ]);

            return $this->success([
                'message' => 'Two-factor authentication has been enabled successfully.',
                'recovery_codes' => $recoveryCodes,
                'help_text' => 'Store these recovery codes incase you lose access to your authenticator app.',
            ]);
        }

        return $this->failure('Invalid code. Please try again.', 422);
    }

    /**
     * Disable 2fa
     */
    public function disable(Request $request)
    {
        $request->validate(['code' => 'required|string']);

        /** @var \Whilesmart\UserAuthentication\Models\User $user */
        $user = $request->user();

        if (! $user->hasTwoFactorEnabled()) {
            return $this->failure('Two-factor authentication is not enabled.', 400);
        }

        $google2fa = app('pragmarx.google2fa');
        if ($google2fa->verifyKey($user->twoFactorAuth->secret, $request->code)) {
            $user->twoFactorAuth()->delete(); // remove the record on table

            return $this->success(['message' => 'Two-factor authentication has been disabled.']);
        }

        return $this->failure('Invalid code. Could not disable 2FA.', 422);
    }

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

        /** @var \Whilesmart\UserAuthentication\Models\User $user */
        $user = \Whilesmart\UserAuthentication\Models\User::find($userId);

        // CASE 1: TOTP including recovery codes
        if ($user->twoFactorAuth && $user->twoFactorAuth->type === 'totp') {
            // recovery codes logic
            if (strlen($request->code) > 6) {
                // Might be a recovery code, check if it matches any of the valid recovery codes
                $recoveryCodes = $user->twoFactorAuth->recovery_codes ?? [];
                if (in_array($request->code, $recoveryCodes)) {
                    // If it's a valid recovery code, remove it from the list so it can't be reused
                    $updatedCodes = array_diff($recoveryCodes, [$request->code]);
                    $user->twoFactorAuth()->update(['recovery_codes' => $updatedCodes]);

                    return $this->completeVerification($user);
                } else {
                    return $this->failure('Invalid or expired code.', 422);
                }
            } else {
                // Regular TOTP verification
                try {
                    $valid = \PragmaRX\Google2FALaravel\Facade::verifyKey(
                        $user->twoFactorAuth->secret, // Eloquent 'encrypted' cast handles decryption
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
            // CASE 2: Handled by the Service to keep Controller thin
        } else {
            $service = app(TwoFactorService::class);
            if (! $service->verifyCode($contact, $request->code, $type)) {
                return $this->failure('Invalid or expired code.', 422);
            }
        }

        // AUTH SUCCESS
        Auth::login($user);
        $token = $user->createToken('auth-token')->plainTextToken;
        session()->forget(['2fa:user_id', '2fa:contact', '2fa:type']);
        session(['2fa:verified' => true]);

        return response()->json(['message' => 'Authenticated successfully.', 'token' => $token]);
    }

    public function completeVerification($user)
    {
        Auth::login($user);
        $token = $user->createToken('auth-token')->plainTextToken;
        session()->forget(['2fa:user_id', '2fa:contact', '2fa:type']);
        session(['2fa:verified' => true]);

        return response()->json(['message' => 'Authenticated successfully using recovery code.', 'token' => $token]);
    }

    public function verifyLink(Request $request)
    {
        // get link that has not been used and matches the token in the request
        $link = \Whilesmart\UserAuthentication\Models\MagicLink::where('token', $request->token)
            ->where('is_used', false)
            ->first();

        // 1. Check if the URL signature is valid
        if (! $link || $link->isExpired() || ! $request->hasValidSignature()) {
            return $this->failure('The link has expired or is invalid.', 403);
        }

        // 2. Find the user based on the link
        $user = $link->user;
        // 3. Log them in and set the 2FA verified flag
        Auth::guard('web')->login($user);

        $link->update(['is_used' => true]);
        session(['2fa:verified' => true]);

        // 4. Redirect them or send a success JSON
        // Since this is likely an API package, you might redirect to your frontend dashboard
        $dashboardUrl = config('user-authentication.dashboard_url', '/dashboard');

        return redirect()->away($dashboardUrl);
    }

    /**
     * Resend the 2FA code (for email/SMS types)
     */
    public function resend()
    {
        $userId = session('2fa:user_id');
        $contact = session('2fa:contact');
        $type = session('2fa:type');

        if (! $userId) {
            return response()->json(['message' => 'Session expired.'], 401);
        }

        $user = \Whilesmart\UserAuthentication\Models\User::find($userId);

        if ($type === 'totp') {
            return response()->json(['message' => 'TOTP codes are generated by your authenticator app.'], 400);
        }

        app(TwoFactorService::class)->handleChallenge($user, $type, $contact);

        return response()->json(['message' => 'A new verification code has been sent.']);
    }
}
