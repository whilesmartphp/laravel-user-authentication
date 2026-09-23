<?php

namespace Whilesmart\UserAuthentication\Http\Controllers\Auth;

use Illuminate\Http\Request;
use Illuminate\Routing\Controller;
use Whilesmart\UserAuthentication\Models\MagicLink;
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

        if ($user->hasTwoFactorEnabled()) {
            return $this->failure('Two-factor authentication is already enabled.', 400);
        }

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
     * Disable 2fa.
     *
     * - TOTP: requires a TOTP code or recovery code.
     * - Email/phone: first call sends a verification code and returns a pending
     *   token; second call verifies the code and disables 2FA.
     */
    public function disable(Request $request)
    {
        $request->validate([
            'code' => 'nullable|string',
            'two_factor_token' => 'nullable|string',
        ]);

        /** @var \Whilesmart\UserAuthentication\Models\User $user */
        $user = $request->user();

        if (! $user->hasTwoFactorEnabled()) {
            return $this->failure('Two-factor authentication is not enabled.', 400);
        }

        $type = $user->twoFactorAuth->type;

        if ($type === 'totp') {
            return $this->disableTotp($user, $request->code);
        }

        return $this->disableEmailOrPhone($user, $type, $request);
    }

    /**
     * Disable TOTP-based 2FA.
     */
    private function disableTotp($user, ?string $code): \Illuminate\Http\JsonResponse
    {
        $recoveryCodes = $user->twoFactorAuth->recovery_codes;

        // If the user has exhausted their recovery codes, allow disabling 2FA with
        // just the bearer token so they are not permanently locked out.
        if (is_array($recoveryCodes) && $recoveryCodes === []) {
            $user->twoFactorAuth()->delete();

            return $this->success([
                'message' => 'Two-factor authentication has been disabled.',
            ]);
        }

        if (! $code) {
            return $this->failure('A TOTP code or recovery code is required.', 422);
        }

        $recoveryCodes ??= [];

        // Recovery codes can be used to disable 2FA when the authenticator device is lost.
        if (strlen($code) > 6) {
            if (in_array($code, $recoveryCodes)) {
                $user->twoFactorAuth()->delete();

                return $this->success([
                    'message' => 'Two-factor authentication has been disabled using a recovery code.',
                ]);
            }

            return $this->failure('Invalid or expired recovery code.', 422);
        }

        $google2fa = app('pragmarx.google2fa');
        if ($google2fa->verifyKey($user->twoFactorAuth->secret, $code)) {
            $user->twoFactorAuth()->delete();

            return $this->success(['message' => 'Two-factor authentication has been disabled.']);
        }

        return $this->failure('Invalid code. Could not disable 2FA.', 422);
    }

    /**
     * Disable email/phone-based 2FA.
     */
    private function disableEmailOrPhone($user, string $type, Request $request): \Illuminate\Http\JsonResponse
    {
        $contact = ($type === 'phone') ? $user->phone : $user->email;
        $service = app(TwoFactorService::class);

        if ($request->code && $request->two_factor_token) {
            $payload = $service->decodePendingToken($request->two_factor_token);

            if (
                ! $payload
                || $payload['user_id'] !== $user->id
                || $payload['type'] !== $type
                || $payload['contact'] !== $contact
            ) {
                return $this->failure('Invalid or expired two-factor token.', 401);
            }

            if (! $service->verifyCode($contact, $request->code, $type, 'disable_2fa')) {
                return $this->failure('Invalid or expired code.', 422);
            }

            $user->twoFactorAuth()->delete();

            return $this->success(['message' => 'Two-factor authentication has been disabled.']);
        }

        $service->handleChallenge($user, $type, $contact, 'disable_2fa', false);

        return $this->success([
            'two_factor_required' => true,
            'method' => $type,
            'two_factor_token' => $service->generatePendingToken($user, $contact, $type),
        ], 'A verification code has been sent to complete 2FA disable.');
    }

    /**
     * Build a successful authentication response consistent with AuthController@login.
     */
    private function authSuccessResponse($user, string $message): \Illuminate\Http\JsonResponse
    {
        return $this->success([
            'token' => $user->createToken('auth-token', ['2fa-verified'])->plainTextToken,
            'token_type' => 'Bearer',
            'user' => $user,
        ], $message);
    }

    /**
     * Verify the 2FA code (TOTP or Email/SMS)
     */
    public function verify(Request $request)
    {
        $request->validate([
            'two_factor_token' => 'required|string',
            'code' => 'required|string',
        ]);

        $service = app(TwoFactorService::class);
        $payload = $service->decodePendingToken($request->two_factor_token);

        if (! $payload) {
            return $this->failure('Invalid or expired two-factor token.', 401);
        }

        $userModel = config('user-authentication.user_model', \Whilesmart\UserAuthentication\Models\User::class);
        $user = $userModel::find($payload['user_id']);

        if (! $user) {
            return $this->failure('User no longer exists.', 404);
        }

        $contact = $payload['contact'];
        $type = $payload['type'];

        // CASE 1: TOTP including recovery codes
        if ($user->twoFactorAuth && $user->twoFactorAuth->type === 'totp') {
            // recovery codes logic
            if (strlen($request->code) > 6) {
                // Might be a recovery code, check if it matches any of the valid recovery codes
                $recoveryCodes = $user->twoFactorAuth->recovery_codes ?? [];
                if (in_array($request->code, $recoveryCodes)) {
                    // If it's a valid recovery code, remove it from the list so it can't be reused.
                    // Use the loaded model instance so Eloquent's encrypted:array cast is honored.
                    $updatedCodes = array_values(array_diff($recoveryCodes, [$request->code]));
                    $user->twoFactorAuth->update(['recovery_codes' => $updatedCodes]);

                    return $this->completeVerification($user);
                } else {
                    return $this->failure('Invalid or expired code.', 422);
                }
            } else {
                // Regular TOTP verification
                try {
                    $google2fa = app('pragmarx.google2fa');
                    $valid = $google2fa->verifyKey(
                        $user->twoFactorAuth->secret, // Eloquent 'encrypted' cast handles decryption
                        $request->code
                    );
                    // Check if valid
                    if (! $valid) {
                        return $this->failure('Invalid code.', 422);
                    }
                } catch (\Illuminate\Contracts\Encryption\DecryptException $e) {
                    return $this->failure(
                        'The provided security token is invalid or the encryption key has changed.',
                        422
                    );
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
        return $this->authSuccessResponse($user, 'Authenticated successfully.');
    }

    public function completeVerification($user)
    {
        return $this->authSuccessResponse($user, 'Authenticated successfully using recovery code.');
    }

    public function verifyLink(Request $request)
    {
        // get link that has not been used and matches the hashed token in the request
        $link = MagicLink::where('token', hash('sha256', (string) $request->token))
            ->where('is_used', false)
            ->first();

        // 1. Check if the URL signature is valid
        if (! $link || $link->isExpired()) {
            return $this->failure('The link has expired or is invalid.', 403);
        }

        // 2. Find the user based on the link
        $user = $link->user;

        $link->update(['is_used' => true]);

        return $this->authSuccessResponse($user, 'Authenticated successfully using magic link.');
    }

    /**
     * Resend the 2FA code (for email/SMS types)
     */
    public function resend(Request $request)
    {
        $request->validate(['two_factor_token' => 'required|string']);

        $service = app(TwoFactorService::class);
        $payload = $service->decodePendingToken($request->two_factor_token);

        if (! $payload) {
            return $this->failure('Invalid or expired two-factor token.', 401);
        }

        if ($payload['type'] === 'totp') {
            return $this->failure('TOTP codes are generated by your authenticator app.', 400);
        }

        $userModel = config('user-authentication.user_model', \Whilesmart\UserAuthentication\Models\User::class);
        $user = $userModel::find($payload['user_id']);

        if (! $user) {
            return $this->failure('User no longer exists.', 404);
        }

        $service->handleChallenge($user, $payload['type'], $payload['contact']);

        return $this->success(message: 'A new verification code has been sent.');
    }
}
