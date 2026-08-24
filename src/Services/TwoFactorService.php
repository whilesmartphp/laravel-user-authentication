<?php

namespace Whilesmart\UserAuthentication\Services;

use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\URL;
use Illuminate\Support\Str;
use Whilesmart\UserAuthentication\Events\VerificationCodeGeneratedEvent;
use Whilesmart\UserAuthentication\Models\MagicLink;
use Whilesmart\UserAuthentication\Models\VerificationCode;

class TwoFactorService
{
    /**
     * Handle the 2FA challenge flow (sending codes or magic links).
     */
    public function handleChallenge($user, string $type, string $contact): void
    {
        $smartPings = app(SmartPingsVerificationService::class);

        if ($type === 'totp') {
            // TOTP is handled by the device app, no code needs to be sent.
            return;
        }

        if ($smartPings->isEnabled()) {
            $smartPings->sendVerification($contact, $type);

            return;
        }

        // Default: Generate and send our own code/link
        $this->sendSelfManagedChallenge($user, $type, $contact);
    }

    /**
     * Consolidate verification logic (Review Point 7)
     */
    public function verifyCode(string $contact, string $code, string $type): bool
    {
        $smartPings = app(SmartPingsVerificationService::class);

        if ($smartPings->isEnabled()) {
            return $smartPings->verify($contact, $code, $type);
        }

        $codeEntry = VerificationCode::where('contact', $contact)
            ->where('purpose', "login_{$type}")
            ->first();

        if (! $codeEntry || $codeEntry->isExpired()) {
            return false;
        }

        if (! Hash::check($code, $codeEntry->code)) {
            return false;
        }

        // Invalidate the code immediately to prevent replay attacks.
        $codeEntry->delete();

        return true;
    }

    /**
     * Generate code and magic link, persist them, and dispatch the event.
     */
    protected function sendSelfManagedChallenge($user, string $type, string $contact): void
    {
        // 1. Generate the numeric code
        $codeLength = config('user-authentication.verification.code_length', 6);
        $code = str_pad((string) random_int(0, pow(10, $codeLength) - 1), $codeLength, '0', STR_PAD_LEFT);

        $expiry = config('user-authentication.verification.code_expiry_minutes', 5);

        // 2. Persist the numeric code
        VerificationCode::updateOrCreate(
            ['contact' => $contact, 'purpose' => "login_{$type}"],
            [
                'code' => Hash::make($code),
                'expires_at' => now()->addMinutes($expiry),
            ]
        );

        // 3.Instead of just a signed URL, we save it to the new table we created
        $token = Str::random(64);
        MagicLink::create([
            'user_id' => $user->id,
            'token' => $token,
            'expires_at' => now()->addMinutes(config('user-authentication.magic_link.expiry_minutes', 15)),
        ]);

        $magicLinkUrl = URL::temporarySignedRoute(
            '2fa.verify.link',
            now()->addMinutes(config('user-authentication.magic_link.expiry_minutes', 15)),
            ['user' => $user->id, 'token' => $token]
        );

        // 4. Dispatch Event (Addressing Review Point 4: Code is no longer null)
        VerificationCodeGeneratedEvent::dispatch($contact, $code, "login_{$type}", $type, $magicLinkUrl);
    }
}
