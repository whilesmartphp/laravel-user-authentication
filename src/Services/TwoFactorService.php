<?php

namespace Whilesmart\UserAuthentication\Services;

use Illuminate\Support\Facades\Crypt;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Str;
use Whilesmart\UserAuthentication\Events\VerificationCodeGeneratedEvent;
use Whilesmart\UserAuthentication\Models\MagicLink;
use Whilesmart\UserAuthentication\Models\VerificationCode;

class TwoFactorService
{
    /**
     * Handle the 2FA challenge flow (sending codes or magic links).
     */
    public function handleChallenge(
        $user,
        string $type,
        string $contact,
        string $purpose = 'login',
        bool $sendMagicLink = true
    ): void {
        $smartPings = app(SmartPingsVerificationService::class);

        if ($type === 'totp') {
            // TOTP is handled by the device app, no code or magic link needs to be sent.
            return;
        }

        if ($smartPings->isEnabled()) {
            $smartPings->sendVerification($contact, $type);

            return;
        }

        // Default: Generate and send our own code/link
        $this->sendSelfManagedChallenge($user, $type, $contact, $purpose, $sendMagicLink);
    }

    /**
     * Consolidate verification logic (Review Point 7)
     */
    public function verifyCode(string $contact, string $code, string $type, string $purpose = 'login'): bool
    {
        $smartPings = app(SmartPingsVerificationService::class);

        if ($smartPings->isEnabled()) {
            return $smartPings->verify($contact, $code, $type);
        }

        $codeEntry = VerificationCode::where('contact', $contact)
            ->where('purpose', "{$purpose}_{$type}")
            ->first();

        if (!$codeEntry || $codeEntry->isExpired()) {
            return false;
        }

        if (!Hash::check($code, $codeEntry->code)) {
            return false;
        }

        // Invalidate the code immediately to prevent replay attacks.
        $codeEntry->delete();

        return true;
    }

    /**
     * Create a short-lived, server-verifiable pending-2FA token.
     */
    public function generatePendingToken($user, string $contact, string $type): string
    {
        $expiryMinutes = config('user-authentication.verification.code_expiry_minutes', 5);

        return Crypt::encryptString(json_encode([
            'user_id' => $user->id,
            'contact' => $contact,
            'type' => $type,
            'expires_at' => now()->addMinutes($expiryMinutes)->toDateTimeString(),
        ]));
    }

    /**
     * Decode and validate a pending-2FA token.
     *
     * @return array<string, mixed>|null
     */
    public function decodePendingToken(string $token): ?array
    {
        try {
            $payload = json_decode(Crypt::decryptString($token), true);

            if (! is_array($payload) || empty($payload['expires_at'])) {
                return null;
            }

            if (now()->greaterThan($payload['expires_at'])) {
                return null;
            }

            return $payload;
        } catch (\Illuminate\Contracts\Encryption\DecryptException $e) {
            return null;
        }
    }

    /**
     * Generate code and magic link, persist them, and dispatch the event.
     */
    protected function sendSelfManagedChallenge(
        $user,
        string $type,
        string $contact,
        string $purpose = 'login',
        bool $sendMagicLink = true
    ): void {
        // 1. Generate the numeric code
        $codeLength = config('user-authentication.verification.code_length', 6);
        $code = str_pad((string)random_int(0, pow(10, $codeLength) - 1), $codeLength, '0', STR_PAD_LEFT);

        $expiry = config('user-authentication.verification.code_expiry_minutes', 5);

        // 2. Persist the numeric code
        VerificationCode::updateOrCreate(
            ['contact' => $contact, 'purpose' => "{$purpose}_{$type}"],
            [
                'code' => Hash::make($code),
                'expires_at' => now()->addMinutes($expiry),
            ]
        );

        $magicLinkUrl = null;

        // 3. Generate a magic link token, store its hash, and build the URL
        if ($sendMagicLink) {
            $rawToken = Str::random(64);
            MagicLink::create([
                'user_id' => $user->id,
                'token' => hash('sha256', $rawToken),
                'expires_at' => now()->addMinutes(config('user-authentication.magic_link.expiry_minutes', 15)),
            ]);

            $magicLinkUrl = rtrim(config('user-authentication.magic_link.url'), '/')
                . '?' . http_build_query(['token' => $rawToken]);
        }

        // 4. Dispatch Event (Addressing Review Point 4: Code is no longer null)
        VerificationCodeGeneratedEvent::dispatch($contact, $code, "{$purpose}_{$type}", $type, $magicLinkUrl);
    }
}
