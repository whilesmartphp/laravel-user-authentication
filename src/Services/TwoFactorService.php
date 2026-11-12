<?php

namespace Whilesmart\UserAuthentication\Services;

use Illuminate\Support\Facades\Crypt;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Str;
use Whilesmart\UserAuthentication\Enums\HookAction;
use Whilesmart\UserAuthentication\Events\VerificationCodeGeneratedEvent;
use Whilesmart\UserAuthentication\Models\TwoFactorAuth;
use Whilesmart\UserAuthentication\Models\TwoFactorChallenge;
use Whilesmart\UserAuthentication\Models\User;

class TwoFactorService
{
    /**
     * @param User $user
     */
    public function userData($user): array
    {
        return $user->only(['id', 'first_name', 'last_name', 'username', 'email', 'phone', 'email_verified_at']);
    }

    /**
     * @param TwoFactorAuth $factor
     */
    public function policy($factor): string
    {
        return hash('sha256', json_encode([
            $factor->id, $factor->type, $factor->is_enabled, $factor->policy_version,
            $factor->getRawOriginal('secret'), $factor->confirmed_at?->toISOString(),
        ]));
    }

    /**
     * @param User $user
     */
    public function issue($user, string $purpose = 'login', HookAction $action = HookAction::LOGIN): ?array
    {
        return DB::transaction(function () use ($user, $purpose, $action) {
            $factor = $user->twoFactorAuth()->lockForUpdate()->first();
            if (! $factor || ! $factor->is_enabled) {
                return null;
            }
            $contact = $factor->type === 'phone' ? $user->phone : $user->email;
            $id = Str::random(64);
            $token = Crypt::encryptString(json_encode([
                'id' => $id, 'purpose' => $purpose, 'method' => $factor->type,
            ]));
            TwoFactorChallenge::where('factor_id', $factor->id)->delete();
            $challenge = TwoFactorChallenge::create([
                'id' => $id,
                'factor_id' => $factor->id,
                'token_hash' => hash('sha256', $token),
                'purpose' => $purpose,
                'method' => $factor->type,
                'contact' => $contact,
                'policy' => $this->policy($factor),
                'action' => $action->value,
                'attempts' => 0,
                'expires_at' => now()->addMinutes(config('user-authentication.two_factor.expiry_minutes', 5)),
            ]);
            if (in_array($factor->type, ['email', 'phone'], true)) {
                $length = max(4, min(8, (int) config('user-authentication.verification.code_length', 6)));
                $code = str_pad((string) random_int(0, 10 ** $length - 1), $length, '0', STR_PAD_LEFT);
                $link = $purpose === 'login' && config('user-authentication.magic_link.url') ? Str::random(64) : null;
                $challenge->update([
                    'code_hash' => Hash::make($code),
                    'link_hash' => $link ? hash('sha256', $link) : null,
                ]);
                $url = $link ? rtrim(config('user-authentication.magic_link.url'), '/')
                    . '?' . http_build_query(['token' => $link, 'two_factor_token' => $token]) : null;
                VerificationCodeGeneratedEvent::dispatch(
                    $contact,
                    $code,
                    $purpose . '_' . $factor->type,
                    $factor->type,
                    $url
                );
            }

            return ['two_factor_required' => true, 'method' => $factor->type, 'two_factor_token' => $token];
        });
    }

    public function challenge(string $token): ?TwoFactorChallenge
    {
        try {
            $payload = json_decode(Crypt::decryptString($token), true);
            if (! is_array($payload) || ! isset($payload['id'], $payload['purpose'], $payload['method'])) {
                return null;
            }

            return TwoFactorChallenge::whereKey($payload['id'])
                ->where('token_hash', hash('sha256', $token))
                ->where('purpose', $payload['purpose'])
                ->where('method', $payload['method'])
                ->whereNull('consumed_at')
                ->where('expires_at', '>', now())->first();
        } catch (\Illuminate\Contracts\Encryption\DecryptException $e) {
            return null;
        }
    }

    public function accountKey(string $token): string
    {
        $challenge = $this->challenge($token);
        $factor = $challenge ? TwoFactorAuth::whereKey($challenge->factor_id)->first() : null;

        return $factor ? hash('sha256', $factor->authenticatable_type . ':' . $factor->authenticatable_id)
            : hash('sha256', $token);
    }

    /**
     * @param User $user
     * @param TwoFactorAuth $factor
     * @param TwoFactorChallenge $challenge
     */
    public function current($user, $factor, $challenge): bool
    {
        $contact = $factor->type === 'phone' ? $user->phone : $user->email;

        return $factor->is_enabled && $challenge->policy === $this->policy($factor)
            && $challenge->method === $factor->type && $challenge->contact === $contact;
    }

    /**
     * @param TwoFactorAuth $factor
     */
    public function verifyFactor($factor, string $code): bool
    {
        foreach ($factor->recovery_codes ?? [] as $index => $recovery) {
            if (hash_equals($recovery, $code)) {
                $codes = $factor->recovery_codes;
                unset($codes[$index]);
                $factor->update(['recovery_codes' => array_values($codes)]);

                return true;
            }
        }
        if ($factor->type !== 'totp' || ! preg_match('/\A[0-9]{6}\z/', $code)) {
            return false;
        }
        $step = app('pragmarx.google2fa')->verifyKeyNewer($factor->secret, $code, $factor->last_used_step ?? 0);
        if ($step === false) {
            return false;
        }
        $factor->update(['last_used_step' => $step]);

        return true;
    }

    /**
     * @param User $user
     */
    public function consume($user, string $token, string $code, string $purpose = 'login', bool $link = false): ?string
    {
        return DB::transaction(function () use ($user, $token, $code, $purpose, $link) {
            $factor = $user->twoFactorAuth()->lockForUpdate()->first();
            $found = $this->challenge($token);
            if (! $factor || ! $found) {
                return null;
            }
            $challenge = TwoFactorChallenge::whereKey($found->id)->lockForUpdate()->first();
            if (
                ! $challenge || $challenge->consumed_at || $challenge->factor_id !== $factor->id
                || $challenge->purpose !== $purpose || ! $this->current($user, $factor, $challenge)
            ) {
                return null;
            }
            $budget = max(1, (int) config('user-authentication.two_factor.attempts', 5));
            if ($challenge->attempts >= $budget) {
                $challenge->delete();

                return null;
            }
            $challenge->increment('attempts');
            if ($link) {
                $valid = $purpose === 'login' && in_array($factor->type, ['email', 'phone'], true)
                    && $challenge->link_hash && hash_equals($challenge->link_hash, hash('sha256', $code));
            } else {
                $valid = $this->verifyFactor($factor, $code);
                if (! $valid && in_array($factor->type, ['email', 'phone'], true)) {
                    $valid = $challenge->code_hash && Hash::check($code, $challenge->code_hash);
                }
            }
            if (! $valid) {
                if ($challenge->attempts >= $budget) {
                    $challenge->delete();
                }

                return null;
            }
            // A successful hash check alone cannot authorize concurrent consumers.
            $consumed = TwoFactorChallenge::whereKey($challenge->id)
                ->whereNull('consumed_at')->where('attempts', $challenge->attempts)
                ->where('expires_at', '>', now())
                ->update(['consumed_at' => now(), 'code_hash' => null, 'link_hash' => null]);
            if ($consumed !== 1) {
                return null;
            }
            if ($purpose === 'disable_2fa') {
                $factor->delete();
                $user->tokens()->delete();
            }

            return $challenge->action;
        });
    }
}
