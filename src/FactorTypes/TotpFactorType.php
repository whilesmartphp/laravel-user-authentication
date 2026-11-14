<?php

namespace Whilesmart\UserAuthentication\FactorTypes;

use Illuminate\Database\Eloquent\Model;
use Whilesmart\UserAuthentication\Interfaces\FactorType;
use Whilesmart\UserAuthentication\Models\AuthChallenge;
use Whilesmart\UserAuthentication\Models\AuthFactor;

class TotpFactorType implements FactorType
{
    public function key(): string
    {
        return 'totp';
    }

    public function needsSecret(): bool
    {
        return true;
    }

    public function uniquePerOwner(): bool
    {
        return false;
    }

    public function contact(Model $owner): ?string
    {
        return null;
    }

    public function setup(AuthFactor $factor): array
    {
        $google = app('pragmarx.google2fa');
        $factor->update(['secret' => $google->generateSecretKey()]);

        return [
            'secret' => $factor->secret,
            'qr_code_url' => $google->getQRCodeUrl(
                config('app.name'),
                $factor->authenticatable->getAttribute('email'),
                $factor->secret
            ),
        ];
    }

    public function issue(AuthFactor $factor, AuthChallenge $challenge, string $token): void
    {
        $challenge->update(['code_expires_at' => $challenge->expires_at]);
    }

    public function verify(AuthFactor $factor, string $code, ?AuthChallenge $challenge = null): bool
    {
        if (! $factor->secret || ! preg_match('/\A[0-9]{6}\z/', $code)) {
            return false;
        }
        $step = app('pragmarx.google2fa')->verifyKeyNewer($factor->secret, $code, $factor->last_used_step ?? 0);
        if ($step === false) {
            return false;
        }
        $factor->update(['last_used_step' => $step]);

        return true;
    }
}
