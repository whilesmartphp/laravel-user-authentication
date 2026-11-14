<?php

namespace Whilesmart\UserAuthentication\FactorTypes;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Str;
use Whilesmart\UserAuthentication\Events\VerificationCodeGeneratedEvent;
use Whilesmart\UserAuthentication\Interfaces\FactorType;
use Whilesmart\UserAuthentication\Models\AuthChallenge;
use Whilesmart\UserAuthentication\Models\AuthFactor;

class EmailFactorType implements FactorType
{
    public function key(): string
    {
        return 'email';
    }

    public function needsSecret(): bool
    {
        return false;
    }

    public function uniquePerOwner(): bool
    {
        return true;
    }

    public function contact(Model $owner): ?string
    {
        return $owner->getAttribute($this->key());
    }

    public function setup(AuthFactor $factor): array
    {
        return [];
    }

    public function issue(AuthFactor $factor, AuthChallenge $challenge, string $token): void
    {
        $length = max(4, min(8, (int) config('user-authentication.verification.code_length', 6)));
        $code = str_pad((string) random_int(0, 10 ** $length - 1), $length, '0', STR_PAD_LEFT);
        $link = $challenge->purpose === 'login' && config('user-authentication.magic_link.url')
            ? Str::random(64) : null;
        $challenge->update([
            'code_hash' => Hash::make($code),
            'code_expires_at' => $challenge->expires_at,
            'link_hash' => $link ? hash('sha256', $link) : null,
            'link_expires_at' => $link ? $challenge->expires_at : null,
        ]);
        $url = $link ? rtrim(config('user-authentication.magic_link.url'), '/')
            . '?' . http_build_query(['token' => $link, 'two_factor_token' => $token]) : null;
        VerificationCodeGeneratedEvent::dispatch(
            $this->contact($factor->authenticatable),
            $code,
            $challenge->purpose . '_' . $this->key(),
            $this->key(),
            $url
        );
    }

    public function verify(AuthFactor $factor, string $code, ?AuthChallenge $challenge = null): bool
    {
        return $challenge && $challenge->code_hash && $challenge->code_expires_at?->isFuture()
            && Hash::check($code, $challenge->code_hash);
    }
}
