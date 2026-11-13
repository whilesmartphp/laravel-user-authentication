<?php

namespace Whilesmart\UserAuthentication\Traits;

use Illuminate\Database\Eloquent\Relations\MorphMany;
use Whilesmart\UserAuthentication\Models\AuthFactor;
use Whilesmart\UserAuthentication\Models\RecoveryCode;

trait HasTwoFactorAuth
{
    public function initializeHasTwoFactorAuth(): void
    {
        $this->makeHidden(['factors', 'recoveryCodes', 'recovery_codes']);
    }

    /** @return MorphMany<AuthFactor, $this> */
    public function factors(): MorphMany
    {
        return $this->morphMany(AuthFactor::class, 'authenticatable');
    }

    /** @return MorphMany<RecoveryCode, $this> */
    public function recoveryCodes(): MorphMany
    {
        return $this->morphMany(RecoveryCode::class, 'authenticatable');
    }

    public function hasTwoFactorEnabled(): bool
    {
        return $this->factors()->whereNotNull('confirmed_at')->exists();
    }
}
