<?php

namespace Whilesmart\UserAuthentication\Traits;

use Whilesmart\UserAuthentication\Models\TwoFactorAuth;
use Illuminate\Database\Eloquent\Relations\MorphOne;

trait HasTwoFactorAuth
{
    /**
     * Link to the 2FA settings.
     */
    public function twoFactorAuth(): MorphOne
    {
        return $this->morphOne(TwoFactorAuth::class, 'authenticatable');
    }

    /**
     * Helper to check if 2FA is actually active.
     */
    public function hasTwoFactorEnabled(): bool
    {
        return $this->twoFactorAuth && $this->twoFactorAuth->is_enabled;
    }
}