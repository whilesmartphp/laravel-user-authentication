<?php

namespace Whilesmart\UserAuthentication\Traits;

use Illuminate\Database\Eloquent\Relations\MorphOne;
use Whilesmart\UserAuthentication\Models\TwoFactorAuth;

/**
 * @property int $id
 * @property string $email
 * @property string $password
 * @property string|null $first_name
 * @property string|null $last_name
 * @property string|null $phone
 * @property string|null $two_factor_type
 * @property-read \Whilesmart\UserAuthentication\Models\TwoFactorAuth|null $twoFactorAuth
 * @property-read \Illuminate\Database\Eloquent\Collection|\Whilesmart\UserAuthentication\Models\OauthAccount[] $oauthAccounts
 * @method bool hasTwoFactorEnabled()
 * @mixin \Illuminate\Database\Eloquent\Builder
 */

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
