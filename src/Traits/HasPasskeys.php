<?php

namespace Whilesmart\UserAuthentication\Traits;

use Illuminate\Database\Eloquent\Relations\MorphMany;
use Whilesmart\UserAuthentication\Models\Passkey;

trait HasPasskeys
{
    public function passkeys(): MorphMany
    {
        return $this->morphMany(Passkey::class, 'keyable');
    }
}
