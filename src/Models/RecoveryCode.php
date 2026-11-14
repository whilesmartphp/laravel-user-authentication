<?php

namespace Whilesmart\UserAuthentication\Models;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\MorphTo;

/**
 * @property int $id
 * @property string $code_hash
 * @property \Illuminate\Support\Carbon|null $used_at
 */
class RecoveryCode extends Model
{
    protected $table = 'auth_recovery_codes';

    protected $guarded = [];

    protected $hidden = ['code_hash'];

    protected function casts(): array
    {
        return ['used_at' => 'datetime'];
    }

    /** @return MorphTo<Model, $this> */
    public function authenticatable(): MorphTo
    {
        return $this->morphTo();
    }
}
