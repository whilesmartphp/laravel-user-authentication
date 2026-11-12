<?php

namespace Whilesmart\UserAuthentication\Models;

use Illuminate\Database\Eloquent\Model;

/**
 * @property string $id
 * @property int $factor_id
 * @property string $token_hash
 * @property string $purpose
 * @property string $method
 * @property string|null $contact
 * @property string $policy
 * @property string $action
 * @property string|null $code_hash
 * @property string|null $link_hash
 * @property int $attempts
 * @property \Illuminate\Support\Carbon $expires_at
 * @property \Illuminate\Support\Carbon|null $consumed_at
 *
 * @mixin \Illuminate\Database\Eloquent\Builder
 */
class TwoFactorChallenge extends Model
{
    public $incrementing = false;

    protected $keyType = 'string';

    protected $guarded = [];

    protected $hidden = ['token_hash', 'code_hash', 'link_hash'];

    protected function casts(): array
    {
        return [
            'expires_at' => 'datetime',
            'consumed_at' => 'datetime',
            'attempts' => 'integer',
            'factor_id' => 'integer',
        ];
    }
}
