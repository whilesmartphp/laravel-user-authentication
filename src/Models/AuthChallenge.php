<?php

namespace Whilesmart\UserAuthentication\Models;

use Illuminate\Database\Eloquent\Builder;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Prunable;

/**
 * @property string|null $authenticatable_type
 * @property int|null $authenticatable_id
 * @property string $id
 * @property \Illuminate\Support\Carbon|null $code_expires_at
 * @property \Illuminate\Support\Carbon|null $link_expires_at
 * @property int|null $factor_id
 * @property string $token_hash
 * @property string $purpose
 * @property string $method
 * @property string|null $contact
 * @property string|null $policy
 * @property string|null $action
 * @property string|null $code_hash
 * @property string|null $link_hash
 * @property int $attempts
 * @property \Illuminate\Support\Carbon $expires_at
 * @property \Illuminate\Support\Carbon|null $consumed_at
 *
 * @mixin \Illuminate\Database\Eloquent\Builder
 */
class AuthChallenge extends Model
{
    use Prunable;

    public $incrementing = false;

    protected $keyType = 'string';

    protected $guarded = [];

    protected $hidden = ['token_hash', 'code_hash', 'link_hash'];

    /** @return Builder<static> */
    public function prunable(): Builder
    {
        return static::query()->where('expires_at', '<=', now()->subHours(
            max(0, (int) config('user-authentication.two_factor.challenge_retention_hours', 24))
        ));
    }

    protected function casts(): array
    {
        return [
            'expires_at' => 'datetime',
            'code_expires_at' => 'datetime',
            'link_expires_at' => 'datetime',
            'metadata' => 'array',
            'consumed_at' => 'datetime',
            'attempts' => 'integer',
            'factor_id' => 'integer',
        ];
    }
}
