<?php

namespace Whilesmart\UserAuthentication\Models;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\MorphTo;

/**
 * @property int $id
 * @property int $authenticatable_id
 * @property string $authenticatable_type
 * @property int|null $last_used_step
 * @property int $setup_attempts
 * @property-read (Model&Authenticatable)|null $authenticatable
 * @property string|null $secret
 * @property string|null $label
 * @property \Illuminate\Support\Carbon|null $last_used_at
 * @property string $type
 * @property \Illuminate\Support\Carbon|null $confirmed_at
 *
 * @mixin \Illuminate\Database\Eloquent\Builder
 */
class AuthFactor extends Model
{
    protected $hidden = ['secret'];

    protected $guarded = [];

    protected static function booted(): void
    {
        static::saved(function (self $factor) {
            if (
                $factor->isDirty('confirmed_at')
                || ($factor->confirmed_at !== null
                    && $factor->isDirty(['type', 'secret']))
            ) {
                static::invalidateChallenges($factor);
            }
        });

        static::deleted(function (self $factor) {
            if ($factor->confirmed_at !== null) {
                static::invalidateChallenges($factor);
            }
            $owner = $factor->authenticatable;
            if ($owner && ! $owner->morphMany(self::class, 'authenticatable')->whereNotNull('confirmed_at')->exists()) {
                $owner->morphMany(RecoveryCode::class, 'authenticatable')->delete();
            }
        });
    }

    protected static function invalidateChallenges(self $factor): void
    {
        AuthChallenge::where('authenticatable_type', $factor->authenticatable_type)
            ->where('authenticatable_id', $factor->authenticatable_id)
            ->whereNull('consumed_at')
            ->update(['policy' => null]);
    }

    protected function casts(): array
    {
        return [
            'last_used_step' => 'integer',
            'setup_attempts' => 'integer',
            'confirmed_at' => 'datetime',
            'last_used_at' => 'datetime',
            'metadata' => 'array',
            'secret' => 'encrypted',
        ];
    }

    /** @return MorphTo<Model, $this> */
    public function authenticatable(): MorphTo
    {
        return $this->morphTo();
    }
}
