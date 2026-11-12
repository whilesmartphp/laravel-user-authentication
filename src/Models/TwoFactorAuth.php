<?php

namespace Whilesmart\UserAuthentication\Models;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\MorphTo;

/**
 * @property int $id
 * @property int $authenticatable_id
 * @property string $authenticatable_type
 * @property int|null $last_used_step
 * @property int $setup_attempts
 * @property int $policy_version
 * @property-read User|null $authenticatable
 * @property string|null $secret
 * @property string $type
 * @property bool $is_enabled
 * @property array|null $recovery_codes
 * @property \Illuminate\Support\Carbon|null $confirmed_at
 *
 * @mixin \Illuminate\Database\Eloquent\Builder
 */
class TwoFactorAuth extends Model
{
    protected $hidden = ['secret', 'recovery_codes'];

    protected $fillable = [
        'last_used_step',
        'setup_attempts',
        'secret',
        'type',
        'is_enabled',
        'confirmed_at',
        'recovery_codes',
    ];

    protected static function booted(): void
    {
        static::updating(function (self $factor) {
            if ($factor->isDirty(['type', 'is_enabled', 'secret', 'confirmed_at'])) {
                $factor->policy_version = ($factor->policy_version ?? 0) + 1;
            }
        });
    }

    /**
     * The attributes that should be cast.
     */
    protected function casts(): array
    {
        return [
            'is_enabled' => 'boolean',
            'last_used_step' => 'integer',
            'setup_attempts' => 'integer',
            'policy_version' => 'integer',
            'confirmed_at' => 'datetime',
            'recovery_codes' => 'encrypted:array',
            'secret' => 'encrypted',
        ];
    }

    /**
     * Get the parent authenticatable model (User, Admin, etc.).
     *
     * @return MorphTo<Model, $this>
     */
    public function authenticatable(): MorphTo
    {
        return $this->morphTo();
    }
}
