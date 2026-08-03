<?php

namespace Whilesmart\UserAuthentication\Models;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\MorphTo;

/**
 * @property int $id
 * @property int $authenticatable_id
 * @property string $authenticatable_type
 * @property string $secret
 * @property string $type
 * @property bool $is_enabled
 * @property array|null $recovery_codes
 * @property \Illuminate\Support\Carbon|null $confirmed_at
 *
 * @mixin \Illuminate\Database\Eloquent\Builder
 */
class TwoFactorAuth extends Model
{
    protected $fillable = [
        'secret',
        'type',
        'is_enabled',
        'confirmed_at',
        'recovery_codes',
    ];

    /**
     * The attributes that should be cast.
     */
    protected function casts(): array
    {
        return [
            'is_enabled' => 'boolean',
            'confirmed_at' => 'datetime',
            'recovery_codes' => 'encrypted:array',
            'secret' => 'encrypted',
        ];
    }

    /**
     * Get the parent authenticatable model (User, Admin, etc.).
     */
    public function authenticatable(): MorphTo
    {
        return $this->morphTo();
    }
}
