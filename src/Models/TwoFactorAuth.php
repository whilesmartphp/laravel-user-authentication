<?php

namespace Whilesmart\UserAuthentication\Models;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\MorphTo;

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
            'recovery_codes' => 'encrypted:json',
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
