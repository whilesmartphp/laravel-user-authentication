<?php

namespace Whilesmart\UserAuthentication\Models;

use Illuminate\Database\Eloquent\Model;

/**
 * @property int $id
 * @property int $user_id
 * @property string $token
 * @property \Illuminate\Support\Carbon $expires_at
 * @property bool $is_used
 * @property \Illuminate\Support\Carbon|null $created_at
 * @property \Illuminate\Support\Carbon|null $updated_at
 * @property-read \Whilesmart\UserAuthentication\Models\User $user
 *
 * @method static \Illuminate\Database\Eloquent\Builder|MagicLink whereToken($value)
 *
 * @mixin \Illuminate\Database\Eloquent\Builder
 */
class MagicLink extends Model
{
    protected $fillable = [
        'user_id',
        'token',
        'expires_at',
        'is_used',
    ];

    /**
     * The attributes that should be cast.
     */
    protected function casts(): array
    {
        return [
            'expires_at' => 'datetime',
            'is_used' => 'boolean',
        ];
    }

    /**
     * Get the user that owns the magic link.
     */
    public function user()
    {
        // Use the config value, and fallback to your package's User model
        // if the consumer hasn't defined one.
        return $this->belongsTo(config('user-authentication.user_model', User::class));
    }

    public function isExpired(): bool
    {
        // A link is invalid if the time has passed OR if it was already used.
        return $this->expires_at->isPast() || $this->is_used;
    }
}
