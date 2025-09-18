<?php

namespace Whilesmart\UserAuthentication\Models;

use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;

class VerificationCode extends Model
{
    use HasFactory;

    protected $fillable = ['contact', 'code', 'purpose', 'expires_at', 'verified_at'];

    public $timestamps = true;

    public function isExpired(): bool
    {
        return now()->greaterThan($this->expires_at);
    }

    /**
     * Clean up expired verification codes.
     */
    public static function cleanupExpired(): int
    {
        return static::where('expires_at', '<', now())->delete();
    }

    /**
     * Clean up old verified codes (older than 1 hour).
     */
    public static function cleanupOldVerified(): int
    {
        return static::where('verified_at', '!=', null)
            ->where('verified_at', '<', now()->subHour())
            ->delete();
    }
}
