<?php

namespace Whilesmart\UserAuthentication\Models;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;

class OauthAccount extends Model
{
    protected $fillable = ['user_id', 'provider', 'provider_id', 'avatar_url', 'token'];

    protected $hidden = ['token'];

    protected function casts(): array
    {
        return [
            'token' => config('user-authentication.encrypt_oauth_tokens', false) ? 'encrypted' : 'string',
        ];
    }

    public function user(): BelongsTo
    {
        $userModel = config('user-authentication.user_model', User::class);

        return $this->belongsTo($userModel);
    }
}
