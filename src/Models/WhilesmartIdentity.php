<?php

namespace Whilesmart\UserAuthentication\Models;

use Illuminate\Database\Eloquent\Model;

class WhilesmartIdentity extends Model
{
    protected $primaryKey = 'identity_key';

    public $incrementing = false;

    protected $keyType = 'string';

    protected $fillable = ['identity_key', 'issuer', 'subject', 'user_type', 'user_id', 'credentials'];

    protected $hidden = ['credentials', 'subject'];

    protected function casts(): array
    {
        return ['credentials' => 'encrypted:array'];
    }
}
