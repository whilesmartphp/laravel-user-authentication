<?php

namespace Whilesmart\UserAuthentication\Models;

use Illuminate\Database\Eloquent\Model;

class OauthAccount extends Model
{
    protected $fillable = ['user_id', 'provider'];
}
