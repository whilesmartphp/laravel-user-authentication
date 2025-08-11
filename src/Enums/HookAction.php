<?php

namespace Whilesmart\UserAuthentication\Enums;

enum HookAction: string
{
    case REGISTER = 'register';
    case LOGIN = 'login';
    case LOGOUT = 'logout';
    case OAUTH_LOGIN = 'oauthLogin';
    case OAUTH_CALLBACK = 'oauthCallback';
    case PASSWORD_RESET_REQUEST = 'passwordResetRequest';
    case PASSWORD_RESET = 'passwordReset';

    /**
     * Get all predefined hook actions.
     */
    public static function all(): array
    {
        return array_column(self::cases(), 'value');
    }
}
