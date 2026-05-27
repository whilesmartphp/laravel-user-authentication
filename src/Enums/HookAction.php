<?php

namespace Whilesmart\UserAuthentication\Enums;

/**
 * @codeCoverageIgnore
 */
enum HookAction: string
{
    case REGISTER = 'register';
    case LOGIN = 'login';
    case LOGOUT = 'logout';
    case OAUTH_LOGIN = 'oauthLogin';
    case OAUTH_CALLBACK = 'oauthCallback';
    case PASSWORD_RESET_REQUEST = 'passwordResetRequest';
    case PASSWORD_RESET = 'passwordReset';
    case SEND_VERIFICATION_CODE = 'sendVerificationCode';
    case VERIFY_CODE = 'verifyCode';
    case PASSKEY_LOGIN_OPTIONS = 'passkeyLoginOptions';
    case PASSKEY_REGISTER_OPTIONS = 'passkeyRegisterOptions';
    case PASSKEY_LOGIN = 'passkeyLogin';
    case PASSKEY_REGISTER = 'passkeyRegister';
    case PASSKEY_INDEX = 'passkeyIndex';
    case PASSKEY_DELETE = 'passkeyDelete';

    /**
     * Get all predefined hook actions.
     */
    public static function all(): array
    {
        return array_column(self::cases(), 'value');
    }
}
