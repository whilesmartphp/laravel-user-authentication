<?php

return [
    'user_model' => Whilesmart\UserAuthentication\Models\User::class,
    'register_routes' => true,
    'register_oauth_routes' => true,
    'route_prefix' => env('USER_AUTH_ROUTE_PREFIX', 'api'),
    'allow_ios_private_emails' => env('USER_AUTH_ALLOW_IOS_PRIVATE_EMAILS', true),

    'response_formatter' => \Whilesmart\UserAuthentication\ResponseFormatters\DefaultResponseFormatter::class,

    'oauth_scopes' => [
        // 'github' => ['read:user', 'user:email'],
        // 'google' => ['openid', 'profile', 'email'],
    ],

    'encrypt_oauth_tokens' => env('USER_AUTH_ENCRYPT_OAUTH_TOKENS', false),

    'middleware_hooks' => [
        // Add your middleware hook classes here
        // Example: \App\Http\Middleware\CustomAuthHook::class,
    ],

    // Verification requirements before registration
    'verification' => [
        'require_email_verification' => env('USER_AUTH_REQUIRE_EMAIL_VERIFICATION', false),  // Set to true to require email verification before registration
        'require_phone_verification' => env('USER_AUTH_REQUIRE_PHONE_VERIFICATION', false),  // Set to true to require phone verification before registration
        'code_length' => env('USER_AUTH_CODE_LENGTH', 6),                     // Length of verification codes
        'code_expiry_minutes' => env('USER_AUTH_CODE_EXPIRY_MINUTES', 5),            // How long codes are valid
        'rate_limit_attempts' => env('USER_AUTH_RATE_LIMIT_ATTEMPTS', 3),             // Number of attempts before rate limiting
        'rate_limit_minutes' => env('USER_AUTH_RATE_LIMIT_MINUTES', 5),              // Rate limit window in minutes
        'provider' => env('USER_AUTH_VERIFICATION_PROVIDER', 'default'),                // Verification provider: 'default', 'smartpings'
        'self_managed' => env('USER_AUTH_SELF_MANAGED', true),                 // Set to false to let the provider handle the entire flow
    ],

    // SmartPings configuration
    'smartpings' => [
        'client_id' => env('SMARTPINGS_CLIENT_ID'),
        'secret_id' => env('SMARTPINGS_SECRET_ID'),
    ],

    /*
    | Email Domain Restrictions
    | Mode: 'whitelist', 'blacklist', or null to allow all emails
    | Domains: an array of domains
    */

    'email_restrictions' => [
        'mode' => env('USER_AUTH_EMAIL_RESTRICTION_MODE', null), // 'whitelist', 'blacklist', or null
        'domains' => array_map('strtolower', array_map('trim', array_filter(explode(',', env('USER_AUTH_EMAIL_RESTRICTION_DOMAINS', '')), 'strlen'))),
    ],

    'passkey' => [
        'domain' => env('USER_AUTH_PASSKEY_DOMAIN', 'localhost'),
        'attestations' => array_map('strtolower', array_map('trim', array_filter(explode(',', env('USER_AUTH_PASSKEY_ATTESTATIONS', 'none')), 'strlen'))), // none,packed, fido
        'allowed_origins' => array_map('strtolower', array_map('trim', array_filter(explode(',', env('USER_AUTH_PASSKEY_ALLOWED_ORIGINS', '')), 'strlen'))), // localhost, google.com, etc...
    ]
];
