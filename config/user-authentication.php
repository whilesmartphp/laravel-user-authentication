<?php

return [
    'user_model' => Whilesmart\UserAuthentication\Models\User::class,
    'register_routes' => true,
    'register_oauth_routes' => true,
    'route_prefix' => 'api',

    'response_formatter' => \Whilesmart\UserAuthentication\ResponseFormatters\DefaultResponseFormatter::class,

    'middleware_hooks' => [
        // Add your middleware hook classes here
        // Example: \App\Http\Middleware\CustomAuthHook::class,
    ],
];
