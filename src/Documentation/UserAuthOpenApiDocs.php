<?php

namespace Whilesmart\UserAuthentication\Documentation;

use Illuminate\Http\Request;
use OpenApi\Attributes as OA;

/**
 * OpenAPI Documentation for Laravel User Authentication Package
 *
 * This class contains all the API documentation that can be published
 * to your application for OpenAPI spec generation without needing
 * to publish the actual controllers.
 *
 * @codeCoverageIgnore
 */
#[OA\Tag(name: 'Authentication', description: 'Endpoints for user authentication')]
class UserAuthOpenApiDocs
{
    #[OA\Post(
        path: '/oauth/firebase/{driver}/callback',
        summary: 'Handles Firebase Oauth login callback',
        requestBody: new OA\RequestBody(
            required: true,
            content: new OA\JsonContent(
                properties: [
                    new OA\Property(
                        property: 'token',
                        description: 'Firebase token',
                        type: 'string',
                    ),
                ]
            )
        ),
        tags: ['Authentication'],
        parameters: [
            new OA\Parameter(
                name: 'driver',
                description: 'Oauth provider name',
                in: 'path',
                required: true,
                schema: new OA\Schema(type: 'string')
            ),
        ],
        responses: [
            new OA\Response(response: 200, description: 'Credentials verified'),
            new OA\Response(response: 500, description: 'Server error'),
            new OA\Response(response: 400, description: 'Invalid token'),
        ]
    )]
    /**
     * @suppressWarnings(PHPMD.UnusedFormalParameter)
     */
    public function firebaseAuthCallback(Request $request, string $driver)
    {
    }

    #[OA\Post(
        path: '/register',
        summary: 'Register a new user',
        security: [],
        requestBody: new OA\RequestBody(
            required: true,
            content: new OA\JsonContent(
                required: ['email', 'first_name', 'password'],
                properties: [
                    new OA\Property(property: 'email', type: 'string', format: 'email'),
                    new OA\Property(property: 'first_name', type: 'string'),
                    new OA\Property(property: 'last_name', type: 'string'),
                    new OA\Property(property: 'username', type: 'string'),
                    new OA\Property(property: 'phone', type: 'string'),
                    new OA\Property(property: 'password', type: 'string', format: 'password'),
                ]
            )
        ),
        tags: ['Authentication'],
        responses: [
            new OA\Response(
                response: 201,
                description: 'User registered successfully',
                content: new OA\JsonContent(
                    properties: [
                        new OA\Property(property: 'success', type: 'boolean', example: true),
                        new OA\Property(property: 'message', type: 'string'),
                        new OA\Property(
                            property: 'data',
                            properties: [
                                new OA\Property(property: 'user', type: 'object'),
                                new OA\Property(property: 'token', type: 'string'),
                            ]
                        ),
                    ]
                )
            ),
            new OA\Response(response: 422, description: 'Validation error'),
        ]
    )]
    public function register()
    {
    }

    #[OA\Post(
        path: '/login',
        summary: 'User login',
        security: [],
        requestBody: new OA\RequestBody(
            required: true,
            content: new OA\JsonContent(
                required: ['password'],
                properties: [
                    new OA\Property(property: 'email', type: 'string', format: 'email'),
                    new OA\Property(property: 'phone', type: 'string'),
                    new OA\Property(property: 'username', type: 'string'),
                    new OA\Property(property: 'password', type: 'string', format: 'password'),
                ]
            )
        ),
        tags: ['Authentication'],
        responses: [
            new OA\Response(
                response: 200,
                description: 'User successfully logged in or 2FA challenge required',
                content: new OA\JsonContent(
                    properties: [
                        new OA\Property(property: 'success', type: 'boolean', example: true),
                        new OA\Property(property: 'message', type: 'string'),
                        new OA\Property(
                            property: 'data',
                            oneOf: [
                                new OA\Schema(
                                    description: 'Direct login response',
                                    properties: [
                                        new OA\Property(property: 'token', type: 'string'),
                                        new OA\Property(property: 'token_type', type: 'string', example: 'Bearer'),
                                    ]
                                ),
                                new OA\Schema(
                                    description: 'Two-factor challenge response',
                                    properties: [
                                        new OA\Property(
                                            property: 'two_factor_required',
                                            type: 'boolean',
                                            example: true
                                        ),
                                        new OA\Property(
                                            property: 'method',
                                            type: 'string',
                                            enum: ['totp', 'email', 'phone']
                                        ),
                                        new OA\Property(property: 'two_factor_token', type: 'string'),
                                    ]
                                ),
                            ]
                        ),
                    ]
                )
            ),
            new OA\Response(response: 401, description: 'Invalid credentials'),
            new OA\Response(response: 500, description: 'Server error'),
        ]
    )]
    public function login()
    {
    }

    #[OA\Post(
        path: '/logout',
        summary: 'User logout',
        security: [
            ['sanctum' => []],
        ],
        tags: ['Authentication'],
        responses: [
            new OA\Response(response: 200, description: 'User successfully logged out'),
            new OA\Response(response: 401, description: 'Invalid credentials'),
            new OA\Response(response: 500, description: 'Server error'),
        ]
    )]
    public function logout()
    {
    }

    #[OA\Get(
        path: '/oauth/{driver}/login',
        summary: 'Get Oauth redirect URI',
        tags: ['Authentication'],
        parameters: [
            new OA\Parameter(
                name: 'driver',
                description: 'Oauth provider name',
                in: 'path',
                required: true,
                schema: new OA\Schema(type: 'string')
            ),
        ],
        responses: [
            new OA\Response(response: 200, description: 'URL generated'),
            new OA\Response(response: 500, description: 'Server error'),
        ]
    )]
    public function oauthLogin()
    {
    }

    #[OA\Get(
        path: '/oauth/{driver}/callback',
        summary: 'Handles Oauth login callback',
        tags: ['Authentication'],
        parameters: [
            new OA\Parameter(
                name: 'driver',
                description: 'Oauth provider name',
                in: 'path',
                required: true,
                schema: new OA\Schema(type: 'string')
            ),
        ],
        responses: [
            new OA\Response(response: 200, description: ' '),
            new OA\Response(response: 500, description: 'Server error'),
        ]
    )]
    public function oauthCallback()
    {
    }

    #[OA\Post(
        path: '/send-verification-code',
        summary: 'Send verification code to email or phone',
        security: [],
        requestBody: new OA\RequestBody(
            required: true,
            content: new OA\JsonContent(
                required: ['contact', 'type'],
                properties: [
                    new OA\Property(property: 'contact', description: 'Email address or phone number', type: 'string'),
                    new OA\Property(
                        property: 'type',
                        description: 'Type of contact',
                        type: 'string',
                        enum: ['email', 'phone']
                    ),
                    new OA\Property(
                        property: 'purpose',
                        description: 'Purpose of verification (optional, defaults to "registration")',
                        type: 'string',
                        enum: ['registration', 'login'],
                        example: 'registration'
                    ),
                ]
            )
        ),
        tags: ['Authentication'],
        responses: [
            new OA\Response(response: 200, description: 'Verification code sent successfully'),
            new OA\Response(response: 422, description: 'Validation error'),
            new OA\Response(response: 429, description: 'Too many requests'),
        ]
    )]
    public function sendVerificationCode()
    {
    }

    #[OA\Post(
        path: '/verify-code',
        summary: 'Verify a code for email or phone',
        security: [],
        requestBody: new OA\RequestBody(
            required: true,
            content: new OA\JsonContent(
                required: ['contact', 'code', 'type'],
                properties: [
                    new OA\Property(property: 'contact', description: 'Email address or phone number', type: 'string'),
                    new OA\Property(property: 'code', description: 'Verification code', type: 'string'),
                    new OA\Property(
                        property: 'type',
                        description: 'Type of contact',
                        type: 'string',
                        enum: ['email', 'phone']
                    ),
                    new OA\Property(
                        property: 'purpose',
                        description: 'Purpose of verification (optional, defaults to "registration")',
                        type: 'string',
                        enum: ['registration', 'login'],
                        example: 'registration'
                    ),
                ]
            )
        ),
        tags: ['Authentication'],
        responses: [
            new OA\Response(response: 200, description: 'Code verified successfully'),
            new OA\Response(response: 400, description: 'Invalid or expired code'),
            new OA\Response(response: 422, description: 'Validation error'),
        ]
    )]
    public function verifyCode()
    {
    }

    #[OA\Post(
        path: '/2fa/setup',
        summary: 'Initiate 2FA setup and get secret/QR code',
        security: [['sanctum' => []]],
        tags: ['Authentication'],
        responses: [
            new OA\Response(response: 200, description: '2FA setup initiated successfully'),
            new OA\Response(response: 401, description: 'Unauthenticated'),
        ]
    )]
    public function setupTwoFactor()
    {
    }

    #[OA\Post(
        path: '/2fa/confirm',
        summary: 'Confirm 2FA setup with OTP code and receive recovery codes',
        security: [['sanctum' => []]],
        requestBody: new OA\RequestBody(
            required: true,
            content: new OA\JsonContent(
                required: ['code'],
                properties: [
                    new OA\Property(property: 'code', description: 'TOTP code from authenticator app', type: 'string'),
                ]
            )
        ),
        tags: ['Authentication'],
        responses: [
            new OA\Response(response: 200, description: '2FA enabled successfully'),
            new OA\Response(response: 400, description: 'Setup not initiated'),
            new OA\Response(response: 422, description: 'Invalid code'),
        ]
    )]
    public function confirmTwoFactor()
    {
    }

    #[OA\Post(
        path: '/2fa/disable',
        summary: 'Disable 2FA',
        security: [['sanctum' => []]],
        requestBody: new OA\RequestBody(
            content: new OA\JsonContent(
                properties: [
                    new OA\Property(
                        property: 'code',
                        description: 'TOTP code, recovery code, or email/phone verification code.',
                        type: 'string',
                        nullable: true
                    ),
                    new OA\Property(
                        property: 'two_factor_token',
                        description: 'Pending token returned by the first disable call for email/phone 2FA.',
                        type: 'string',
                        nullable: true
                    ),
                ]
            )
        ),
        tags: ['Authentication'],
        responses: [
            new OA\Response(response: 200, description: '2FA disabled or verification code sent'),
            new OA\Response(response: 400, description: '2FA not enabled'),
            new OA\Response(response: 422, description: 'Invalid code'),
        ]
    )]
    public function disableTwoFactor()
    {
    }

    #[OA\Post(
        path: '/2fa/verify',
        summary: 'Verify 2FA login challenge code or recovery code',
        security: [],
        requestBody: new OA\RequestBody(
            required: true,
            content: new OA\JsonContent(
                required: ['code'],
                properties: [
                    new OA\Property(
                        property: 'code',
                        description: 'TOTP code, email code, or recovery code',
                        type: 'string'
                    ),
                ]
            )
        ),
        tags: ['Authentication'],
        responses: [
            new OA\Response(
                response: 200,
                description: 'Authenticated successfully',
                content: new OA\JsonContent(
                    properties: [
                        new OA\Property(property: 'success', type: 'boolean', example: true),
                        new OA\Property(property: 'message', type: 'string'),
                        new OA\Property(
                            property: 'data',
                            properties: [
                                new OA\Property(property: 'token', type: 'string'),
                                new OA\Property(property: 'token_type', type: 'string', example: 'Bearer'),
                                new OA\Property(property: 'user', type: 'object'),
                            ]
                        ),
                    ]
                )
            ),
            new OA\Response(response: 401, description: 'Session expired'),
            new OA\Response(response: 422, description: 'Invalid code'),
        ]
    )]
    public function verifyTwoFactor()
    {
    }

    #[OA\Post(
        path: '/2fa/resend',
        summary: 'Resend 2FA verification code',
        security: [],
        tags: ['Authentication'],
        responses: [
            new OA\Response(
                response: 200,
                description: 'Verification code resent',
                content: new OA\JsonContent(
                    properties: [
                        new OA\Property(property: 'success', type: 'boolean', example: true),
                        new OA\Property(property: 'message', type: 'string'),
                        new OA\Property(property: 'data', type: 'object', nullable: true),
                    ]
                )
            ),
            new OA\Response(response: 400, description: 'Not applicable for TOTP'),
            new OA\Response(response: 401, description: 'Session expired'),
        ]
    )]
    public function resendTwoFactor()
    {
    }

    #[OA\Get(
        path: '/2fa/verify',
        summary: 'Verify magic link',
        security: [],
        parameters: [
            new OA\Parameter(
                name: 'token',
                description: 'Magic link token',
                in: 'query',
                required: true,
                schema: new OA\Schema(type: 'string')
            ),
        ],
        tags: ['Authentication'],
        responses: [
            new OA\Response(
                response: 200,
                description: 'Authenticated successfully via magic link',
                content: new OA\JsonContent(
                    properties: [
                        new OA\Property(property: 'success', type: 'boolean', example: true),
                        new OA\Property(property: 'message', type: 'string'),
                        new OA\Property(
                            property: 'data',
                            properties: [
                                new OA\Property(property: 'token', type: 'string'),
                                new OA\Property(property: 'token_type', type: 'string', example: 'Bearer'),
                                new OA\Property(property: 'user', type: 'object'),
                            ]
                        ),
                    ]
                )
            ),
            new OA\Response(response: 403, description: 'Expired or invalid link'),
        ]
    )]
    public function verifyMagicLink()
    {
    }
}
