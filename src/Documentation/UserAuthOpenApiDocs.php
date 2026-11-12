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
        summary: 'Start TOTP setup; returns the secret only for enrollment',
        security: [['sanctum' => []]],
        tags: ['Authentication'],
        responses: [
            new OA\Response(response: 200, description: 'Secret and QR URI for enrollment'),
            new OA\Response(response: 400, description: 'Already enabled'),
            new OA\Response(response: 403, description: 'Current token has not completed 2FA'),
            new OA\Response(response: 429, description: 'IP or account limit reached'),
        ]
    )]
    public function setupTwoFactor()
    {
    }

    #[OA\Post(
        path: '/2fa/confirm',
        summary: 'Confirm pending setup; returns recovery codes once and revokes other sessions',
        security: [['sanctum' => []]],
        requestBody: new OA\RequestBody(
            required: true,
            content: new OA\JsonContent(
                required: ['code'],
                properties: [new OA\Property(property: 'code', type: 'string', pattern: '^[0-9]{6}$')]
            )
        ),
        tags: ['Authentication'],
        responses: [
            new OA\Response(response: 200, description: 'Enabled; current bearer retained and marked verified'),
            new OA\Response(response: 400, description: 'Setup missing or already enabled'),
            new OA\Response(
                response: 422,
                description: 'Invalid code; setup invalidated after five failed attempts by default'
            ),
            new OA\Response(response: 429, description: 'IP or account limit reached'),
        ]
    )]
    public function confirmTwoFactor()
    {
    }

    #[OA\Post(
        path: '/2fa/disable',
        summary: 'Disable only with a fresh current factor and a verified bearer',
        security: [['sanctum' => []]],
        requestBody: new OA\RequestBody(content: new OA\JsonContent(properties: [
            new OA\Property(
                property: 'code',
                description: 'Six-digit TOTP, unused 10-character alphanumeric recovery code, or fresh email/SMS code',
                type: 'string',
                maxLength: 10
            ),
            new OA\Property(
                property: 'two_factor_token',
                description: 'For email/SMS, omit both fields to send a disable challenge, then submit its pending '
                    . 'token and code',
                type: 'string',
                maxLength: 2048
            ),
        ])),
        tags: ['Authentication'],
        responses: [
            new OA\Response(response: 200, description: 'Challenge issued or disabled with all sessions revoked'),
            new OA\Response(response: 400, description: 'Not enabled'),
            new OA\Response(response: 422, description: 'Missing, invalid or replayed factor'),
            new OA\Response(response: 429, description: 'IP or account limit reached'),
        ]
    )]
    public function disableTwoFactor()
    {
    }

    #[OA\Post(
        path: '/2fa/verify',
        summary: 'Complete the pending password, OAuth or Firebase sign-in',
        description: 'Primary sign-in returns data.two_factor_token instead of an access token for enabled '
            . 'accounts. Challenges expire after five minutes and permit five attempts by default. '
            . 'Codes, pending tokens and recovery codes are single use. TOTP timesteps cannot be '
            . 'replayed, including the setup timestep. User responses contain only public identity '
            . 'fields.',
        security: [],
        requestBody: new OA\RequestBody(required: true, content: new OA\JsonContent(
            required: ['two_factor_token', 'code'],
            properties: [
                new OA\Property(
                    property: 'two_factor_token',
                    description: 'Opaque pending token from primary sign-in',
                    type: 'string',
                    minLength: 100,
                    maxLength: 2048
                ),
                new OA\Property(
                    property: 'code',
                    description: 'Six-digit TOTP, configured 4 to 8 digit email/SMS code, or unused 10-character '
                        . 'alphanumeric recovery code',
                    type: 'string',
                    maxLength: 10
                ),
            ]
        )),
        tags: ['Authentication'],
        responses: [
            new OA\Response(
                response: 200,
                description: 'Access token, Bearer token type and allowlisted user identity'
            ),
            new OA\Response(response: 401, description: 'Pending token missing, expired, consumed or exhausted'),
            new OA\Response(response: 422, description: 'Invalid factor or changed policy'),
            new OA\Response(response: 429, description: 'IP or account limit reached'),
        ]
    )]
    public function verifyTwoFactor()
    {
    }

    #[OA\Post(
        path: '/2fa/resend',
        summary: 'Replace an email/SMS login challenge and invalidate its earlier code and link',
        security: [],
        requestBody: new OA\RequestBody(required: true, content: new OA\JsonContent(
            required: ['two_factor_token'],
            properties: [new OA\Property(property: 'two_factor_token', type: 'string', minLength: 100, maxLength: 2048)]
        )),
        tags: ['Authentication'],
        responses: [
            new OA\Response(
                response: 200,
                description: 'Replacement data.two_factor_token; use it for subsequent requests'
            ),
            new OA\Response(response: 400, description: 'TOTP cannot be resent'),
            new OA\Response(response: 401, description: 'Invalid pending token'),
            new OA\Response(response: 429, description: 'IP or account limit reached'),
        ]
    )]
    public function resendTwoFactor()
    {
    }

    #[OA\Post(
        path: '/2fa/verify-link',
        summary: 'Consume an email/SMS magic link after frontend confirmation',
        description: 'The emailed URL points to USER_AUTH_MAGIC_LINK_URL with token and two_factor_token. GET '
            . 'never authenticates or consumes. The frontend POSTs both values here. Links cannot '
            . 'satisfy TOTP and are rejected after factor policy changes or challenge replacement. '
            . 'Default per-IP and per-account limits per minute: verify/link/setup/confirm/disable 5, '
            . 'resend 3. USER_AUTH_2FA_* overrides configure limits, expiry and attempts.',
        security: [],
        requestBody: new OA\RequestBody(required: true, content: new OA\JsonContent(
            required: ['token', 'two_factor_token'],
            properties: [
                new OA\Property(property: 'token', type: 'string', pattern: '^[a-zA-Z0-9]{64}$'),
                new OA\Property(property: 'two_factor_token', type: 'string', minLength: 100, maxLength: 2048),
            ]
        )),
        tags: ['Authentication'],
        responses: [
            new OA\Response(response: 200, description: 'Authenticated; link and pending token consumed atomically'),
            new OA\Response(response: 401, description: 'Invalid, expired or consumed pending token'),
            new OA\Response(response: 422, description: 'Invalid link or changed factor policy'),
            new OA\Response(response: 429, description: 'IP or account limit reached'),
        ]
    )]
    public function verifyMagicLink()
    {
    }
}
