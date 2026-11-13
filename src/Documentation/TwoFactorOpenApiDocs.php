<?php

namespace Whilesmart\UserAuthentication\Documentation;

use OpenApi\Attributes as OA;

/** @codeCoverageIgnore */
class TwoFactorOpenApiDocs
{
    #[OA\Get(
        path: '/2fa/factors',
        summary: 'List the authenticated owner’s factors',
        security: [['sanctum' => []]],
        tags: ['Authentication'],
        responses: [new OA\Response(response: 200, description: 'Public factors', content: new OA\JsonContent(
            properties: [new OA\Property(property: 'data', properties: [
                new OA\Property(property: 'factors', type: 'array', items: new OA\Items(properties: [
                    new OA\Property(property: 'id', type: 'integer'),
                    new OA\Property(property: 'type', type: 'string'),
                    new OA\Property(property: 'label', type: 'string', nullable: true),
                    new OA\Property(property: 'confirmed_at', type: 'string', format: 'date-time', nullable: true),
                    new OA\Property(property: 'last_used_at', type: 'string', format: 'date-time', nullable: true),
                ])),
            ], type: 'object')]
        ))]
    )]
    public function listFactors()
    {
    }

    #[OA\Post(
        path: '/2fa/recovery-codes',
        summary: 'Replace the owner’s recovery codes and return ten new codes once',
        description: 'Requires a verified bearer and a confirmed factor. Previous codes and spent rows are deleted.',
        security: [['sanctum' => []]],
        tags: ['Authentication'],
        responses: [
            new OA\Response(response: 200, description: 'New recovery codes', content: new OA\JsonContent(
                properties: [new OA\Property(property: 'data', properties: [
                    new OA\Property(property: 'recovery_codes', type: 'array', items: new OA\Items(type: 'string')),
                ], type: 'object')]
            )),
            new OA\Response(response: 400, description: 'No confirmed factor'),
            new OA\Response(response: 403, description: 'Bearer has not completed two-factor authentication'),
            new OA\Response(response: 429, description: 'Rate limit reached'),
        ]
    )]
    public function regenerateRecoveryCodes()
    {
    }

    #[OA\Post(
        path: '/2fa/setup',
        summary: 'Enroll a labeled factor; only TOTP returns an enrollment secret',
        description: 'Up to two_factor.max_factors (default five), including pending factors. One email and one '
            . 'phone factor per owner. Returns factor_id and either TOTP enrollment data or a setup pending token.',
        requestBody: new OA\RequestBody(content: new OA\JsonContent(properties: [
            new OA\Property(property: 'type', type: 'string', default: 'totp', maxLength: 16),
            new OA\Property(property: 'label', type: 'string', nullable: true),
        ])),
        security: [['sanctum' => []]],
        tags: ['Authentication'],
        responses: [
            new OA\Response(response: 200, description: 'Factor ID, TOTP secret and QR URI or delivery setup token'),
            new OA\Response(response: 422, description: 'Unknown type, missing contact, duplicate or factor limit'),
            new OA\Response(response: 403, description: 'Current token has not completed 2FA'),
            new OA\Response(response: 429, description: 'IP or account limit reached'),
        ]
    )]
    public function setupTwoFactor()
    {
    }

    #[OA\Post(
        path: '/2fa/confirm',
        summary: 'Confirm a factor; first confirmation returns ten owner recovery codes once',
        security: [['sanctum' => []]],
        requestBody: new OA\RequestBody(
            required: true,
            content: new OA\JsonContent(
                required: ['factor_id', 'code'],
                properties: [
                    new OA\Property(property: 'factor_id', type: 'integer'),
                    new OA\Property(property: 'code', type: 'string', pattern: '^[0-9]{4,8}$'),
                    new OA\Property(
                        property: 'two_factor_token',
                        type: 'string',
                        description: 'Email/phone setup token'
                    ),
                ]
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
        requestBody: new OA\RequestBody(content: new OA\JsonContent(required: ['factor_id'], properties: [
            new OA\Property(property: 'factor_id', type: 'integer'),
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
            new OA\Response(response: 404, description: 'Factor does not belong to this owner'),
            new OA\Response(response: 422, description: 'Missing, invalid or replayed factor'),
            new OA\Response(response: 429, description: 'IP or account limit reached'),
        ]
    )]
    public function disableTwoFactor()
    {
    }

    #[OA\Post(
        path: '/2fa/verify',
        summary: 'Complete the pending password, OAuth, Firebase or passkey sign-in',
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
        summary: 'Select a confirmed factor and replace the pending login challenge',
        security: [],
        requestBody: new OA\RequestBody(required: true, content: new OA\JsonContent(
            required: ['two_factor_token', 'factor_id'],
            properties: [
                new OA\Property(property: 'two_factor_token', type: 'string', minLength: 100, maxLength: 2048),
                new OA\Property(property: 'factor_id', type: 'integer', description: 'Confirmed factor to challenge'),
            ]
        )),
        tags: ['Authentication'],
        responses: [
            new OA\Response(
                response: 200,
                description: 'Replacement data.two_factor_token; use it for subsequent requests'
            ),
            new OA\Response(response: 422, description: 'Selected confirmed factor not found'),
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
