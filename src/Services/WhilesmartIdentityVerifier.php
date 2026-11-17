<?php

namespace Whilesmart\UserAuthentication\Services;

use Firebase\JWT\JWK;
use Firebase\JWT\JWT;
use Illuminate\Support\Facades\Http;
use RuntimeException;

class WhilesmartIdentityVerifier
{
    public function verify(string $raw, array $metadata, array $transaction): array
    {
        $claims = $this->decodeIdentity($raw, $metadata);
        $this->validateClaims($claims, $metadata, $transaction);
        return $claims;
    }

    private function decodeIdentity(string $raw, array $metadata): array
    {
        $keySet = Http::timeout(10)->connectTimeout(5)->withoutRedirecting()
            ->get($metadata['jwks_uri'])->throw()->json();
        if (! is_array($keySet) || ! isset($keySet['keys']) || count($keySet['keys']) > 20) {
            throw new RuntimeException('Invalid signing keys.');
        }
        foreach ($keySet['keys'] as $key) {
            if (
                ($key['kty'] ?? '') !== 'RSA'
                || ($key['alg'] ?? 'RS256') !== 'RS256'
                || ($key['use'] ?? 'sig') !== 'sig'
            ) {
                throw new RuntimeException('Unsupported signing key.');
            }
        }
        $keys = JWK::parseKeySet($keySet, 'RS256');
        foreach ($keys as $key) {
            $publicKey = openssl_pkey_get_public($key->getKeyMaterial());
            $details = $publicKey === false ? false : openssl_pkey_get_details($publicKey);
            if ($details === false || $details['bits'] < 2048) {
                throw new RuntimeException('Signing key is too small.');
            }
        }
        return (array) JWT::decode($raw, $keys);
    }

    private function validateClaims(array $claims, array $metadata, array $transaction): void
    {
        $audiences = is_string($claims['aud'] ?? null) ? [$claims['aud']] : ($claims['aud'] ?? []);
        if (
            ($claims['iss'] ?? null) !== $metadata['issuer']
            || ! is_array($audiences)
            || ! in_array($transaction['client_id'], $audiences, true)
            || (count($audiences) > 1
            && ($claims['azp'] ?? null) !== $transaction['client_id'])
            || ! is_int($claims['exp'] ?? null)
            || ! is_int($claims['iat'] ?? null)
            || $claims['iat'] > time() + 30
            || ! is_string($claims['sub'] ?? null)
            || $claims['sub'] === ''
            || strlen($claims['sub']) > 255
            || ! is_string($claims['nonce'] ?? null)
            || ! hash_equals($transaction['nonce'], $claims['nonce'])
        ) {
            throw new RuntimeException('Invalid identity token.');
        }
    }
}
