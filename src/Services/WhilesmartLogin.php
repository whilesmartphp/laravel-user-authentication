<?php

namespace Whilesmart\UserAuthentication\Services;

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Str;
use RuntimeException;
use Laravel\Sanctum\PersonalAccessToken;

class WhilesmartLogin
{
    public function begin(Request $request, bool $link = false): array
    {
        $metadata = $this->metadata();
        $state = bin2hex(random_bytes(32));
        $nonce = bin2hex(random_bytes(32));
        $verifier = Str::random(96);
        $browser = $request->cookie('user_auth_whilesmart');
        if (! is_string($browser) || ! preg_match('/^[a-f0-9]{64}$/D', $browser)) {
            $browser = bin2hex(random_bytes(32));
        }
        $scopes = config('user-authentication.whilesmart.scopes', ['openid', 'profile', 'email']);
        if (! is_array($scopes) || ! in_array('openid', $scopes, true)) {
            throw new RuntimeException('Invalid Whilesmart scopes.');
        }
        $transaction = [
            'browser' => hash('sha256', $browser),
            'nonce' => $nonce,
            'verifier' => $verifier,
            'issuer' => $metadata['issuer'],
            'client_id' => config('user-authentication.whilesmart.client_id'),
            'redirect_uri' => config('user-authentication.whilesmart.redirect_uri'),
        ];
        if ($link) {
            $token = $request->user()?->currentAccessToken();
            if (! $token instanceof PersonalAccessToken || $token->getAttribute('expires_at')?->isPast()) {
                throw new RuntimeException('Account linking requires an active personal access token.');
            }
            $transaction['link'] = ['type' => get_class($request->user()),
                 'id' => (string) $request->user()->getAuthIdentifier(),
                 'token_id' => $token->getKey(),
                 'token_hash' => $token->getAttribute('token')];
        }
        $stateHash = hash('sha256', $state);
        Cache::put("whilesmart_login:{$stateHash}", $transaction, 600);
        $query = http_build_query([
            'response_type' => 'code',
            'client_id' => $transaction['client_id'],
            'redirect_uri' => $transaction['redirect_uri'],
            'scope' => implode(' ', $scopes),
            'state' => $state,
            'nonce' => $nonce,
            'code_challenge' => rtrim(strtr(base64_encode(hash('sha256', $verifier, true)), '+/', '-_'), '='),
            'code_challenge_method' => 'S256',
        ], '', '&', PHP_QUERY_RFC3986);

        return ['url' => sprintf('%s?%s', $metadata['authorization_endpoint'], $query), 'browser' => $browser];
    }

    public function complete(Request $request): array
    {
        $transaction = $this->consumeTransaction($request);
        $metadata = $this->metadata();
        if (
            $metadata['issuer'] !== $transaction['issuer']
            || config('user-authentication.whilesmart.client_id') !== $transaction['client_id']
            || config('user-authentication.whilesmart.redirect_uri') !== $transaction['redirect_uri']
        ) {
            throw new RuntimeException('Authorization configuration changed.');
        }
        $tokens = $this->exchange($request, $metadata, $transaction);
        $claims = app(WhilesmartIdentityVerifier::class)->verify($tokens['id_token'], $metadata, $transaction);
        $identity = Http::timeout(10)->connectTimeout(5)->withoutRedirecting()
            ->withToken($tokens['access_token'])
            ->get($metadata['userinfo_endpoint'])->throw()->json();
        if (! is_array($identity) || ($identity['sub'] ?? null) !== $claims['sub']) {
            throw new RuntimeException('Identity mismatch.');
        }

        if (isset($transaction['link'])) {
            $this->verifyLink($transaction['link']);
        }

        return ['issuer' => $metadata['issuer'],
             'subject' => $claims['sub'],
             'identity' => $identity,
             'credentials' => $tokens,
             'link' => $transaction['link'] ?? null];
    }

    private function consumeTransaction(Request $request): array
    {
        $state = $request->query('state');
        $browser = $request->cookie('user_auth_whilesmart');
        if (! is_string($state) || ! preg_match('/^[a-f0-9]{64}$/D', $state) || ! is_string($browser)) {
            throw new RuntimeException('Invalid authorization transaction.');
        }
        $stateHash = hash('sha256', $state);
        $key = "whilesmart_login:{$stateHash}";
        $transaction = Cache::lock("{$key}:lock", 10)->block(5, function () use ($key, $browser) {
            $transaction = Cache::get($key);
            if (! is_array($transaction) || ! hash_equals($transaction['browser'], hash('sha256', $browser))) {
                throw new RuntimeException('Invalid authorization transaction.');
            }
            Cache::forget($key);

            return $transaction;
        });
        if (
            $request->query('error')
            || ! is_string($request->query('code'))
            || strlen($request->query('code')) > 2048
        ) {
            throw new RuntimeException('Authorization denied.');
        }
        return $transaction;
    }

    private function exchange(Request $request, array $metadata, array $transaction): array
    {
        $tokens = Http::timeout(10)->connectTimeout(5)->withoutRedirecting()->asForm()->withBasicAuth(
            $transaction['client_id'],
            config('user-authentication.whilesmart.client_secret')
        )->post($metadata['token_endpoint'], [
            'grant_type' => 'authorization_code',
            'code' => $request->query('code'),
            'redirect_uri' => $transaction['redirect_uri'],
            'code_verifier' => $transaction['verifier'],
        ])->throw()->json();
        if (
            ! is_array($tokens)
            || ! is_string($tokens['id_token'] ?? null)
            || ! is_string($tokens['access_token'] ?? null)
        ) {
            throw new RuntimeException('Invalid token response.');
        }
        return $tokens;
    }

    private function verifyLink(array $link): void
    {
        $token = PersonalAccessToken::query()->whereKey($link['token_id'])->first();
        if (
            ! $token
            || ! hash_equals($token->getAttribute('token'), $link['token_hash'])
            || $token->getAttribute('expires_at')?->isPast()
            || (config('sanctum.expiration')
            && $token->getAttribute('created_at')->lte(now()->subMinutes(config('sanctum.expiration'))))
            || $token->getAttribute('tokenable_type') !== (new $link['type']())->getMorphClass()
            || (string) $token->getAttribute('tokenable_id') !== $link['id']
        ) {
            throw new RuntimeException('Account linking authorization expired.');
        }
    }

    private function metadata(): array
    {
        $issuer = rtrim((string) config('user-authentication.whilesmart.issuer'), '/');
        $parsed = parse_url($issuer);
        if (
            ! is_array($parsed)
            || ($parsed['scheme'] ?? null) !== 'https'
            || empty($parsed['host'])
            || isset($parsed['user'])
            || isset($parsed['pass'])
            || isset($parsed['query'])
            || isset($parsed['fragment'])
            || ! config('user-authentication.whilesmart.client_id')
            || ! config('user-authentication.whilesmart.client_secret')
            || ! config('user-authentication.whilesmart.redirect_uri')
        ) {
            throw new RuntimeException('Whilesmart login is not configured.');
        }
        $metadata = Http::timeout(10)->connectTimeout(5)->withoutRedirecting()
            ->get("{$issuer}/.well-known/openid-configuration")->throw()->json();
        if (! is_array($metadata) || ($metadata['issuer'] ?? null) !== $issuer) {
            throw new RuntimeException('Invalid issuer discovery.');
        }
        $this->validateEndpoints($metadata, $parsed);

        return $metadata;
    }

    private function validateEndpoints(array $metadata, array $parsed): void
    {
        foreach (['authorization_endpoint', 'token_endpoint', 'userinfo_endpoint', 'jwks_uri'] as $name) {
            $endpoint = $metadata[$name] ?? null;
            $url = is_string($endpoint) ? parse_url($endpoint) : false;
            if (
                ! is_array($url)
                || ($url['scheme'] ?? null) !== 'https'
                || ($url['host'] ?? null) !== $parsed['host']
                || ($url['port'] ?? 443) !== ($parsed['port'] ?? 443)
                || isset($url['user'])
                || isset($url['pass'])
                || isset($url['fragment'])
                || isset($url['query'])
            ) {
                throw new RuntimeException('Invalid issuer endpoint.');
            }
        }
    }
}
