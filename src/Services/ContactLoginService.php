<?php

namespace Whilesmart\UserAuthentication\Services;

use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Str;
use Whilesmart\UserAuthentication\Models\AuthChallenge;

class ContactLoginService
{
    public function binding(string $channel, string $contact): string
    {
        return hash('sha256', 'contact_login:' . $channel . ':' . $contact);
    }

    public function prepare(string $channel, string $contact, string $policy, array $settings): array
    {
        $code = str_pad((string) random_int(0, 999999), 6, '0', STR_PAD_LEFT);
        $token = Str::random(64);
        $codeExpiry = now()->addMinutes(max(1, (int) $settings['code_expiry_minutes']));
        $linkExpiry = now()->addMinutes(max(1, (int) $settings['link_expiry_minutes']));

        return [
            'code' => $code,
            'token' => $token,
            'attributes' => [
                'id' => Str::random(64),
                'factor_id' => null,
                'binding_key' => $this->binding($channel, $contact),
                'token_hash' => hash('sha256', Str::random(64)),
                'purpose' => 'contact_login',
                'method' => $channel,
                'contact' => $contact,
                'policy' => $policy,
                'action' => 'login',
                'code_hash' => Hash::make($code),
                'link_hash' => hash('sha256', $token),
                'attempts' => 0,
                'code_expires_at' => $codeExpiry,
                'link_expires_at' => $linkExpiry,
                'expires_at' => $codeExpiry->greaterThan($linkExpiry) ? $codeExpiry : $linkExpiry,
                'consumed_at' => null,
                'created_at' => now(),
                'updated_at' => now(),
            ],
        ];
    }

    public function store(array $attributes): void
    {
        AuthChallenge::upsert($attributes, ['binding_key'], array_keys($attributes));
    }

    public function contactForToken(string $token): ?string
    {
        return AuthChallenge::where('purpose', 'contact_login')
            ->where('link_hash', hash('sha256', $token))->value('contact');
    }

    public function consume(string $channel, string $contact, string $credential, bool $link, int $budget): ?array
    {
        return DB::transaction(function () use ($channel, $contact, $credential, $link, $budget) {
            $challenge = AuthChallenge::where('binding_key', $this->binding($channel, $contact))
                ->where('purpose', 'contact_login')->where('method', $channel)->where('contact', $contact)
                ->lockForUpdate()->first();
            if (
                ! $challenge || $challenge->consumed_at || $challenge->expires_at->isPast()
                || $challenge->policy === null
            ) {
                return null;
            }
            $budget = max(1, $budget);
            if ($challenge->attempts >= $budget) {
                return null;
            }
            $challenge->increment('attempts');
            $valid = $link
                ? $challenge->link_expires_at?->isFuture() && $challenge->link_hash
                    && hash_equals($challenge->link_hash, hash('sha256', $credential))
                : $challenge->code_expires_at?->isFuture() && $challenge->code_hash
                    && Hash::check($credential, $challenge->code_hash);
            if (! $valid) {
                if ($challenge->attempts >= $budget) {
                    $challenge->update(['consumed_at' => now(), 'code_hash' => null, 'link_hash' => null]);
                }

                return null;
            }
            $consumed = AuthChallenge::whereKey($challenge->id)->whereNull('consumed_at')
                ->where('attempts', $challenge->attempts)
                ->where($link ? 'link_expires_at' : 'code_expires_at', '>', now())
                ->update(['consumed_at' => now(), 'code_hash' => null, 'link_hash' => null]);

            return $consumed === 1 ? ['policy' => $challenge->policy] : null;
        });
    }
}
