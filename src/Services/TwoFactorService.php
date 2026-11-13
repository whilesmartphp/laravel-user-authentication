<?php

namespace Whilesmart\UserAuthentication\Services;

use Illuminate\Database\Eloquent\Collection;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\MorphMany;
use Illuminate\Support\Facades\Crypt;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Str;
use Illuminate\Validation\ValidationException;
use RuntimeException;
use Whilesmart\UserAuthentication\Enums\HookAction;
use Whilesmart\UserAuthentication\Interfaces\FactorType;
use Whilesmart\UserAuthentication\Models\AuthChallenge;
use Whilesmart\UserAuthentication\Models\AuthFactor;
use Whilesmart\UserAuthentication\Models\RecoveryCode;

class TwoFactorService
{
    public function userData(Model $user): array
    {
        return $user->makeHidden(['factors', 'recoveryCodes', 'recovery_codes'])->toArray();
    }

    public function type(string $key): FactorType
    {
        $class = config('user-authentication.two_factor.types.' . $key);
        if (! is_string($class) || strlen($key) > 16 || ! is_a($class, FactorType::class, true)) {
            throw ValidationException::withMessages(['type' => 'Unsupported factor type.']);
        }

        $type = app($class);
        if ($type->key() !== $key) {
            throw ValidationException::withMessages(['type' => 'Factor type key does not match its registration.']);
        }

        return $type;
    }

    /** @return MorphMany<AuthFactor, Model> */
    private function factors(Model $user): MorphMany
    {
        return $user->morphMany(AuthFactor::class, 'authenticatable');
    }

    /** @return MorphMany<RecoveryCode, Model> */
    private function recoveryCodes(Model $user): MorphMany
    {
        return $user->morphMany(RecoveryCode::class, 'authenticatable');
    }

    /** @return Collection<int, AuthFactor> */
    public function lockFactors(Model $user): Collection
    {
        // The owner lock also serializes enrollment when no factor rows exist yet.
        $user->newQuery()->whereKey($user->getKey())->lockForUpdate()->firstOrFail();

        return $this->factors($user)->orderBy('id')->lockForUpdate()->get();
    }

    public function setup(Model $user, string $key, ?string $label): array
    {
        return DB::transaction(function () use ($user, $key, $label) {
            $factors = $this->lockFactors($user);
            $type = $this->type($key);
            foreach ($factors as $index => $factor) {
                if ($factor->type === $key && $factor->confirmed_at === null) {
                    $factor->delete();
                    $factors->forget($index);
                }
            }
            if ($factors->count() >= max(1, (int) config('user-authentication.two_factor.max_factors', 5))) {
                throw ValidationException::withMessages(['type' => 'Maximum number of factors reached.']);
            }
            if ($type->uniquePerOwner() && $factors->contains('type', $key)) {
                throw ValidationException::withMessages(['type' => 'This factor type is already registered.']);
            }
            if (! $type->needsSecret() && ! $type->contact($user)) {
                throw ValidationException::withMessages(['type' => 'A delivery contact is required.']);
            }
            $factor = $this->factors($user)->create(['type' => $key, 'label' => $label]);
            $data = $type->setup($factor);
            if (! $type->needsSecret()) {
                $data = $this->issue($user, 'setup_2fa', HookAction::LOGIN, $factor->id) ?? [];
            }

            return ['factor_id' => $factor->id, ...$data];
        });
    }

    public function policy(Model $user): string
    {
        $factors = $this->factors($user)->whereNotNull('confirmed_at')->orderBy('id')->get();

        return hash('sha256', $factors->map(fn (AuthFactor $factor) => [
            $factor->id, $factor->type, $factor->getRawOriginal('secret'),
            $factor->confirmed_at?->toISOString(), $this->type($factor->type)->contact($user),
        ])->toJson());
    }

    public function issue(
        Model $user,
        string $purpose = 'login',
        HookAction $action = HookAction::LOGIN,
        ?int $factorId = null
    ): ?array {
        return DB::transaction(function () use ($user, $purpose, $action, $factorId) {
            $factors = $this->lockFactors($user);
            $factor = $factorId === null ? $factors->firstWhere('confirmed_at', '!=', null) : $factors->find($factorId);
            if (! $factor || ($purpose !== 'setup_2fa' && ! $factor->confirmed_at)) {
                return null;
            }
            $type = $this->type($factor->type);
            $id = Str::random(64);
            $token = Crypt::encryptString(json_encode([
                'id' => $id, 'purpose' => $purpose, 'method' => $factor->type,
            ]));
            AuthChallenge::where('authenticatable_type', $user->getMorphClass())
                ->where('authenticatable_id', $user->getKey())->where('purpose', $purpose)
                ->whereNull('consumed_at')->update(['consumed_at' => now()]);
            $challenge = AuthChallenge::create([
                'id' => $id,
                'authenticatable_type' => $user->getMorphClass(),
                'authenticatable_id' => $user->getKey(),
                'factor_id' => $factor->id,
                'token_hash' => hash('sha256', $token),
                'purpose' => $purpose,
                'method' => $factor->type,
                'contact' => $type->contact($user),
                'policy' => $this->policy($user),
                'action' => $action->value,
                'expires_at' => now()->addMinutes(config('user-authentication.two_factor.expiry_minutes', 5)),
                'ip_address' => request()->ip(),
                'user_agent' => request()->userAgent(),
            ]);
            $type->issue($factor, $challenge, $token);
            $this->synchronizeExpiry($challenge);

            return [
                'two_factor_required' => true, 'factor_id' => $factor->id,
                'method' => $factor->type, 'two_factor_token' => $token,
                'factors' => $factors->whereNotNull('confirmed_at')->map->only([
                    'id', 'type', 'label', 'confirmed_at', 'last_used_at',
                ])->values()->all(),
            ];
        });
    }

    private function synchronizeExpiry(AuthChallenge $challenge): void
    {
        $expiry = $challenge->code_expires_at ?? $challenge->link_expires_at ?? $challenge->expires_at;
        if ($challenge->link_expires_at?->greaterThan($expiry)) {
            $expiry = $challenge->link_expires_at;
        }
        $challenge->update(['expires_at' => $expiry]);
    }

    public function challenge(string $token): ?AuthChallenge
    {
        try {
            $payload = json_decode(Crypt::decryptString($token), true);
            if (! is_array($payload) || ! isset($payload['id'], $payload['purpose'], $payload['method'])) {
                return null;
            }

            return AuthChallenge::whereKey($payload['id'])
                ->where('token_hash', hash('sha256', $token))
                ->where('purpose', $payload['purpose'])
                ->where('method', $payload['method'])
                ->whereNull('consumed_at')
                ->where('expires_at', '>', now())->first();
        } catch (\Illuminate\Contracts\Encryption\DecryptException $e) {
            return null;
        }
    }

    public function accountKey(string $token): string
    {
        $challenge = $this->challenge($token);
        $factor = $challenge ? AuthFactor::whereKey($challenge->factor_id)->first() : null;

        return $factor ? hash('sha256', $factor->authenticatable_type . ':' . $factor->authenticatable_id)
            : hash('sha256', $token);
    }

    public function current(Model $user, AuthFactor $factor, AuthChallenge $challenge): bool
    {
        return ($factor->confirmed_at || $challenge->purpose === 'setup_2fa')
            && $challenge->policy === $this->policy($user)
            && $challenge->authenticatable_type === $user->getMorphClass()
            && (string) $challenge->getAttribute('authenticatable_id') === (string) $user->getKey()
            && $challenge->method === $factor->type
            && $challenge->contact === $this->type($factor->type)->contact($user);
    }

    public function regenerateRecoveryCodes(Model $user): array
    {
        return DB::transaction(function () use ($user) {
            $this->lockFactors($user);
            $this->recoveryCodes($user)->delete();
            $codes = [];
            for ($index = 0; $index < 10; $index++) {
                $code = Str::random(10);
                $this->recoveryCodes($user)->create(['code_hash' => Hash::make($code)]);
                $codes[] = $code;
            }

            return $codes;
        });
    }

    public function verifyRecoveryCode(Model $user, string $code): bool
    {
        return DB::transaction(function () use ($user, $code) {
            $this->lockFactors($user);
            $codes = $this->recoveryCodes($user)->whereNull('used_at')->orderBy('id')->lockForUpdate()->get();
            foreach ($codes as $recovery) {
                if (Hash::check($code, $recovery->code_hash)) {
                    return RecoveryCode::whereKey($recovery->id)->whereNull('used_at')
                        ->update(['used_at' => now()]) === 1;
                }
            }

            return false;
        });
    }

    public function verifyFactor(AuthFactor $factor, string $code, ?AuthChallenge $challenge = null): bool
    {
        $valid = $this->type($factor->type)->verify($factor, $code, $challenge);
        if ($valid) {
            $factor->update(['last_used_at' => now()]);
        }

        return $valid;
    }

    public function remove(Model $user, AuthFactor $factor): void
    {
        $factor->delete();
        /** @var Model&\Laravel\Sanctum\Contracts\HasApiTokens $user */
        $user->tokens()->delete();
    }

    public function consume(
        Model $user,
        string $token,
        string $code,
        string $purpose = 'login',
        bool $link = false
    ): ?string {
        return DB::transaction(function () use ($user, $token, $code, $purpose, $link) {
            $factors = $this->lockFactors($user);
            $found = $this->challenge($token);
            $factor = $found ? $factors->find($found->factor_id) : null;
            if (! $factor || ! $found) {
                return null;
            }
            $challenge = AuthChallenge::whereKey($found->id)->lockForUpdate()->first();
            if (! $challenge || ! $this->canConsume($user, $factor, $challenge, $purpose)) {
                return null;
            }

            return $this->consumeChallenge($user, $factor, $challenge, $code, $link);
        });
    }

    private function consumeChallenge(
        Model $user,
        AuthFactor $factor,
        AuthChallenge $challenge,
        string $code,
        bool $link
    ): ?string {
        $budget = max(1, (int) config('user-authentication.two_factor.attempts', 5));
        if ($challenge->attempts >= $budget) {
            return null;
        }
        $challenge->increment('attempts');
        if (! $this->verifyChallenge($user, $factor, $challenge, $code, $link)) {
            if ($challenge->attempts >= $budget) {
                $challenge->update(['consumed_at' => now()]);
            }

            return null;
        }
        $consumed = AuthChallenge::whereKey($challenge->id)
            ->whereNull('consumed_at')->where('attempts', $challenge->attempts)
            ->where('expires_at', '>', now())
            ->update(['consumed_at' => now(), 'code_hash' => null, 'link_hash' => null]);
        if ($consumed !== 1) {
            throw new RuntimeException('Challenge changed during verification.');
        }
        $factor->update(['last_used_at' => now()]);
        if ($challenge->purpose === 'disable_2fa') {
            $this->remove($user, $factor);
        }

        return $challenge->action;
    }

    private function canConsume(Model $user, AuthFactor $factor, AuthChallenge $challenge, string $purpose): bool
    {
        return ! $challenge->consumed_at && $challenge->expires_at->isFuture()
            && $challenge->purpose === $purpose && $this->current($user, $factor, $challenge);
    }

    private function verifyChallenge(
        Model $user,
        AuthFactor $factor,
        AuthChallenge $challenge,
        string $code,
        bool $link
    ): bool {
        if ($link) {
            return $challenge->purpose === 'login' && $challenge->link_hash
                && $challenge->link_expires_at?->isFuture()
                && hash_equals($challenge->link_hash, hash('sha256', $code));
        }

        return ($challenge->code_expires_at?->isFuture() && $this->verifyFactor($factor, $code, $challenge))
            || ($challenge->purpose !== 'setup_2fa' && $this->verifyRecoveryCode($user, $code));
    }
}
