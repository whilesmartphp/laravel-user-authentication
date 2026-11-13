<?php

namespace Whilesmart\UserAuthentication\Interfaces;

use Illuminate\Database\Eloquent\Model;
use Whilesmart\UserAuthentication\Models\AuthChallenge;
use Whilesmart\UserAuthentication\Models\AuthFactor;

interface FactorType
{
    public function key(): string;

    public function needsSecret(): bool;

    public function uniquePerOwner(): bool;

    public function contact(Model $owner): ?string;

    public function setup(AuthFactor $factor): array;

    public function issue(AuthFactor $factor, AuthChallenge $challenge, string $token): void;

    public function verify(AuthFactor $factor, string $code, ?AuthChallenge $challenge = null): bool;
}
