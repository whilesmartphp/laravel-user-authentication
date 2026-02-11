<?php

namespace Whilesmart\UserAuthentication\Events;

use Illuminate\Broadcasting\InteractsWithSockets;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Foundation\Events\Dispatchable;
use Illuminate\Queue\SerializesModels;
use Laravel\Socialite\Contracts\User as SocialiteUser;

class OauthUserAuthenticatedEvent
{
    use Dispatchable, InteractsWithSockets, SerializesModels;

    public Authenticatable $user;

    public ?SocialiteUser $socialUser;

    public string $driver;

    public bool $isNewUser;

    public function __construct(Authenticatable $user, ?SocialiteUser $socialUser, string $driver, bool $isNewUser = false)
    {
        $this->user = $user;
        $this->socialUser = $socialUser;
        $this->driver = $driver;
        $this->isNewUser = $isNewUser;
    }
}
