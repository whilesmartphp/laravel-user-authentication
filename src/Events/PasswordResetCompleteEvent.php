<?php

namespace Whilesmart\LaravelUserAuthentication\Events;

use Illuminate\Broadcasting\InteractsWithSockets;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Foundation\Events\Dispatchable;
use Illuminate\Queue\SerializesModels;

class PasswordResetCompleteEvent
{
    use Dispatchable, InteractsWithSockets, SerializesModels;

    public Authenticatable $user;

    /**
     * Create a new event instance.
     *
     * @return void
     */
    public function __construct(Authenticatable $user)
    {
        $this->user = $user;
    }
}
