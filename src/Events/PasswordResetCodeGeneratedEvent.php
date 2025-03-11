<?php

namespace Whilesmart\LaravelUserAuthentication\Events;

use Illuminate\Broadcasting\InteractsWithSockets;
use Illuminate\Foundation\Events\Dispatchable;
use Illuminate\Queue\SerializesModels;

class PasswordResetCodeGeneratedEvent
{
    use Dispatchable, InteractsWithSockets, SerializesModels;

    public string $email;

    public string $code;

    /**
     * Create a new event instance.
     *
     * @return void
     */
    public function __construct(string $email, string $code)
    {
        $this->email = $email;
        $this->code = $code;
    }
}
