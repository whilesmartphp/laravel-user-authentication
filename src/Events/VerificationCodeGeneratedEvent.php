<?php

namespace Whilesmart\UserAuthentication\Events;

use Illuminate\Broadcasting\InteractsWithSockets;
use Illuminate\Foundation\Events\Dispatchable;
use Illuminate\Queue\SerializesModels;

class VerificationCodeGeneratedEvent
{
    use Dispatchable, InteractsWithSockets, SerializesModels;

    /**
     * Create a new event instance.
     */
    public function __construct(
        public string $contact,
        public string $code,
        public string $purpose,
        public string $type = 'email' // 'email' or 'phone'
    ) {}
}
