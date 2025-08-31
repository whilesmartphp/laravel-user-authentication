# Email/Phone Verification

This package provides configurable email and phone verification before user registration. The verification system uses Laravel events, allowing you to integrate with any email/SMS provider.

## Configuration

Enable verification in your `config/user-authentication.php`:

```php
'verification' => [
    'require_email_verification' => true,   // Require email verification before registration
    'require_phone_verification' => false,  // Require phone verification before registration
    'code_length' => 6,                     // Length of verification codes (default: 6)
    'code_expiry_minutes' => 5,             // Code expiry time in minutes (default: 5)
    'rate_limit_attempts' => 3,             // Rate limit attempts (default: 3)
    'rate_limit_minutes' => 5,              // Rate limit window in minutes (default: 5)
],
```

## New API Endpoints

When verification is enabled, these endpoints become available:

* **POST /api/send-verification-code:** Send verification code to email or phone
* **POST /api/verify-code:** Verify a submitted code

## Event-Driven Integration

The package dispatches `VerificationCodeGeneratedEvent` when codes are generated. You must create event listeners to actually send the codes via your preferred providers.

### Setting Up Email Verification with Laravel Mail

1. **Create an Event Listener:**

```php
<?php

namespace App\Listeners;

use Illuminate\Support\Facades\Mail;
use Whilesmart\UserAuthentication\Events\VerificationCodeGeneratedEvent;

class SendVerificationCodeEmailListener
{
    public function handle(VerificationCodeGeneratedEvent $event): void
    {
        if ($event->type === 'email') {
            Mail::raw("Your verification code is: {$event->code}\n\nThis code will expire in 5 minutes.", function ($message) use ($event) {
                $message->to($event->contact)
                        ->subject('Verification Code - Your App');
            });
        }
    }
}
```

2. **Register the Listener in your EventServiceProvider:**

```php
protected $listen = [
    \Whilesmart\UserAuthentication\Events\VerificationCodeGeneratedEvent::class => [
        \App\Listeners\SendVerificationCodeEmailListener::class,
    ],
];
```

### Setting Up SMS Verification with Third-Party Providers

**Example: SmartPings Integration**

```php
<?php

namespace App\Listeners;

use Smartpings\Messaging\SmartpingsService;
use Whilesmart\UserAuthentication\Events\VerificationCodeGeneratedEvent;

class SendVerificationCodeSmsListener
{
    public function __construct(private SmartpingsService $smartpingsService)
    {
    }

    public function handle(VerificationCodeGeneratedEvent $event): void
    {
        if ($event->type === 'phone') {
            $message = "Your verification code is: {$event->code}. This code will expire in 5 minutes.";
            
            try {
                $response = $this->smartpingsService->sendSms($message, $event->contact);
                \Log::info('SMS sent successfully', ['contact' => $event->contact]);
            } catch (\Exception $e) {
                \Log::error('Failed to send SMS', [
                    'contact' => $event->contact,
                    'error' => $e->getMessage()
                ]);
            }
        }
    }
}
```

### Multi-Provider Setup

You can register multiple listeners for different providers or fallback scenarios:

```php
protected $listen = [
    \Whilesmart\UserAuthentication\Events\VerificationCodeGeneratedEvent::class => [
        \App\Listeners\SendVerificationCodeEmailListener::class,  // For email verification
        \App\Listeners\SendVerificationCodeSmsListener::class,    // For SMS verification
        \App\Listeners\LogVerificationCodeListener::class,        // For logging/debugging
    ],
];
```

## Frontend Integration

The verification flow follows these steps:

1. **User enters email/phone** → Frontend calls `POST /api/send-verification-code`
2. **User enters verification code** → Frontend calls `POST /api/verify-code`  
3. **User completes registration** → Backend automatically validates that verification was completed

## Security Notes

- The backend validates verification internally by checking the database
- Frontend cannot bypass verification by sending flags
- Verification codes expire automatically (configurable)
- Rate limiting prevents abuse