# Email/Phone Verification

This package provides configurable email and phone verification before user registration. You can choose between:

1. **Managed Verification** - Using SmartPings to handle the entire verification flow
2. **Self-Managed Verification** - Using Laravel events to integrate with any provider

## Configuration Options

### Option 1: SmartPings Managed Verification

For hassle-free verification where SmartPings handles sending and validation:

```php
// config/user-authentication.php
'verification' => [
    'require_email_verification' => true,   // Require email verification before registration
    'require_phone_verification' => false,  // Require phone verification before registration
    'provider' => 'smartpings',            // Use SmartPings provider
    'self_managed' => false,               // Let SmartPings handle everything
    'code_expiry_minutes' => 5,            // Code expiry time in minutes (default: 5)
    'rate_limit_attempts' => 3,             // Rate limit attempts (default: 3)
    'rate_limit_minutes' => 5,              // Rate limit window in minutes (default: 5)
],

// SmartPings credentials
'smartpings' => [
    'client_id' => env('SMARTPINGS_CLIENT_ID'),
    'secret_id' => env('SMARTPINGS_SECRET_ID'),
],
```

Set your credentials in `.env`:

```bash
SMARTPINGS_CLIENT_ID=your-client-id
SMARTPINGS_SECRET_ID=your-secret-id
```

### Option 2: Self-Managed Verification

For custom integration with your preferred email/SMS providers:

```php
// config/user-authentication.php
'verification' => [
    'require_email_verification' => true,   // Require email verification before registration
    'require_phone_verification' => false,  // Require phone verification before registration
    'provider' => 'default',               // Use default (self-managed) provider
    'self_managed' => true,                // Handle sending yourself via events
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

## SmartPings Managed Verification

When using SmartPings managed verification, you get a complete hands-off verification solution:

### What SmartPings Handles

- **Code Generation & Delivery**: Verification codes are generated and sent directly by SmartPings
- **No Database Storage**: Codes aren't stored in your database - SmartPings manages everything
- **No Email/SMS Setup**: No need to configure email providers or SMS gateways
- **Security & Rate Limiting**: Built-in protection against abuse and spam attempts
- **Multi-Channel Support**: Handles both email and SMS verification seamlessly
- **International Support**: Proper handling of phone numbers (use `00` country code prefix)

### Benefits

- **Zero Configuration**: Just add your SmartPings credentials
- **No Infrastructure**: No need to manage email servers or SMS providers  
- **Built-in Security**: Enterprise-grade security and rate limiting
- **Reliability**: High deliverability rates and redundant infrastructure
- **Compliance**: Handles anti-spam and telecommunications regulations

### API Flow

1. **Send Verification**: Your app calls `POST /api/send-verification-code` → SmartPings sends the code
2. **Verify Code**: User submits code via `POST /api/verify-code` → Validated with SmartPings
3. **Registration**: Your app checks verification status before allowing registration

## Event-Driven Integration (Self-Managed)

When using self-managed verification, the package dispatches `VerificationCodeGeneratedEvent` when codes are generated. You must create event listeners to actually send the codes via your preferred providers.

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