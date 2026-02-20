<?php

namespace Whilesmart\UserAuthentication\Rules;

use Closure;
use Illuminate\Contracts\Validation\ValidationRule;

class EmailDomainRestriction implements ValidationRule
{
    public function validate(string $attribute, mixed $value, Closure $fail): void
    {
        // Validation logic for email domain restriction
        $mode = config('user-authentication.email_restrictions.mode');
        $restrictedDomains = config('user-authentication.email_restrictions.domains', []);

        // if no mode is set or domains are empty, allow everything
        if (! $mode || empty($restrictedDomains)) {
            return;
        }

        $emailDomain = substr(strrchr($value, '@'), 1);

        if ($mode === 'blacklist') {
            if (in_array($emailDomain, $restrictedDomains)) {
                $fail("This {$attribute} email domain is not allowed for registration.");
            }
        } elseif ($mode === 'whitelist') {
            if (! in_array($emailDomain, $restrictedDomains)) {
                $fail("This {$attribute} email domain is not allowed for registration.");
            }
        }
    }
}
