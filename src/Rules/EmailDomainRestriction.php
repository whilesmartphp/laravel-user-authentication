<?php

namespace Whilesmart\UserAuthentication\Rules;

use Closure;
use Illuminate\Contracts\Validation\ValidationRule;

class EmailDomainRestriction implements ValidationRule
{
    public function validate(string $attribute, mixed $value, Closure $fail): void
    {
        $mode = config('user-authentication.email_restrictions.mode');
        $restrictedDomains = config('user-authentication.email_restrictions.domains', []);

        if (! $mode || empty($restrictedDomains)) {
            return;
        }

        $emailDomain = $this->extractDomain($value);

        if ($emailDomain === null) {
            $fail(__('validation.email', ['attribute' => $attribute]));

            return;
        }

        if ($mode === 'blacklist' && in_array($emailDomain, $restrictedDomains)) {
            $fail(__('user-authentication::validation.email_domain_blacklisted', ['attribute' => $attribute]));
        } elseif ($mode === 'whitelist' && ! in_array($emailDomain, $restrictedDomains)) {
            $fail(__('user-authentication::validation.email_domain_not_whitelisted', ['attribute' => $attribute]));
        }
    }

    private function extractDomain(string $email): ?string
    {
        $atPos = strrpos($email, '@');

        if ($atPos === false) {
            return null;
        }

        $domain = substr($email, $atPos + 1);

        if ($domain === '') {
            return null;
        }

        return strtolower($domain);
    }
}
