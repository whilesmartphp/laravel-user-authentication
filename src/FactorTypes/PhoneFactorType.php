<?php

namespace Whilesmart\UserAuthentication\FactorTypes;

class PhoneFactorType extends EmailFactorType
{
    public function key(): string
    {
        return 'phone';
    }
}
