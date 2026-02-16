<?php

namespace Whilesmart\UserAuthentication\Traits;

trait Loggable
{
    protected function info(string $message, array $context = []): void
    {
        $class = get_class($this);
        logger()->info("$class:  $message", $context);
    }

    protected function error(string $message, array $context = []): void
    {
        $class = get_class($this);
        logger()->error("$class:  $message", $context);
    }
}
