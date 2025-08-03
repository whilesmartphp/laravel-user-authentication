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

    protected function warning(string $message, array $context = []): void
    {
        $class = get_class($this);
        logger()->warning("$class:  $message", $context);
    }

    protected function debug(string $message, array $context = []): void
    {
        $class = get_class($this);
        logger()->debug("$class:  $message", $context);
    }

    protected function critical(string $message, array $context = []): void
    {
        $class = get_class($this);
        logger()->critical("$class:  $message", $context);
    }

    protected function alert(string $message, array $context = []): void
    {
        $class = get_class($this);
        logger()->alert("$class:  $message", $context);
    }

    protected function emergency(string $message, array $context = []): void
    {
        $class = get_class($this);
        logger()->emergency("$class:  $message", $context);
    }

    protected function notice(string $message, array $context = []): void
    {
        $class = get_class($this);
        logger()->notice("$class:  $message", $context);
    }

    protected function log($level, string $message, array $context = []): void
    {
        $class = get_class($this);
        logger()->log($level, "$class:  $message", $context);
    }
}
