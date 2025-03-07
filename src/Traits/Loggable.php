<?php

namespace Whilesmart\LaravelUserAuthentication\Traits;

trait Loggable
{
    private function info(string $message, array $context = []): void
    {
        $class = get_class($this);
        logger()->info("$class:  $message", $context);
    }

    private function error(string $message, array $context = []): void
    {
        $class = get_class($this);
        logger()->error("$class:  $message", $context);
    }

    private function warning(string $message, array $context = []): void
    {
        $class = get_class($this);
        logger()->warning("$class:  $message", $context);
    }

    private function debug(string $message, array $context = []): void
    {
        $class = get_class($this);
        logger()->debug("$class:  $message", $context);
    }

    private function critical(string $message, array $context = []): void
    {
        $class = get_class($this);
        logger()->critical("$class:  $message", $context);
    }

    private function alert(string $message, array $context = []): void
    {
        $class = get_class($this);
        logger()->alert("$class:  $message", $context);
    }

    private function emergency(string $message, array $context = []): void
    {
        $class = get_class($this);
        logger()->emergency("$class:  $message", $context);
    }

    private function notice(string $message, array $context = []): void
    {
        $class = get_class($this);
        logger()->notice("$class:  $message", $context);
    }

    private function log($level, string $message, array $context = []): void
    {
        $class = get_class($this);
        logger()->log($level, "$class:  $message", $context);
    }

}
