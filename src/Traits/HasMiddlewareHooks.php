<?php

namespace Whilesmart\UserAuthentication\Traits;

use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Whilesmart\UserAuthentication\Enums\HookAction;
use Whilesmart\UserAuthentication\Interfaces\MiddlewareHookInterface;

trait HasMiddlewareHooks
{
    /**
     * Run before hooks.
     */
    protected function runBeforeHooks(Request $request, HookAction|string $action): Request
    {
        $hooks = config('user-authentication.middleware_hooks', []);

        foreach ($hooks as $hookClass) {
            if (class_exists($hookClass)) {
                $hook = app($hookClass);
                if ($hook instanceof MiddlewareHookInterface) {
                    $actionValue = $action instanceof HookAction ? $action->value : $action;
                    $result = $hook->before($request, $actionValue);
                    if ($result instanceof Request) {
                        $request = $result;
                    }
                }
            }
        }

        return $request;
    }

    /**
     * Run after hooks.
     */
    protected function runAfterHooks(Request $request, JsonResponse $response, HookAction|string $action): JsonResponse
    {
        $hooks = config('user-authentication.middleware_hooks', []);

        foreach ($hooks as $hookClass) {
            if (class_exists($hookClass)) {
                $hook = app($hookClass);
                if ($hook instanceof MiddlewareHookInterface) {
                    $actionValue = $action instanceof HookAction ? $action->value : $action;
                    $result = $hook->after($request, $response, $actionValue);
                    if ($result instanceof Response) {
                        $response = $result;
                    }
                }
            }
        }

        return $response;
    }
}
