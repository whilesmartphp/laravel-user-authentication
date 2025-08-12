<?php

namespace Whilesmart\UserAuthentication\Interfaces;

use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;

interface MiddlewareHookInterface
{
    /**
     * Handle the request before processing.
     */
    public function before(Request $request, string $action): ?Request;

    /**
     * Handle the response after processing.
     */
    public function after(Request $request, JsonResponse $response, string $action): JsonResponse;
}
